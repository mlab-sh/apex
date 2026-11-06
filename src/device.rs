//! Direct USB Android connector via `adb_client` (ADBUSBDevice).
//!
//! Lists non-system (third-party) packages, resolves their APK paths, and
//! pulls the APKs off the device so they can be scanned like local files.

use adb_client::usb::{find_all_connected_adb_devices, ADBUSBDevice};
use adb_client::ADBDeviceExt;
use chrono::Utc;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Instant;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// A single audited on-device action (shell command or file pull), recorded so
/// an investigator can prove exactly what APEX did to the device and when.
///
/// Every entry is UTC-timestamped and carries the SHA-256 of the raw output,
/// so the audit trail is tamper-evident and the acquisition reproducible.
#[derive(Clone)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts_utc: String,
    pub action: String,
    pub ok: bool,
    pub output_sha256: Option<String>,
    pub output_bytes: usize,
    pub duration_ms: u128,
    pub error: Option<String>,
}

impl AuditEntry {
    pub fn to_json(&self) -> Value {
        let mut d = serde_json::Map::new();
        d.insert("seq".into(), json!(self.seq));
        d.insert("ts_utc".into(), json!(self.ts_utc));
        d.insert("action".into(), json!(self.action));
        d.insert("ok".into(), json!(self.ok));
        if let Some(h) = &self.output_sha256 {
            d.insert("output_sha256".into(), json!(h));
        }
        d.insert("output_bytes".into(), json!(self.output_bytes));
        d.insert("duration_ms".into(), json!(self.duration_ms as u64));
        if let Some(e) = &self.error {
            d.insert("error".into(), json!(e));
        }
        Value::Object(d)
    }
}

/// Detect ADB-capable USB devices without authenticating (reads USB
/// descriptors only). Returns each device's (vendor_id, product_id).
pub fn detect_devices() -> Result<Vec<(u16, u16)>, String> {
    let devs = find_all_connected_adb_devices()
        .map_err(|e| format!("USB scan failed: {e}"))?;
    Ok(devs.iter().map(|d| (d.vendor_id, d.product_id)).collect())
}

/// `~/.android/adbkey` (same path as the platform `adb`), created if missing.
///
/// Without a persistent key, `adb_client` signs with a fresh random key on
/// every connection, so the phone re-prompts "Allow USB debugging?" each time.
fn default_adb_key() -> Result<PathBuf, String> {
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    let home = std::env::var_os("HOME").ok_or("HOME is not set; pass --adb-key")?;
    let path = PathBuf::from(home).join(".android").join("adbkey");
    if path.exists() {
        return Ok(path);
    }
    let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048)
        .map_err(|e| format!("cannot generate ADB key: {e}"))?;
    let pem = key.to_pkcs8_pem(LineEnding::LF).map_err(|e| format!("cannot encode ADB key: {e}"))?;
    std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| format!("cannot create ~/.android: {e}"))?;
    std::fs::write(&path, pem.as_bytes()).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!("\x1b[2mCreated ADB key {} — accept the phone's prompt once and tick \"Always allow\".\x1b[0m", path.display());
    Ok(path)
}

pub struct Phone {
    dev: ADBUSBDevice,
    /// Tamper-evident record of every action taken against the device.
    log: Vec<AuditEntry>,
    /// UTC timestamp when the session (connection) was opened.
    session_start_utc: String,
}

impl Phone {
    /// Autodetect and connect to the single attached ADB-USB device.
    /// The phone must be in USB-debugging mode and authorized (RSA prompt).
    pub fn connect(key: Option<PathBuf>) -> Result<Phone, String> {
        let key = match key {
            Some(k) => k,
            None => default_adb_key()?,
        };
        // The handshake blocks until the phone authorizes this key; say so, or a
        // pending "Allow USB debugging?" prompt looks like a hang.
        let waiting = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let w = waiting.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(3));
            if w.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!("\x1b[33mWaiting for the phone: unlock it and accept \"Allow USB debugging?\" (tick \"Always allow\").\x1b[0m");
            }
        });
        let dev = ADBUSBDevice::autodetect_with_custom_private_key(key);
        waiting.store(false, std::sync::atomic::Ordering::Relaxed);
        let dev = dev.map_err(|e| format!("ADB USB connection failed: {e}"))?;
        Ok(Phone {
            dev,
            log: Vec::new(),
            session_start_utc: Utc::now().to_rfc3339(),
        })
    }

    /// The audit trail of every action taken so far, in order.
    pub fn audit(&self) -> &[AuditEntry] {
        &self.log
    }

    /// UTC RFC-3339 timestamp of when this session was opened.
    pub fn session_start_utc(&self) -> &str {
        &self.session_start_utc
    }

    fn record(
        &mut self,
        action: String,
        started: Instant,
        ok: bool,
        output: Option<&[u8]>,
        error: Option<String>,
    ) {
        self.log.push(AuditEntry {
            seq: self.log.len() as u64,
            ts_utc: Utc::now().to_rfc3339(),
            action,
            ok,
            output_sha256: output.map(sha256_hex),
            output_bytes: output.map(|o| o.len()).unwrap_or(0),
            duration_ms: started.elapsed().as_millis(),
            error,
        });
    }

    /// Run an arbitrary shell command on the device and return its stdout.
    ///
    /// The connection uses a non-root `shell` uid unless the device is rooted
    /// and grants it. Commands are executed via the device's `sh`, so pipes and
    /// redirection technically work, but output is pulled in full and parsed
    /// host-side (some `adb_client` shell transports mishandle large pipes), so
    /// callers should prefer fetching raw output and parsing in Rust.
    pub fn run(&mut self, cmd: &str) -> Result<String, String> {
        let mut out = Vec::new();
        let command = cmd.to_string();
        let started = Instant::now();
        let res = self.dev.shell_command(&command, Some(&mut out), None);
        match res {
            Ok(_) => {
                self.record(format!("shell: {cmd}"), started, true, Some(&out), None);
                Ok(String::from_utf8_lossy(&out).into_owned())
            }
            Err(e) => {
                let err = format!("shell '{cmd}' failed: {e}");
                self.record(format!("shell: {cmd}"), started, false, Some(&out), Some(err.clone()));
                Err(err)
            }
        }
    }

    /// List third-party (non-system) package names, sorted.
    pub fn list_third_party(&mut self) -> Result<Vec<String>, String> {
        let out = self.run("pm list packages -3")?;
        let mut pkgs: Vec<String> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        pkgs.sort();
        pkgs.dedup();
        Ok(pkgs)
    }

    /// Read all device properties (`getprop`) into a key→value map.
    pub fn props(&mut self) -> Result<std::collections::HashMap<String, String>, String> {
        let out = self.run("getprop")?;
        let mut m = std::collections::HashMap::new();
        for line in out.lines() {
            // Format: [key]: [value]
            if let Some(rest) = line.trim().strip_prefix('[') {
                if let Some((k, v)) = rest.split_once("]: [") {
                    let v = v.strip_suffix(']').unwrap_or(v);
                    m.insert(k.to_string(), v.to_string());
                }
            }
        }
        Ok(m)
    }

    /// Resolve the on-device APK path(s) for a package.
    pub fn apk_paths(&mut self, pkg: &str) -> Result<Vec<String>, String> {
        let out = self.run(&format!("pm path {pkg}"))?;
        let paths: Vec<String> = out
            .lines()
            .filter_map(|l| l.trim().strip_prefix("package:"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(paths)
    }

    /// Pick the primary (base) APK path for a package.
    pub fn base_apk_path(&mut self, pkg: &str) -> Result<Option<String>, String> {
        let paths = self.apk_paths(pkg)?;
        let base = paths
            .iter()
            .find(|p| p.ends_with("base.apk"))
            .or_else(|| paths.first())
            .cloned();
        Ok(base)
    }

    /// Generate a full bugreport on the device (`bugreportz`, 1-5 min) and
    /// pull the zip to `local`. Returns the on-device path. The zip is left in
    /// the shell user's own bugreports dir (not deleted: no device alteration
    /// beyond creating it).
    pub fn bugreport(&mut self, local: &Path) -> Result<String, String> {
        let out = self.run("bugreportz")?;
        let remote = out
            .lines()
            .find_map(|l| l.trim().strip_prefix("OK:"))
            .map(|s| s.trim().to_string())
            .ok_or_else(|| format!("bugreportz failed: {}", out.trim()))?;
        self.pull(&remote, local)?;
        Ok(remote)
    }

    /// Pull a remote file into a local path.
    pub fn pull(&mut self, remote: &str, local: &Path) -> Result<(), String> {
        let started = Instant::now();
        let mut f = std::fs::File::create(local)
            .map_err(|e| format!("cannot create {}: {e}", local.display()))?;
        let src = remote.to_string();
        let action = format!("pull: {remote} -> {}", local.display());
        if let Err(e) = self.dev.pull(&src, &mut f) {
            let err = format!("pull '{remote}' failed: {e}");
            self.record(action, started, false, None, Some(err.clone()));
            return Err(err);
        }
        drop(f);
        // Hash the acquired file so the artifact is tamper-evident in the trail.
        let (sha, len) = match std::fs::read(local) {
            Ok(bytes) => (Some(sha256_hex(&bytes)), bytes.len()),
            Err(_) => (None, 0),
        };
        self.log.push(AuditEntry {
            seq: self.log.len() as u64,
            ts_utc: Utc::now().to_rfc3339(),
            action,
            ok: true,
            output_sha256: sha,
            output_bytes: len,
            duration_ms: started.elapsed().as_millis(),
            error: None,
        });
        Ok(())
    }
}
