//! Direct USB Android connector via `adb_client` (ADBUSBDevice).
//!
//! Lists non-system (third-party) packages, resolves their APK paths, and
//! pulls the APKs off the device so they can be scanned like local files.

use adb_client::usb::{find_all_connected_adb_devices, ADBUSBDevice};
use adb_client::ADBDeviceExt;
use std::path::{Path, PathBuf};

/// Detect ADB-capable USB devices without authenticating (reads USB
/// descriptors only). Returns each device's (vendor_id, product_id).
pub fn detect_devices() -> Result<Vec<(u16, u16)>, String> {
    let devs = find_all_connected_adb_devices()
        .map_err(|e| format!("USB scan failed: {e}"))?;
    Ok(devs.iter().map(|d| (d.vendor_id, d.product_id)).collect())
}

pub struct Phone {
    dev: ADBUSBDevice,
}

impl Phone {
    /// Autodetect and connect to the single attached ADB-USB device.
    /// The phone must be in USB-debugging mode and authorized (RSA prompt).
    pub fn connect(key: Option<PathBuf>) -> Result<Phone, String> {
        let dev = match key {
            Some(k) => ADBUSBDevice::autodetect_with_custom_private_key(k),
            None => ADBUSBDevice::autodetect(),
        }
        .map_err(|e| format!("ADB USB connection failed: {e}"))?;
        Ok(Phone { dev })
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
        self.dev
            .shell_command(&command, Some(&mut out), None)
            .map_err(|e| format!("shell '{cmd}' failed: {e}"))?;
        Ok(String::from_utf8_lossy(&out).into_owned())
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

    /// Pull a remote file into a local path.
    pub fn pull(&mut self, remote: &str, local: &Path) -> Result<(), String> {
        let mut f = std::fs::File::create(local)
            .map_err(|e| format!("cannot create {}: {e}", local.display()))?;
        let src = remote.to_string();
        self.dev
            .pull(&src, &mut f)
            .map_err(|e| format!("pull '{remote}' failed: {e}"))?;
        Ok(())
    }
}
