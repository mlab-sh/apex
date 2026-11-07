//! The APEX agent: a 17 KB app with no UI, embedded in the binary. During an
//! acquisition it is installed over USB, given only the permissions the legal
//! scope allows (`pm grant`), read once through its content provider, then
//! uninstalled. Everything it does is in the audit log and listed as a change
//! to the phone in the manifest and the PV.
//!
//! What it adds to the shell: packages with signing certificates, install
//! source and granted permissions (no APK pull needed for indicator matching),
//! accounts, SIM details and line numbers, paired Bluetooth devices, usage
//! events (app in front, screen on / off, unlock) going back weeks, every
//! MediaStore row (path, dates, size, the app that wrote it); under mandate,
//! contacts, call log and calendar with every column, and photo / video GPS.
//! SMS and notification content come from the shell, so the agent does not
//! ask for them.

use crate::device::Phone;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Full build: also SMS and notification access.
pub const APK: &[u8] = include_bytes!("../agent/apex-agent.apk");
/// Lite build: without them, for phones that block apps asking for them
/// (Play Protect on sideloaded apps, makers' own checks).
pub const APK_LITE: &[u8] = include_bytes!("../agent/apex-agent-lite.apk");
pub const PKG: &str = "sh.mlab.apex.agent";
const REMOTE: &str = "/data/local/tmp/apex-agent.apk";
const LISTENER: &str = "sh.mlab.apex.agent/sh.mlab.apex.agent.Listener";

pub struct Scope {
    pub mandate: bool,
    /// `--notification-content`: read active notifications (full build, under mandate).
    pub notifications: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Build {
    Full,
    Lite,
}

impl Build {
    fn apk(self) -> &'static [u8] {
        match self {
            Build::Full => APK,
            Build::Lite => APK_LITE,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Build::Full => "full",
            Build::Lite => "lite",
        }
    }
}

pub struct Outcome {
    pub json: PathBuf,
    pub bytes: usize,
    /// Human-readable changes to the phone, for the manifest and the PV.
    pub changes: Vec<String>,
    pub errors: String,
    pub build: Build,
}

fn now() -> String {
    chrono::Utc::now().format("%H:%M:%S UTC").to_string()
}

/// Permissions granted for this scope (only those the phone's Android version has).
fn permissions(sdk: u32, scope: &Scope, build: Build) -> Vec<&'static str> {
    let mut p = vec!["android.permission.GET_ACCOUNTS", "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS"];
    if sdk >= 31 {
        p.push("android.permission.BLUETOOTH_CONNECT");
    }
    if sdk >= 33 {
        p.extend(["android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO"]);
    } else {
        p.push("android.permission.READ_EXTERNAL_STORAGE");
    }
    if scope.mandate {
        p.extend(["android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.READ_CALENDAR"]);
        if sdk >= 29 {
            p.push("android.permission.ACCESS_MEDIA_LOCATION");
        }
        if build == Build::Full {
            p.push("android.permission.READ_SMS");
        }
    }
    p
}

/// Sections read for this scope.
pub fn sections(scope: &Scope, build: Build) -> Vec<&'static str> {
    let mut s = vec!["packages", "accounts", "telephony", "bluetooth", "usage", "media"];
    if scope.mandate {
        s.extend(["contacts", "calllog", "calendar", "media_gps"]);
        if build == Build::Full {
            s.push("sms");
            if scope.notifications {
                s.push("notifications");
            }
        }
    }
    s
}

/// `pm install` of one build: Ok(output) whatever the result.
fn adb_install(phone: &mut Phone, build: Build) -> Result<String, String> {
    phone.push(build.apk(), REMOTE)?;
    // Some makers (Xiaomi) ask on screen; give the examiner two chances.
    let mut r = String::new();
    for attempt in 1..=2 {
        eprintln!("\x1b[33m  On the phone: if asked, allow the installation of \"APEX agent\" ({} build){}\x1b[0m", build.name(), if attempt == 2 { ", second try" } else { "" });
        r = phone.run(&format!("pm install -r {REMOTE} 2>&1")).unwrap_or_default();
        if r.contains("Success") || !r.contains("USER_RESTRICTED") {
            break;
        }
    }
    let _ = phone.run(&format!("rm -f {REMOTE}"));
    Ok(r)
}

fn sha(b: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(b))
}

/// Install, grant, read, uninstall. The agent is removed even if reading fails.
pub fn run(phone: &mut Phone, out: &Path, scope: &Scope) -> Result<Outcome, String> {
    let sdk: u32 = phone.run("getprop ro.build.version.sdk").unwrap_or_default().trim().parse().unwrap_or(0);
    let mut changes = Vec::new();
    // Full build first; the lite one if the phone refuses it. The phone's own
    // installer (Xiaomi without "Install via USB") gets the lite build: Play
    // Protect blocks sideloaded apps that ask for SMS or notification access.
    let mut build = Build::Full;
    let r = adb_install(phone, build)?;
    if r.contains("USER_RESTRICTED") {
        build = Build::Lite;
        changes.push(format!("{} APEX agent: ADB install refused by the phone ({})", now(), r.trim()));
        install_on_screen(phone, &mut changes)?;
    } else if !r.contains("Success") {
        changes.push(format!("{} APEX agent full build refused ({}), trying the lite build", now(), r.trim()));
        build = Build::Lite;
        let r2 = adb_install(phone, build)?;
        if !r2.contains("Success") {
            return Err(format!("agent install refused: full: {} / lite: {}", r.trim(), r2.trim()));
        }
    }
    changes.push(format!("{} APEX agent, {} build ({PKG}, sha256 {}), installed", now(), build.name(), sha(build.apk())));
    let res = collect(phone, out, scope, sdk, build, &mut changes);
    if build == Build::Full && scope.notifications && scope.mandate {
        let _ = phone.run(&format!("cmd notification disallow_listener {LISTENER}"));
    }
    // APEX_KEEP_AGENT=1: leave it installed (agent development only; it is then not in the PV as removed).
    if std::env::var("APEX_KEEP_AGENT").as_deref() == Ok("1") {
        eprintln!("\x1b[33m  APEX_KEEP_AGENT=1: agent left installed\x1b[0m");
        changes.push(format!("{} APEX agent LEFT INSTALLED (APEX_KEEP_AGENT)", now()));
    } else {
        let u = phone.run(&format!("pm uninstall {PKG} 2>&1")).unwrap_or_default();
        changes.push(format!("{} APEX agent uninstalled ({})", now(), u.trim()));
    }
    let (json, bytes, errors) = res?;
    Ok(Outcome { json, bytes, changes, errors, build })
}

const DOWNLOAD: &str = "/sdcard/Download/apex-agent.apk";

fn installed(phone: &mut Phone) -> bool {
    phone.run(&format!("pm path {PKG}")).unwrap_or_default().contains("package:")
}

/// Fallback: the APK in Download, opened in the phone's installer; the examiner
/// taps "Install". Waits up to 3 minutes, then removes the file.
fn install_on_screen(phone: &mut Phone, changes: &mut Vec<String>) -> Result<(), String> {
    phone.push(APK_LITE, DOWNLOAD)?;
    changes.push(format!("{} APEX agent APK copied to {DOWNLOAD} (ADB install refused by the phone)", now()));
    let _ = phone.run(&format!("am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://{DOWNLOAD} >/dev/null 2>&1"));
    std::thread::sleep(std::time::Duration::from_secs(1));
    let q = phone.run("content query --uri content://media/external/file --projection _id --where \"_data LIKE '%/Download/apex-agent.apk'\"").unwrap_or_default();
    let id = q.lines().find_map(|l| l.split("_id=").nth(1)).map(|v| v.trim().to_string());
    if let Some(id) = id {
        let _ = phone.run(&format!("am start -a android.intent.action.VIEW -t application/vnd.android.package-archive -d content://media/external/file/{id} --grant-read-uri-permission >/dev/null 2>&1"));
    }
    eprintln!("\x1b[33m  The phone refused the ADB install. On the phone: tap \"Install\" in the installer that opened\n  (or Files → Download → apex-agent.apk). If it asks, allow installing from this source. Waiting up to 3 min…\x1b[0m");
    let started = std::time::Instant::now();
    while started.elapsed().as_secs() < 180 {
        if installed(phone) {
            let _ = phone.run(&format!("rm -f {DOWNLOAD}"));
            changes.push(format!("{} APEX agent installed through the phone's installer, confirmed on screen; {DOWNLOAD} removed", now()));
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
    let _ = phone.run(&format!("rm -f {DOWNLOAD}"));
    changes.push(format!("{} APEX agent not installed (no confirmation on screen); {DOWNLOAD} removed", now()));
    Err("agent not installed: nobody confirmed the installation on the phone within 3 minutes".into())
}

fn collect(phone: &mut Phone, out: &Path, scope: &Scope, sdk: u32, build: Build, changes: &mut Vec<String>) -> Result<(PathBuf, usize, String), String> {
    let wanted = permissions(sdk, scope, build);
    for p in &wanted {
        let _ = phone.run(&format!("pm grant {PKG} {p} 2>&1"));
    }
    let _ = phone.run(&format!("appops set {PKG} GET_USAGE_STATS allow"));
    // `pm grant` can be ignored silently (Xiaomi without "USB debugging (Security
    // settings)"): record what the phone actually granted.
    let dump = phone.run(&format!("dumpsys package {PKG}")).unwrap_or_default();
    let granted: Vec<&str> = wanted.iter().filter(|p| dump.lines().any(|l| l.trim().starts_with(&format!("{p}: granted=true")))).map(|p| p.trim_start_matches("android.permission.")).collect();
    let refused: Vec<&str> = wanted.iter().map(|p| p.trim_start_matches("android.permission.")).filter(|p| !granted.contains(p)).collect();
    changes.push(format!("{} APEX agent permissions granted: {}{}", now(), if granted.is_empty() { "none".to_string() } else { granted.join(", ") }, if refused.is_empty() { String::new() } else { format!("; refused by the phone: {}", refused.join(", ")) }));
    if !refused.is_empty() {
        eprintln!("\x1b[33m  agent: the phone refused {} permission(s) ({}). On Xiaomi / Redmi / POCO: Developer options → \"USB debugging (Security settings)\" (Mi account). Those sections come back empty.\x1b[0m", refused.len(), refused.join(", "));
    }
    if build == Build::Full && scope.notifications && scope.mandate {
        let _ = phone.run(&format!("cmd notification allow_listener {LISTENER}"));
        changes.push(format!("{} APEX agent notification access allowed", now()));
        // The system binds the listener asynchronously.
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    let uri = format!("content://{PKG}/dump/{}", sections(scope, build).join(","));
    let raw = phone.run_raw(&format!("content read --uri {uri}"))?;
    let v: Value = serde_json::from_slice(&raw).map_err(|e| format!("agent output unreadable ({e}): {}", String::from_utf8_lossy(&raw[..raw.len().min(3000)])))?;
    let dir = out.join("agent");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join("agent.json");
    std::fs::write(&path, &raw).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((path, raw.len(), v["errors"].as_str().unwrap_or("").to_string()))
}

/// Signing certificates read by the agent, for apps whose APK was not pulled
/// (`--quick`): bundled stalkerware certificates and STIX2 `app:cert.*` indicators.
pub fn cert_findings(root: &Path, iocs: &crate::ioc::IocSet) -> Vec<crate::models::Finding> {
    use crate::ioc::Kind;
    use crate::models::{Finding, Severity};
    let Some(v) = load(root) else { return Vec::new() };
    let mut out = Vec::new();
    for p in v["sections"]["packages"].as_array().into_iter().flatten() {
        let pkg = p["package"].as_str().unwrap_or("");
        if pkg == PKG || p["system"].as_bool() == Some(true) || root.join("apps").join(pkg).join("base.apk").is_file() {
            continue;
        }
        for c in p["certs"].as_array().into_iter().flatten() {
            let sha1 = c["sha1"].as_str().unwrap_or("").to_ascii_uppercase();
            let sha256 = c["sha256"].as_str().unwrap_or("");
            if crate::stalkerware_iocs::STALKERWARE_CERTS.contains(&sha1.as_str()) {
                out.push(
                    Finding::new("PKG_STALKERWARE_CERT", format!("{pkg}: signed with a known stalkerware certificate"), format!("The signing certificate of {pkg} (SHA-1 {sha1}, read on the phone by the APEX agent) belongs to a known stalkerware vendor (Echap indicators), even if the package was renamed."), Severity::Critical, "stalkerware")
                        .meta("package", serde_json::json!(pkg))
                        .meta("cert_sha1", serde_json::json!(sha1)),
                );
            }
            for (k, h) in [(Kind::CertSha1, sha1.as_str()), (Kind::CertSha256, sha256)] {
                if let Some(m) = iocs.get(k, h) {
                    out.push(
                        Finding::new("IOC_MATCH", format!("{pkg}: signing certificate matches {m}"), format!("The signing certificate of {pkg} ({h}, read on the phone by the APEX agent) matches an indicator of {m}."), Severity::Critical, "ioc")
                            .meta("package", serde_json::json!(pkg))
                            .meta("cert", serde_json::json!(h)),
                    );
                }
            }
        }
    }
    out
}

/// The agent's JSON from a case, if it ran.
pub fn load(case_root: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(case_root.join("agent/agent.json")).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope() {
        let base = Scope { mandate: false, notifications: true };
        assert!(!sections(&base, Build::Full).contains(&"contacts") && !sections(&base, Build::Full).contains(&"sms"));
        assert!(!permissions(34, &base, Build::Full).contains(&"android.permission.READ_CONTACTS"));
        let m = Scope { mandate: true, notifications: true };
        assert!(sections(&m, Build::Full).contains(&"notifications") && sections(&m, Build::Full).contains(&"sms"));
        assert!(!sections(&m, Build::Lite).contains(&"sms") && !permissions(34, &m, Build::Lite).contains(&"android.permission.READ_SMS"));
        assert!(permissions(34, &m, Build::Lite).contains(&"android.permission.ACCESS_MEDIA_LOCATION"));
        assert!(permissions(30, &m, Build::Full).contains(&"android.permission.READ_EXTERNAL_STORAGE"));
        assert!(APK.starts_with(b"PK") && APK_LITE.starts_with(b"PK") && APK != APK_LITE);
    }
}
