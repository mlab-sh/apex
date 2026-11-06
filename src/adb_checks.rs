//! On-device (ADB) security posture and per-app runtime checks.
//!
//! Static analysis (the `scan` path) reports what an app *requests*; these
//! checks report what the device and its apps are *actually configured to do*
//! at runtime — device hardening (verified boot, SELinux, root, patch age),
//! privacy-sensitive settings, and per-app granted permissions / app-ops.
//!
//! Everything here runs over a **non-root** ADB shell; the handful of checks
//! that benefit from root degrade gracefully (they simply produce no finding
//! when the data is unreadable). Property-based signals (verified boot, root)
//! are best-effort: they can be spoofed by a determined attacker (e.g. Magisk
//! `resetprop`), so they are indicators, not attestation.

use crate::device::Phone;
use crate::models::{Finding, Severity};
use crate::stalkerware_iocs::{STALKERWARE_CERTS, STALKERWARE_PACKAGES};
use chrono::{Local, NaiveDate};
use serde_json::json;

/// Whether a package name exactly matches a bundled stalkerware indicator.
pub fn is_stalkerware(pkg: &str) -> bool {
    STALKERWARE_PACKAGES.contains(&pkg)
}

/// A single-package stalkerware finding (used by offline analysis, where each
/// package is scanned individually).
pub fn stalkerware_package_finding(pkg: &str) -> Finding {
    Finding::new(
        "PKG_STALKERWARE",
        "Known stalkerware/spyware package",
        format!("Package '{pkg}' matches the Echap stalkerware indicator set by exact name — covert monitoring software. Investigate carefully before removal in case of an abusive context."),
        Severity::Critical,
        "stalkerware",
    )
}

/// Critical finding when an APK is signed by a known stalkerware certificate.
/// Catches renamed / repackaged builds that the package-name match misses.
pub fn stalkerware_cert_findings(apk: &std::path::Path) -> Vec<Finding> {
    crate::cert_util::apk_signer_sha1s(apk)
        .into_iter()
        .filter(|c| STALKERWARE_CERTS.contains(&c.as_str()))
        .map(|c| {
            Finding::new(
                "PKG_STALKERWARE_CERT",
                "Signed with a known stalkerware certificate",
                format!("The APK's signing certificate (SHA-1 {c}) belongs to a known stalkerware vendor (Echap indicators). This holds even if the package was renamed. Investigate carefully before removal in case of an abusive context."),
                Severity::Critical,
                "stalkerware",
            )
            .meta("cert_sha1", json!(c))
        })
        .collect()
}

/// One aggregate finding if any installed package matches the stalkerware set.
pub fn stalkerware_finding(packages: &[String]) -> Option<Finding> {
    let hits: Vec<String> = packages
        .iter()
        .filter(|p| is_stalkerware(p))
        .cloned()
        .collect();
    if hits.is_empty() {
        return None;
    }
    Some(
        Finding::new(
            "DEV_STALKERWARE",
            "Known stalkerware/spyware installed",
            format!(
                "{} installed package(s) match the Echap stalkerware indicator set by exact name: {}. These apps covertly monitor the device owner. Investigate before removing — abrupt removal can escalate risk in abusive situations.",
                hits.len(),
                hits.join(", ")
            ),
            Severity::Critical,
            "device",
        )
        .meta("packages", json!(hits)),
    )
}

/// A labelled device-property snapshot for the posture report header.
pub struct DeviceInfo {
    pub rows: Vec<(&'static str, String)>,
}

/// Result of a full posture sweep.
pub struct Posture {
    pub info: DeviceInfo,
    pub findings: Vec<Finding>,
    /// Whether the shell appears to have root (informs bonus checks / caveats).
    pub rooted: bool,
}

/// Split a marker-delimited batch output into (marker → section-body) pairs.
/// Markers are lines of the exact form `@@NAME`.
fn split_sections(out: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut cur: Option<String> = None;
    let mut buf = String::new();
    for line in out.lines() {
        if let Some(name) = line.strip_prefix("@@") {
            if let Some(k) = cur.take() {
                map.insert(k, std::mem::take(&mut buf));
            }
            cur = Some(name.trim().to_string());
        } else if cur.is_some() {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    if let Some(k) = cur.take() {
        map.insert(k, buf);
    }
    map
}

/// A `settings get` value is unset when empty or the literal `null`.
fn setting_set(v: &str) -> Option<String> {
    let v = v.trim();
    if v.is_empty() || v == "null" {
        None
    } else {
        Some(v.to_string())
    }
}

/// Collect the on-device posture: device info rows plus hardening/privacy
/// findings. One `getprop` call plus one batched shell call.
pub fn collect_posture(phone: &mut Phone) -> Result<Posture, String> {
    let props = phone.props()?;
    let get = |k: &str| props.get(k).cloned().unwrap_or_default();

    // Single batched round-trip for everything that isn't a plain property.
    let batch = "\
        echo @@SELINUX; getenforce 2>/dev/null; \
        echo @@SU; which su 2>/dev/null; ls /system/xbin/su /system/bin/su /sbin/su /su/bin/su /magisk/.core/bin/su 2>/dev/null; \
        echo @@MAGISK; pm path com.topjohnwu.magisk 2>/dev/null; pm path io.github.huskydg.magisk 2>/dev/null; pm path com.koushikdutta.superuser 2>/dev/null; \
        echo @@ACCESS; settings get secure enabled_accessibility_services 2>/dev/null; \
        echo @@NOTIF; settings get secure enabled_notification_listeners 2>/dev/null; \
        echo @@DEVOPT; settings get global development_settings_enabled 2>/dev/null; \
        echo @@ADB; settings get global adb_enabled 2>/dev/null; \
        echo @@MOCK; settings get secure mock_location 2>/dev/null; \
        echo @@PROXY; settings get global http_proxy 2>/dev/null; \
        echo @@ADMIN; dumpsys device_policy 2>/dev/null | grep -iE 'Active admin|Device Owner|Profile Owner'; \
        echo @@PKGS; pm list packages 2>/dev/null; \
        echo @@END";
    let out = phone.run(batch)?;
    let sec = split_sections(&out);
    let section = |k: &str| sec.get(k).map(|s| s.as_str()).unwrap_or("").trim().to_string();

    let mut findings: Vec<Finding> = Vec::new();

    // ---- Device info rows (for the report header). ----
    let info = DeviceInfo {
        rows: vec![
            ("model", get("ro.product.model")),
            ("manufacturer", get("ro.product.manufacturer")),
            ("serial", get("ro.serialno")),
            ("android", get("ro.build.version.release")),
            ("sdk", get("ro.build.version.sdk")),
            ("security_patch", get("ro.build.version.security_patch")),
            ("build_fingerprint", get("ro.build.fingerprint")),
        ],
    };

    // ---- Root / integrity. ----
    let su = section("SU");
    let magisk = section("MAGISK");
    let tags = get("ro.build.tags");
    let build_type = get("ro.build.type");
    let adb_root = get("service.adb.root");
    let rooted = !su.is_empty()
        || magisk.contains("package:")
        || adb_root == "1"
        || tags.contains("test-keys");
    if rooted {
        let mut signals = Vec::new();
        if !su.is_empty() {
            signals.push("su binary present");
        }
        if magisk.contains("package:") {
            signals.push("Magisk/superuser package installed");
        }
        if adb_root == "1" {
            signals.push("adbd running as root");
        }
        if tags.contains("test-keys") {
            signals.push("build signed with test-keys");
        }
        findings.push(
            Finding::new(
                "DEV_ROOTED",
                "Device appears rooted",
                format!(
                    "Root indicators detected ({}). Root removes the app-sandbox guarantees APEX's static findings assume. Indicators are spoofable and best-effort.",
                    signals.join(", ")
                ),
                Severity::High,
                "device",
            )
            .meta("signals", json!(signals)),
        );
    }

    // ---- Verified boot / bootloader. ----
    let vbs = get("ro.boot.verifiedbootstate");
    match vbs.as_str() {
        "orange" => findings.push(Finding::new(
            "DEV_VERIFIED_BOOT",
            "Verified Boot disabled (orange state)",
            "ro.boot.verifiedbootstate=orange — the bootloader is unlocked and the boot chain is not verified; the system image cannot be trusted.",
            Severity::High,
            "device",
        )),
        "yellow" => findings.push(Finding::new(
            "DEV_VERIFIED_BOOT",
            "Verified Boot using a custom key (yellow state)",
            "ro.boot.verifiedbootstate=yellow — boot is verified against a user-supplied key (custom OS). Expected only on intentionally reflashed devices.",
            Severity::Medium,
            "device",
        )),
        "red" => findings.push(Finding::new(
            "DEV_VERIFIED_BOOT",
            "Verified Boot failed (red state)",
            "ro.boot.verifiedbootstate=red — dm-verity verification failed; the boot or system partition is corrupt or tampered.",
            Severity::High,
            "device",
        )),
        _ => {}
    }
    if get("ro.boot.flash.locked") == "0" || get("ro.boot.vbmeta.device_state") == "unlocked" {
        findings.push(Finding::new(
            "DEV_BOOTLOADER_UNLOCKED",
            "Bootloader is unlocked",
            "The bootloader is unlocked (ro.boot.flash.locked=0), allowing unsigned images to be flashed — a physical-access compromise vector.",
            Severity::High,
            "device",
        ));
    }

    // ---- SELinux. ----
    if section("SELINUX").eq_ignore_ascii_case("permissive") {
        findings.push(Finding::new(
            "DEV_SELINUX_PERMISSIVE",
            "SELinux is Permissive",
            "getenforce reports Permissive — the mandatory-access-control layer logs but does not enforce policy, greatly widening the impact of any app or kernel compromise.",
            Severity::High,
            "device",
        ));
    }

    // ---- Debuggable / insecure build. ----
    if get("ro.debuggable") == "1" || get("ro.secure") == "0" || build_type == "userdebug" || build_type == "eng" {
        findings.push(
            Finding::new(
                "DEV_DEBUGGABLE_BUILD",
                "Non-production (debuggable) build",
                "The device runs a debuggable/insecure build (ro.debuggable=1 / ro.secure=0 / build type userdebug|eng). adbd can run as root and app data is broadly accessible.",
                Severity::High,
                "device",
            )
            .meta("build_type", json!(build_type))
            .meta("ro.debuggable", json!(get("ro.debuggable"))),
        );
    }

    // ---- Storage encryption. ----
    let crypto = get("ro.crypto.state");
    if !crypto.is_empty() && crypto != "encrypted" {
        findings.push(Finding::new(
            "DEV_NOT_ENCRYPTED",
            "Storage not encrypted",
            format!("ro.crypto.state={crypto} — user data at rest is not encrypted; physical access exposes all app data."),
            Severity::High,
            "device",
        ));
    }

    // ---- Security patch age. ----
    if let Some(f) = patch_age_finding(&get("ro.build.version.security_patch")) {
        findings.push(f);
    }

    // ---- Privacy / attack-surface settings. ----
    if section("MOCK") == "1" {
        findings.push(Finding::new(
            "DEV_MOCK_LOCATION",
            "Mock location enabled",
            "A mock-location provider is allowed (settings secure mock_location=1); apps relying on device location can be fed spoofed coordinates.",
            Severity::Medium,
            "device",
        ));
    }
    if let Some(proxy) = setting_set(&section("PROXY")) {
        findings.push(
            Finding::new(
                "DEV_HTTP_PROXY",
                "Global HTTP proxy configured",
                format!("A system-wide HTTP proxy is set (http_proxy={proxy}). All proxy-aware traffic is routed through it — a legitimate debug setup, but also the classic adversary-in-the-middle interception point."),
                Severity::Medium,
                "device",
            )
            .meta("http_proxy", json!(proxy)),
        );
    }
    if section("DEVOPT") == "1" {
        findings.push(Finding::new(
            "DEV_DEVELOPER_OPTIONS",
            "Developer options enabled",
            "Developer options are enabled — a prerequisite for USB debugging and several sideloading/instrumentation paths. Disable on a device holding sensitive data.",
            Severity::Low,
            "device",
        ));
    }
    if section("ADB") == "1" {
        findings.push(Finding::new(
            "DEV_ADB_ENABLED",
            "USB debugging (ADB) enabled",
            "ADB is enabled. Anyone with a trusted host key and physical access can read app data and install packages. (Necessarily true while APEX is connected this way.)",
            Severity::Low,
            "device",
        ));
    }

    // ---- Abuse vectors: accessibility, notification listeners, device admins. ----
    let access = section("ACCESS");
    if let Some(list) = setting_set(&access) {
        let svcs: Vec<&str> = list.split(':').filter(|s| !s.is_empty()).collect();
        findings.push(
            Finding::new(
                "DEV_ACCESSIBILITY_SERVICE",
                "Accessibility service(s) enabled",
                "One or more apps hold an Accessibility service — the single most abused Android capability (screen reading, input injection, overlay/keylogging). Verify every entry is a tool you installed intentionally.",
                Severity::Medium,
                "device",
            )
            .meta("services", json!(svcs)),
        );
    }
    let notif = section("NOTIF");
    if let Some(list) = setting_set(&notif) {
        let svcs: Vec<&str> = list.split(':').filter(|s| !s.is_empty()).collect();
        findings.push(
            Finding::new(
                "DEV_NOTIF_LISTENER",
                "Notification listener(s) enabled",
                "App(s) can read every notification (including 2FA codes and message previews) via a NotificationListenerService. Confirm each is expected.",
                Severity::Low,
                "device",
            )
            .meta("services", json!(svcs)),
        );
    }
    // Stalkerware: match every installed package against the bundled indicators.
    let all_pkgs: Vec<String> = section("PKGS")
        .lines()
        .filter_map(|l| l.trim().strip_prefix("package:"))
        .map(|s| s.trim().to_string())
        .collect();
    if let Some(f) = stalkerware_finding(&all_pkgs) {
        findings.push(f);
    }

    let admins = parse_device_admins(&section("ADMIN"));
    if !admins.is_empty() {
        findings.push(
            Finding::new(
                "DEV_DEVICE_ADMIN",
                "Active device administrator app(s)",
                "App(s) hold Device Administrator rights (remote wipe/lock, policy enforcement, resistance to uninstall). Legitimate for MDM, abused by stalkerware to prevent removal.",
                Severity::Medium,
                "device",
            )
            .meta("admins", json!(admins)),
        );
    }

    Ok(Posture { info, findings, rooted })
}

/// Known legitimate app-store installer package names. An app installed by
/// anything else (or by nothing) is treated as sideloaded.
pub const KNOWN_STORES: &[&str] = &[
    "com.android.vending",           // Google Play
    "com.google.android.feedback",   // Play (legacy)
    "com.amazon.venezia",            // Amazon Appstore
    "com.amazon.mShop.android",      // Amazon
    "com.sec.android.app.samsungapps", // Samsung Galaxy Store
    "com.samsung.android.galaxyapps",
    "com.huawei.appmarket",          // Huawei AppGallery
    "com.xiaomi.discover",           // Xiaomi GetApps
    "com.xiaomi.mipicks",
    "com.oppo.market",
    "com.heytap.market",
    "com.vivo.appstore",
    "com.facebook.system",           // Meta app-manager (Instagram/WhatsApp updates)
    "com.facebook.appmanager",
];

/// Runtime dangerous permissions worth surfacing when actually granted, mapped
/// to their ATT&CK for Mobile technique so a grant pivots straight into ATT&CK.
const SENSITIVE_PERMS: &[(&str, &str)] = &[
    ("android.permission.CAMERA", "T1512"),
    ("android.permission.RECORD_AUDIO", "T1429"),
    ("android.permission.ACCESS_FINE_LOCATION", "T1430"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", "T1430"),
    ("android.permission.READ_CONTACTS", "T1636.003"),
    ("android.permission.READ_SMS", "T1636.004"),
    ("android.permission.RECEIVE_SMS", "T1636.004"),
    ("android.permission.SEND_SMS", "T1582"),
    ("android.permission.READ_CALL_LOG", "T1636.002"),
    ("android.permission.READ_PHONE_NUMBERS", "T1422"),
    ("android.permission.BODY_SENSORS", "T1418"),
];

/// Per-app runtime posture derived from `dumpsys package` + `appops get`.
///
/// This is the on-device counterpart to the static permission analyzer: it
/// reports which sensitive permissions are *granted* (not merely requested),
/// where the app came from, and whether it holds high-risk app-ops (overlay,
/// all-files access, silent install). Best-effort — returns an empty vector if
/// the device data can't be read.
pub fn runtime_findings(phone: &mut Phone, pkg: &str) -> Vec<Finding> {
    let batch = format!("echo @@DUMP; dumpsys package {pkg} 2>/dev/null; echo @@OPS; cmd appops get {pkg} 2>/dev/null; echo @@END");
    let out = match phone.run(&batch) {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let sec = split_sections(&out);
    let dump = sec.get("DUMP").cloned().unwrap_or_default();
    let ops = sec.get("OPS").cloned().unwrap_or_default();

    let mut findings = Vec::new();

    // Known stalkerware by exact package name.
    if is_stalkerware(pkg) {
        findings.push(Finding::new(
            "RT_STALKERWARE",
            "Known stalkerware/spyware package",
            format!("Package '{pkg}' matches the Echap stalkerware indicator set — covert monitoring software. Investigate carefully before removal in case of an abusive context."),
            Severity::Critical,
            "runtime",
        ));
    }

    // Installer source.
    let installer = dump
        .lines()
        .find_map(|l| l.trim().strip_prefix("installerPackageName="))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "null");
    let from_store = installer.as_deref().is_some_and(|i| KNOWN_STORES.contains(&i));
    if !from_store {
        let src = installer.clone().unwrap_or_else(|| "none".into());
        findings.push(
            Finding::new(
                "RT_INSTALLER_UNTRUSTED",
                "Installed outside a known app store",
                format!("Installer is '{src}' — not a recognized app store. Sideloaded apps bypass store malware review; treat their requested capabilities with extra suspicion."),
                Severity::Low,
                "runtime",
            )
            .meta("installer", json!(installer)),
        );
    }

    // Runtime build flags.
    let flags: String = dump
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with("flags=[") || t.starts_with("pkgFlags=[")
        })
        .collect::<Vec<_>>()
        .join(" ");
    if flags.contains("DEBUGGABLE") {
        findings.push(Finding::new(
            "RT_DEBUGGABLE",
            "App is installed debuggable",
            "The installed package carries the DEBUGGABLE flag — its process can be attached to and its data read via `run-as`/jdwp on this device.",
            Severity::High,
            "runtime",
        ));
    }
    if flags.contains("TEST_ONLY") {
        findings.push(Finding::new(
            "RT_TEST_ONLY",
            "App is a test-only build",
            "The installed package carries TEST_ONLY — a development build not intended for production distribution.",
            Severity::Medium,
            "runtime",
        ));
    }

    // Granted sensitive permissions (granted=true anywhere in the dump).
    let granted: std::collections::HashSet<&str> = dump
        .lines()
        .filter(|l| l.contains("granted=true"))
        .filter_map(|l| l.trim().split(':').next())
        .map(|s| s.trim())
        .collect();
    let hits: Vec<&(&str, &str)> = SENSITIVE_PERMS
        .iter()
        .filter(|(p, _)| granted.contains(p))
        .collect();
    if !hits.is_empty() {
        let names: Vec<String> = hits
            .iter()
            .map(|(p, _)| p.rsplit('.').next().unwrap_or(p).to_string())
            .collect();
        // Sideloaded app holding sensitive grants is the real risk combination.
        let sev = if !from_store { Severity::Medium } else { Severity::Low };
        let mut f = Finding::new(
            "RT_SENSITIVE_PERMS_GRANTED",
            "Sensitive permissions granted at runtime",
            format!("The user has granted {} sensitive permission(s): {}. Unlike static analysis (which sees only what is requested), these are active now.", names.len(), names.join(", ")),
            sev,
            "runtime",
        )
        .meta("granted", json!(names));
        // If a single dominant capability, tag its technique.
        if hits.len() == 1 {
            f = f.mitre(hits[0].1);
        }
        findings.push(f);
    }

    // High-risk app-ops actually allowed.
    let allowed_ops = parse_allowed_ops(&ops);
    if allowed_ops.iter().any(|o| o == "SYSTEM_ALERT_WINDOW") {
        findings.push(Finding::new(
            "RT_APPOP_OVERLAY",
            "Can draw over other apps (overlay)",
            "SYSTEM_ALERT_WINDOW is allowed — the app can draw on top of other apps, the primitive behind tapjacking, fake-login overlays and screen-obscuring attacks.",
            Severity::High,
            "runtime",
        ));
    }
    if allowed_ops.iter().any(|o| o == "MANAGE_EXTERNAL_STORAGE" || o == "LEGACY_STORAGE") {
        findings.push(Finding::new(
            "RT_APPOP_ALLFILES",
            "All-files storage access allowed",
            "The app is allowed broad external-storage / all-files access, letting it read other apps' shared files and user documents.",
            Severity::Medium,
            "runtime",
        ));
    }
    if allowed_ops.iter().any(|o| o == "REQUEST_INSTALL_PACKAGES") {
        findings.push(Finding::new(
            "RT_APPOP_INSTALL",
            "Can install other apps",
            "REQUEST_INSTALL_PACKAGES is allowed — the app can prompt to install further APKs, a common second-stage delivery mechanism.",
            Severity::Medium,
            "runtime",
        ));
    }

    findings
}

/// Parse `appops get` output into the set of op names whose mode is `allow` or
/// `foreground`. Lines look like `SYSTEM_ALERT_WINDOW: allow; time=…`.
fn parse_allowed_ops(s: &str) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    for line in s.lines() {
        let line = line.trim();
        let (name, rest) = match line.split_once(':') {
            Some(x) => x,
            None => continue,
        };
        // Op names are uppercase identifiers (skip "Uid mode" and MIUIOP(...)).
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_uppercase() || c == '_') {
            continue;
        }
        let mode = rest.trim().split(|c: char| c == ';' || c.is_whitespace()).next().unwrap_or("");
        if mode == "allow" || mode == "foreground" {
            set.insert(name.to_string());
        }
    }
    set
}

/// Build a patch-staleness finding from a `YYYY-MM-DD` security-patch string.
fn patch_age_finding(patch: &str) -> Option<Finding> {
    let patch = patch.trim();
    let pd = NaiveDate::parse_from_str(patch, "%Y-%m-%d").ok()?;
    let today = Local::now().date_naive();
    let days = (today - pd).num_days();
    if days < 90 {
        return None;
    }
    let sev = if days > 365 {
        Severity::High
    } else if days > 180 {
        Severity::Medium
    } else {
        Severity::Low
    };
    let months = days / 30;
    Some(
        Finding::new(
            "DEV_PATCH_STALE",
            "Security patch level is out of date",
            format!(
                "Security patch level is {patch} — about {months} month(s) old. Devices missing patches remain exposed to publicly known, already-fixed vulnerabilities."
            ),
            sev,
            "device",
        )
        .meta("security_patch", json!(patch))
        .meta("days_behind", json!(days)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sections_split_on_markers() {
        let out = "@@A\nfoo\nbar\n@@B\nbaz\n@@END\n";
        let m = split_sections(out);
        assert_eq!(m.get("A").unwrap().trim(), "foo\nbar");
        assert_eq!(m.get("B").unwrap().trim(), "baz");
        assert!(m.contains_key("END"));
    }

    #[test]
    fn allowed_ops_keeps_allow_and_foreground_only() {
        let ops = "\
Uid mode: READ_CONTACTS: ignore\n\
SYSTEM_ALERT_WINDOW: allow; time=+1d ago\n\
RECORD_AUDIO: foreground\n\
CAMERA: ignore\n\
MANAGE_EXTERNAL_STORAGE: default\n\
MIUIOP(10002): allow\n";
        let set = parse_allowed_ops(ops);
        assert!(set.contains("SYSTEM_ALERT_WINDOW"));
        assert!(set.contains("RECORD_AUDIO"));
        assert!(!set.contains("CAMERA"));
        assert!(!set.contains("MANAGE_EXTERNAL_STORAGE"));
        // MIUIOP(...) is not a plain uppercase op name and must be ignored.
        assert!(!set.iter().any(|o| o.starts_with("MIUIOP")));
    }

    #[test]
    fn stalkerware_exact_match_only() {
        assert!(is_stalkerware("com.mspy.lite"));
        assert!(!is_stalkerware("com.instagram.android"));
        // Substring of an indicator must not match.
        assert!(!is_stalkerware("com.mspy"));
    }

    #[test]
    fn stalkerware_finding_aggregates_hits() {
        let pkgs = vec![
            "com.instagram.android".to_string(),
            "com.mspy.lite".to_string(),
            "org.telegram.messenger".to_string(),
        ];
        let f = stalkerware_finding(&pkgs).expect("one hit expected");
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.id, "DEV_STALKERWARE");
        let listed = f.metadata.get("packages").unwrap().as_array().unwrap();
        assert_eq!(listed.len(), 1);
    }

    #[test]
    fn stalkerware_finding_none_when_clean() {
        let pkgs = vec!["com.instagram.android".to_string()];
        assert!(stalkerware_finding(&pkgs).is_none());
    }

    #[test]
    fn patch_age_thresholds() {
        // Fresh patch (today) → no finding.
        let today = Local::now().date_naive().format("%Y-%m-%d").to_string();
        assert!(patch_age_finding(&today).is_none());
        // Very old patch → High.
        let f = patch_age_finding("2020-01-01").expect("stale");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.id, "DEV_PATCH_STALE");
        // Garbage input → no finding, no panic.
        assert!(patch_age_finding("not-a-date").is_none());
    }

    #[test]
    fn device_admins_extract_components() {
        let s = "    Active admin: com.example.mdm/.AdminReceiver\n    enabled=true";
        let admins = parse_device_admins(s);
        assert_eq!(admins, vec!["com.example.mdm/.AdminReceiver"]);
    }
}

/// Best-effort extraction of active device-admin component names from a grepped
/// `dumpsys device_policy` slice. Format varies across OEMs/versions, so we pull
/// any `package/Component` token from admin/owner lines.
pub fn parse_device_admins(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in s.lines() {
        for tok in line.split_whitespace() {
            let tok = tok.trim_matches(|c| c == '{' || c == '}' || c == ',');
            if tok.contains('/') && tok.contains('.') && !tok.contains('=') {
                let comp = tok.to_string();
                if !out.contains(&comp) {
                    out.push(comp);
                }
            }
        }
    }
    out
}
