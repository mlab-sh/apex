//! Seizure helpers for an investigator:
//! - **remote-wipe risk**: can someone erase this phone right now
//!   (find-my-device service, MDM / device admin, network up)?
//! - **identifiers sheet**: every identifier a legal request to an operator or
//!   a platform needs (IMEI, IMSI, ICCID, line number, MACs, accounts…).
//!
//! Both read the text artifacts of a case, so they work the same live (right
//! after connecting) and offline.

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------- accounts

/// `dumpsys account` → (type, name), deduplicated, in order.
pub fn parse_accounts(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for l in text.lines() {
        let Some(i) = l.find("Account {") else { continue };
        let body = l[i + 9..].split('}').next().unwrap_or("");
        let Some((name, ty)) = body.strip_prefix("name=").and_then(|b| b.rsplit_once(", type=")) else { continue };
        let a = (ty.trim().to_string(), name.trim().to_string());
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Account type → the service a legal request goes to.
pub fn service(ty: &str) -> &str {
    match ty {
        "com.google" => "Google",
        "com.whatsapp" | "com.whatsapp.w4b" => "WhatsApp",
        "com.facebook.auth.login" | "com.facebook.messenger" => "Facebook / Messenger",
        "www.instagram.com" => "Instagram (user ID)",
        "www.instagram.barcelona" => "Threads (user ID)",
        "org.telegram.messenger" | "org.telegram.messenger.web" => "Telegram",
        "org.thoughtcrime.securesms" => "Signal",
        "com.snapchat.android" => "Snapchat",
        "com.twitter.android.auth.login" => "X (Twitter)",
        "com.microsoft.workaccount" | "com.microsoft.office" | "com.skype.android" | "com.microsoft.teams" => "Microsoft",
        "com.osp.app.signin" => "Samsung",
        "com.xiaomi" => "Xiaomi",
        "com.huawei.hwid" => "Huawei",
        "com.linkedin.android" => "LinkedIn",
        "com.discord" => "Discord",
        "com.dropbox.android.account" => "Dropbox",
        "com.viber.voip" | "com.viber.voip.account" => "Viber",
        "jp.naver.line.android" => "LINE",
        "com.tinder" => "Tinder",
        "com.zhiliaoapp.musically" => "TikTok",
        t if t.starts_with("com.google.android.gm") => "Google (Gmail)",
        t => t,
    }
}

// ---------------------------------------------------------------- remote wipe

/// Find-my-device services that can erase the phone remotely, when their
/// account is signed in: (package, account type, label).
const FIND_SERVICES: &[(&str, &str, &str)] = &[
    ("com.google.android.gms", "com.google", "Google Find Hub (Find My Device)"),
    ("com.xiaomi.finddevice", "com.xiaomi", "Xiaomi Find device"),
    ("com.samsung.android.fmm", "com.osp.app.signin", "Samsung Find My Mobile / SmartThings Find"),
    ("com.huawei.android.findmyphone", "com.huawei.hwid", "Huawei Find Device"),
    ("com.coloros.findmyphone", "com.oplus.account", "OPPO / OnePlus Find My Phone"),
];

/// Device / profile owner component from `dumpsys device_policy`.
fn owners(device_policy: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_owner = false;
    for l in device_policy.lines() {
        let t = l.trim();
        if t.starts_with("Device Owner") || t.starts_with("Profile Owner") {
            in_owner = true;
        }
        if in_owner {
            if let Some(c) = t.strip_prefix("admin=ComponentInfo{").and_then(|r| r.split('}').next()) {
                out.push(c.to_string());
                in_owner = false;
            }
        }
    }
    out
}

/// Remote-wipe risks: (reasons it can be wiped, the phone is online now).
pub fn wipe_risks(accounts: &str, packages: &BTreeSet<String>, device_policy: &str, connectivity: &str, airplane: Option<bool>) -> (Vec<String>, bool) {
    let types: BTreeSet<String> = parse_accounts(accounts).into_iter().map(|(t, _)| t).collect();
    let mut why = Vec::new();
    for (pkg, acct, label) in FIND_SERVICES {
        if packages.contains(*pkg) && types.contains(*acct) {
            why.push(format!("{label}: account signed in, erase possible from the web unless the owner turned it off"));
        }
    }
    for o in owners(device_policy) {
        why.push(format!("managed device (MDM owner {o}): its console can wipe the phone"));
    }
    // Enabled admins are listed as `    pkg/.Receiver:` lines.
    let admins: BTreeSet<&str> = device_policy
        .lines()
        .map(str::trim)
        .filter(|t| t.ends_with(':') && t.contains('/') && !t.contains(' '))
        .map(|t| t.trim_end_matches(':'))
        .collect();
    let owned = owners(device_policy);
    for a in admins.iter().filter(|a| !owned.iter().any(|o| o == *a)) {
        why.push(format!("active device admin {a}: may hold the wipe-data policy"));
    }
    // Online = a default network is up (Wi-Fi or mobile), whatever airplane mode says.
    let online = connectivity
        .lines()
        .find_map(|l| l.trim().strip_prefix("Active default network:"))
        .map(|v| v.trim() != "none" && !v.trim().is_empty())
        .unwrap_or(airplane != Some(true));
    (why, online)
}

/// The banner printed right after connecting, before anything slow.
pub fn wipe_banner(why: &[String], online: bool) -> Option<String> {
    if why.is_empty() && !online {
        return None;
    }
    let (r, y, b, z) = ("\x1b[31m", "\x1b[33m", "\x1b[1m", "\x1b[0m");
    let mut s = String::new();
    if !why.is_empty() {
        s.push_str(&format!("{r}{b}⚠ REMOTE WIPE POSSIBLE{z}\n"));
        for w in why {
            s.push_str(&format!("{r}  • {w}{z}\n"));
        }
    }
    if online {
        s.push_str(&format!(
            "{y}{b}  The phone is online now.{z}{y} Isolate it: airplane mode (then check Wi-Fi and Bluetooth stay off) or a Faraday bag, keep it charging and unlocked.{z}\n"
        ));
    } else {
        s.push_str(&format!("{y}  The phone is offline: keep it that way (airplane mode / Faraday bag).{z}\n"));
    }
    Some(s)
}

/// Offline finding with the same content.
pub fn wipe_finding(case: &crate::case::Case) -> Option<crate::models::Finding> {
    let read = |f: &str| std::fs::read_to_string(case.root.join("device").join(f)).unwrap_or_default();
    let pkgs: BTreeSet<String> = case.packages.iter().map(|p| p.name.clone()).collect();
    let (why, online) = wipe_risks(&read("accounts.txt"), &pkgs, &read("device_policy.txt"), &read("connectivity.txt"), None);
    if why.is_empty() {
        return None;
    }
    Some(
        crate::models::Finding::new(
            "CASE_REMOTE_WIPE",
            "The phone can be wiped remotely",
            format!(
                "{}. At acquisition the phone was {}. A seized phone must be isolated from all networks (airplane mode, Faraday bag) as soon as possible.",
                why.join("; "),
                if online { "online" } else { "offline" }
            ),
            crate::models::Severity::Medium,
            "investigation",
        )
        .meta("reasons", json!(why))
        .meta("online_at_acquisition", json!(online)),
    )
}

// ---------------------------------------------------------------- identifiers

fn luhn(s: &str) -> bool {
    let d: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    d.len() == s.len()
        && d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 1 { let y = x * 2; if y > 9 { y - 9 } else { y } } else { x }).sum::<u32>() % 10 == 0
}

/// Strings returned by `service call iphonesubinfo N …` (one `## …` block per
/// call, as written by acquire), decoded from the Parcel hex dump.
pub fn parcel_strings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for block in text.split("## ").skip(1) {
        // The Parcel dump's ASCII column: '8.6.4.0.' → "8640".
        let s: String = block
            .lines()
            .filter_map(|l| l.split('\'').nth(1))
            .collect::<String>()
            .chars()
            .filter(|c| *c != '.')
            .collect();
        let s = s.trim().to_string();
        if s.len() >= 6 && !s.contains("Parcel") && !s.contains("FFFFFFFF") && !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// Classify telephony identifiers: IMEI (Luhn), IMSI (starts with the SIM's
/// MCC+MNC), ICCID (89…), line number.
pub fn classify_telephony(strings: &[String], sim_mccmnc: &[String]) -> Map<String, Value> {
    let (mut imei, mut imsi, mut iccid, mut msisdn) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for s in strings {
        let digits = s.chars().all(|c| c.is_ascii_digit());
        let t = s.trim_end_matches(['F', 'f']);
        if digits && s.len() == 15 && sim_mccmnc.iter().any(|m| !m.is_empty() && s.starts_with(m.as_str())) {
            imsi.insert(s.clone());
        } else if digits && s.len() == 15 && luhn(s) {
            imei.insert(s.clone());
        } else if t.starts_with("89") && (18..=22).contains(&t.len()) && t.chars().all(|c| c.is_ascii_digit()) {
            iccid.insert(t.to_string());
        } else if (s.starts_with('+') && s[1..].chars().all(|c| c.is_ascii_digit()) && s.len() >= 8) || (digits && (8..=14).contains(&s.len())) {
            msisdn.insert(s.clone());
        }
    }
    let mut m = Map::new();
    for (k, v) in [("imei", imei), ("imsi", imsi), ("iccid", iccid), ("line_number", msisdn)] {
        if !v.is_empty() {
            m.insert(k.into(), json!(v));
        }
    }
    m
}

fn prop(getprop: &str, key: &str) -> Option<String> {
    let pre = format!("[{key}]: [");
    getprop.lines().find_map(|l| l.trim().strip_prefix(pre.as_str()).map(|v| v.trim_end_matches(']').to_string())).filter(|v| !v.is_empty())
}

/// Every identifier useful for legal requests, from a case.
pub fn identifiers(case: &crate::case::Case) -> Value {
    let read = |f: &str| std::fs::read_to_string(case.root.join("device").join(f)).unwrap_or_default();
    let gp = read("getprop.txt");
    let secure = read("settings_secure.txt");
    let global = read("settings_global.txt");
    let set = |t: &str, k: &str| crate::artifacts::setting(t, k);

    let mut device = Map::new();
    for (k, v) in [
        ("manufacturer", prop(&gp, "ro.product.manufacturer")),
        ("model", prop(&gp, "ro.product.model")),
        ("device_name", set(&global, "device_name")),
        ("serial", prop(&gp, "ro.serialno").or_else(|| prop(&gp, "ro.boot.serialno"))),
        ("android_id", set(&secure, "android_id")),
        ("android_release", prop(&gp, "ro.build.version.release")),
        ("build_fingerprint", prop(&gp, "ro.build.fingerprint")),
    ] {
        if let Some(v) = v {
            device.insert(k.into(), json!(v));
        }
    }

    // Dual-SIM props are comma-separated per slot: ",20815".
    let split = |k: &str| prop(&gp, k).map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect::<Vec<_>>()).unwrap_or_default();
    let mut tel = classify_telephony(&parcel_strings(&read("iphonesubinfo.txt")), &split("gsm.sim.operator.numeric"));
    for (k, p) in [("sim_operator", "gsm.sim.operator.alpha"), ("sim_country", "gsm.sim.operator.iso-country"), ("network_operator", "gsm.operator.alpha")] {
        let v = split(p);
        if !v.is_empty() {
            tel.insert(k.into(), json!(v));
        }
    }

    let mut net = Map::new();
    let wifi = read("wifi.txt");
    if let Some(m) = wifi.lines().find_map(|l| l.trim().strip_prefix("wifi_sta_factory_mac_address=")) {
        net.insert("wifi_mac_factory".into(), json!(m.trim()));
    }
    if let Some(m) = set(&secure, "bluetooth_address") {
        net.insert("bluetooth_mac".into(), json!(m));
    }
    if let Some(m) = set(&secure, "bluetooth_name") {
        net.insert("bluetooth_name".into(), json!(m));
    }

    let accounts: Vec<Value> = parse_accounts(&read("accounts.txt"))
        .into_iter()
        .map(|(t, n)| json!({"service": service(&t), "type": t, "name": n}))
        .collect();

    let apps: Vec<Value> = crate::appdata::apps_of_interest(case.third_party.iter()).into_iter().map(|(p, c, o)| json!({"package": p, "category": c, "operator": o})).collect();

    json!({"device": device, "telephony": tel, "network": net, "accounts": accounts, "apps_of_interest": apps})
}

/// Terminal rendering of `identifiers()`.
pub fn print_identifiers(v: &Value) {
    let (b, d, z) = ("\x1b[1m", "\x1b[2m", "\x1b[0m");
    for (title, key) in [("Device", "device"), ("Telephony", "telephony"), ("Network", "network")] {
        let Some(m) = v[key].as_object().filter(|m| !m.is_empty()) else { continue };
        println!("{b}{title}{z}");
        for (k, x) in m {
            let s = match x {
                Value::Array(a) => a.iter().filter_map(|e| e.as_str()).collect::<Vec<_>>().join(", "),
                x => x.as_str().map(String::from).unwrap_or_else(|| x.to_string()),
            };
            println!("  {k:<18} {s}");
        }
    }
    if let Some(a) = v["accounts"].as_array().filter(|a| !a.is_empty()) {
        println!("{b}Accounts{z}");
        for x in a {
            println!("  {:<24} {}  {d}({}){z}", x["service"].as_str().unwrap_or(""), x["name"].as_str().unwrap_or(""), x["type"].as_str().unwrap_or(""));
        }
    }
    if let Some(a) = v["apps_of_interest"].as_array().filter(|a| !a.is_empty()) {
        println!("{b}Apps whose operator holds data (legal requests){z}");
        for x in a {
            println!("  {:<24} {:<20} {d}{}{z}", x["operator"].as_str().unwrap_or(""), x["category"].as_str().unwrap_or(""), x["package"].as_str().unwrap_or(""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accounts() {
        let a = parse_accounts("  Accounts: 2\n    Account {name=x@gmail.com, type=com.google}\n    Account {name=+33600000000, type=com.whatsapp}\n    Account {name=x@gmail.com, type=com.google}\n");
        assert_eq!(a, vec![("com.google".into(), "x@gmail.com".into()), ("com.whatsapp".into(), "+33600000000".into())]);
        assert_eq!(service("www.instagram.com"), "Instagram (user ID)");
    }

    #[test]
    fn telephony() {
        // Real `service call iphonesubinfo` output layout (values made up).
        let t = "## 1 s16\nResult: Parcel(\n  0x00000000: 00000000 0000000f 00350033 00300034 '........3.5.4.0.'\n  0x00000010: 00390032 00350030 00320033 00310035 '9.2.0.5.3.2.5.1.'\n  0x00000020: 00310035 00000032                   '5.1.7...        ')\n\
## 3 s16\nResult: Parcel(fffffffc ffffffff 00000000  '............')\n\
## 8 s16\nResult: Parcel(\n  0x0: 0 0 '2.0.8.1.5.0.0.4.4.6.7.9.5.2.2.')\n\
## 12 s16\nResult: Parcel(\n  0x0: 0 0 '8.9.3.3.1.5.0.2.2.4.0.8.7.0.7.7.1.2.7.F.')\n\
## 15 s16\nResult: Parcel(\n  0x0: 0 0 '+.3.3.6.0.0.0.0.0.0.0.0.')\n";
        let s = parcel_strings(t);
        assert_eq!(s.len(), 4);
        assert!(luhn("354092053251517"));
        assert!(!luhn("208150044679522"));
        let m = classify_telephony(&s, &["20815".into()]);
        assert_eq!(m["imei"], json!(["354092053251517"]));
        assert_eq!(m["imsi"], json!(["208150044679522"]));
        assert_eq!(m["iccid"], json!(["8933150224087077127"]));
        assert_eq!(m["line_number"], json!(["+33600000000"]));
    }

    #[test]
    fn wipe() {
        let pkgs: BTreeSet<String> = ["com.google.android.gms", "com.xiaomi.finddevice"].iter().map(|s| s.to_string()).collect();
        let acc = "Account {name=a@gmail.com, type=com.google}";
        let dp = "Device Owner (User 0):\n    admin=ComponentInfo{com.mdm/com.mdm.Admin}\n  Enabled Device Admins (User 0, provisioningState: 3):\n    com.mdm/com.mdm.Admin:\n";
        let (why, online) = wipe_risks(acc, &pkgs, dp, "Active default network: 100\n", Some(false));
        assert_eq!(why.len(), 2, "{why:?}");
        assert!(why[0].starts_with("Google"));
        assert!(why[1].contains("com.mdm/com.mdm.Admin"));
        assert!(online);
        let (why, online) = wipe_risks("", &pkgs, "", "Active default network: none\n", Some(true));
        assert!(why.is_empty() && !online);
        assert!(wipe_banner(&[], false).is_none());
    }
}
