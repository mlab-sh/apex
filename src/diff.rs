//! `apex diff OLD NEW`: what changed on a phone between two `device acquire`
//! cases (apps, signing certificates, users, sensitive settings, findings).
//! The typical use is "before / after handing the phone back" or a periodic
//! check of a protected person's phone.

use crate::case::Case;
use crate::ioc::IocSet;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Settings whose change matters in an investigation: (file, key).
const SETTINGS: &[(&str, &str)] = &[
    ("settings_secure", "enabled_accessibility_services"),
    ("settings_secure", "enabled_notification_listeners"),
    ("settings_secure", "default_input_method"),
    ("settings_secure", "install_non_market_apps"),
    ("settings_secure", "always_on_vpn_app"),
    ("settings_global", "adb_enabled"),
    ("settings_global", "adb_wifi_enabled"),
    ("settings_global", "development_settings_enabled"),
    ("settings_global", "package_verifier_enable"),
    ("settings_global", "verifier_verify_adb_installs"),
    ("settings_global", "private_dns_mode"),
    ("settings_global", "private_dns_specifier"),
    ("settings_global", "http_proxy"),
    ("settings_global", "global_http_proxy_host"),
];

const IDENTIFIERS: &[&str] = &["model", "serial", "android_release", "security_patch", "build_fingerprint"];

fn read(c: &Case, rel: &str) -> String {
    std::fs::read(c.root.join(rel)).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default()
}

/// `versionName=` from an acquired app's dumpsys.
fn version(c: &Case, pkg: &str) -> Option<String> {
    read(c, &format!("apps/{pkg}/dumpsys_package.txt"))
        .lines()
        .find_map(|l| l.trim().strip_prefix("versionName=").map(str::to_string))
}

fn signers(c: &Case, pkg: &str) -> Vec<String> {
    let apk = c.root.join("apps").join(pkg).join("base.apk");
    if apk.is_file() {
        crate::cert_util::apk_signer_sha1s(&apk)
    } else {
        Vec::new()
    }
}

fn set_diff<T: Ord + Clone + serde::Serialize>(a: &BTreeSet<T>, b: &BTreeSet<T>) -> Value {
    json!({
        "added": b.difference(a).cloned().collect::<Vec<_>>(),
        "removed": a.difference(b).cloned().collect::<Vec<_>>(),
    })
}

pub fn diff(old: &Case, new: &Case, iocs: &IocSet) -> Value {
    // Device identity: a different serial means these are not the same phone.
    let ids = |c: &Case| serde_json::from_str::<Value>(&read(c, "device/identifiers.json")).unwrap_or(Value::Null);
    let (ia, ib) = (ids(old), ids(new));
    let device: BTreeMap<&str, Value> = IDENTIFIERS
        .iter()
        .filter(|k| ia[**k] != ib[**k])
        .map(|k| (*k, json!({"old": ia[*k], "new": ib[*k]})))
        .collect();

    let names = |c: &Case| c.third_party.iter().cloned().collect::<BTreeSet<String>>();
    let (ta, tb) = (names(old), names(new));
    let all = |c: &Case| c.packages.iter().map(|p| p.name.clone()).collect::<BTreeSet<String>>();
    let mut changed = Vec::new();
    for pkg in ta.intersection(&tb) {
        let mut ch = serde_json::Map::new();
        let inst = |c: &Case| c.packages.iter().find(|p| &p.name == pkg).and_then(|p| p.installer.clone());
        if inst(old) != inst(new) {
            ch.insert("installer".into(), json!({"old": inst(old), "new": inst(new)}));
        }
        let (va, vb) = (version(old, pkg), version(new, pkg));
        // Only when both cases acquired the app (a `--package` run has one).
        if va.is_some() && vb.is_some() && va != vb {
            ch.insert("version".into(), json!({"old": va, "new": vb}));
        }
        let (sa, sb) = (signers(old, pkg), signers(new, pkg));
        // Same package, different signer: the app was replaced by someone else's build.
        if !sa.is_empty() && !sb.is_empty() && sa != sb {
            ch.insert("signer_sha1".into(), json!({"old": sa, "new": sb}));
        }
        if !ch.is_empty() {
            ch.insert("package".into(), json!(pkg));
            changed.push(Value::Object(ch));
        }
    }

    let users = |c: &Case| c.users.iter().map(|u| format!("{}:{} ({})", u.id, u.name, u.kind())).collect::<BTreeSet<_>>();
    let roles = |c: &Case| {
        let mut s = BTreeSet::new();
        s.extend(c.admins.iter().map(|p| format!("device admin: {p}")));
        s.extend(c.accessibility.iter().map(|p| format!("accessibility: {p}")));
        s.extend(c.notif_listeners.iter().map(|p| format!("notification listener: {p}")));
        s
    };

    let mut settings = BTreeMap::new();
    for (file, key) in SETTINGS {
        let get = |c: &Case| crate::artifacts::setting(&read(c, &format!("device/{file}.txt")), key);
        let (a, b) = (get(old), get(new));
        if a != b {
            settings.insert(format!("{file}/{key}"), json!({"old": a, "new": b}));
        }
    }

    // Findings can only be compared on artifacts both cases have.
    let files = |c: &Case| {
        std::fs::read_dir(c.root.join("device"))
            .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect::<BTreeSet<_>>())
            .unwrap_or_default()
    };

    let fkey = |f: &crate::models::Finding| format!("[{}] {}", f.severity.value(), f.title);
    let fa: BTreeSet<String> = old.findings(iocs).iter().map(fkey).collect();
    let fb: BTreeSet<String> = new.findings(iocs).iter().map(fkey).collect();

    json!({
        "old": old.root.display().to_string(),
        "new": new.root.display().to_string(),
        "old_capture": old.capture_local.map(|t| t.to_string()),
        "new_capture": new.capture_local.map(|t| t.to_string()),
        "device": device,
        "third_party_apps": set_diff(&ta, &tb),
        "all_packages": set_diff(&all(old), &all(new)),
        "changed_apps": changed,
        "users": set_diff(&users(old), &users(new)),
        "privileges": set_diff(&roles(old), &roles(new)),
        "settings": settings,
        "findings": set_diff(&fa, &fb),
        "artifacts": set_diff(&files(old), &files(new)),
    })
}

/// Terminal rendering of `diff()`.
pub fn print(d: &Value) {
    let (g, r, y, dim, b, z) = ("\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[2m", "\x1b[1m", "\x1b[0m");
    println!("{b}apex diff{z}  {dim}{} ({}) → {} ({}){z}", d["old"].as_str().unwrap_or(""), d["old_capture"].as_str().unwrap_or("?"), d["new"].as_str().unwrap_or(""), d["new_capture"].as_str().unwrap_or("?"));
    let mut any = false;
    let section = |title: &str, v: &Value, any: &mut bool| {
        let (add, rem) = (v["added"].as_array().cloned().unwrap_or_default(), v["removed"].as_array().cloned().unwrap_or_default());
        if add.is_empty() && rem.is_empty() {
            return;
        }
        *any = true;
        println!("\n{b}{title}{z}");
        for x in &add {
            println!("  {g}+ {}{z}", x.as_str().unwrap_or(""));
        }
        for x in &rem {
            println!("  {r}- {}{z}", x.as_str().unwrap_or(""));
        }
    };
    if let Some(m) = d["device"].as_object().filter(|m| !m.is_empty()) {
        any = true;
        println!("\n{b}Device{z}");
        for (k, v) in m {
            let warn = if k == "serial" { format!("  {r}(different phone?){z}") } else { String::new() };
            println!("  {y}~ {k}: {} → {}{z}{warn}", v["old"], v["new"]);
        }
    }
    section("Third-party apps", &d["third_party_apps"], &mut any);
    if let Some(a) = d["changed_apps"].as_array().filter(|a| !a.is_empty()) {
        any = true;
        println!("\n{b}Apps changed{z}");
        for c in a {
            let pkg = c["package"].as_str().unwrap_or("");
            for (k, v) in c.as_object().into_iter().flatten().filter(|(k, _)| *k != "package") {
                let col = if k == "signer_sha1" { r } else { y };
                let note = if k == "signer_sha1" { "  (signed by someone else: replaced app)" } else { "" };
                println!("  {col}~ {pkg} {k}: {} → {}{note}{z}", v["old"], v["new"]);
            }
        }
    }
    section("Users / profiles", &d["users"], &mut any);
    section("Privileged apps", &d["privileges"], &mut any);
    if let Some(m) = d["settings"].as_object().filter(|m| !m.is_empty()) {
        any = true;
        println!("\n{b}Settings{z}");
        for (k, v) in m {
            println!("  {y}~ {k}: {} → {}{z}", v["old"], v["new"]);
        }
    }
    section("Findings", &d["findings"], &mut any);
    let only = |k: &str| d["artifacts"][k].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    for (k, which) in [("removed", "old"), ("added", "new")] {
        if !only(k).is_empty() {
            println!("\n{y}Only in the {which} case: {}. Findings based on these are not comparable.{z}", only(k));
        }
    }
    let sys = &d["all_packages"];
    let n = |k: &str| sys[k].as_array().map(|a| a.len()).unwrap_or(0);
    if n("added") + n("removed") > 0 {
        println!("\n{dim}All packages incl. system: +{} -{} (see --json for the list){z}", n("added"), n("removed"));
    }
    if !any {
        println!("\n{g}No change in apps, users, privileges, settings or findings.{z}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sets() {
        let a: BTreeSet<String> = ["x", "y"].iter().map(|s| s.to_string()).collect();
        let b: BTreeSet<String> = ["y", "z"].iter().map(|s| s.to_string()).collect();
        assert_eq!(set_diff(&a, &b), json!({"added": ["z"], "removed": ["x"]}));
    }
}
