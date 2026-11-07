//! `apex link`: what several exhibits have in common (numbers, e-mails,
//! accounts, wallets, IBANs, Wi-Fi networks, Bluetooth devices, sideloaded apps).

use crate::case::Case;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// kind → normalized value → (shown value, cases).
pub type Links = BTreeMap<&'static str, BTreeMap<String, (String, BTreeSet<String>)>>;

fn phone_key(s: &str) -> Option<String> {
    let d: String = s.split('@').next().unwrap_or(s).chars().filter(char::is_ascii_digit).collect();
    (d.len() >= 9).then(|| d[d.len() - 9..].to_string())
}

/// Wi-Fi network names: `cmd wifi list-networks` ("0  Name  wpa2-psk") or an import's listing.
fn ssids(text: &str) -> Vec<String> {
    let re = regex::Regex::new(r"^\s*\d+\s+(.+?)\s+(\S+)\s*$").unwrap();
    text.lines().skip_while(|l| !l.contains("SSID")).skip(1).filter_map(|l| re.captures(l).map(|c| c[1].trim().trim_matches('"').to_string())).filter(|s| !s.is_empty()).collect()
}

/// Identifiers of one case: (kind, key, shown).
fn items(case: &Case) -> Vec<(&'static str, String, String)> {
    let mut out = Vec::new();
    for c in crate::comms::load(case) {
        if let Some(k) = phone_key(&c.peer) {
            if matches!(c.kind, "sms" | "mms" | "call" | "contact" | "whatsapp" | "signal" | "telegram") {
                out.push(("phone", k, c.peer.split(" (").next().unwrap_or(&c.peer).to_string()));
            }
        }
    }
    for (kind, vals) in crate::search::extract(&crate::search::sources(case)) {
        for v in vals.keys() {
            match kind {
                "phone" => {
                    if let Some(k) = phone_key(v) {
                        out.push(("phone", k, v.clone()));
                    }
                }
                "email" => out.push(("email", v.to_lowercase(), v.clone())),
                "iban" => out.push(("iban", v.clone(), v.clone())),
                "bitcoin" | "ethereum" => out.push(("wallet", v.to_lowercase(), v.clone())),
                _ => {}
            }
        }
    }
    let ids = crate::seizure::identifiers(case);
    for a in ids["accounts"].as_array().into_iter().flatten() {
        let (t, n) = (a["type"].as_str().unwrap_or(""), a["name"].as_str().unwrap_or(""));
        let svc = a["service"].as_str().unwrap_or(t);
        // Names that are only the service's ("WhatsApp") say nothing.
        if !n.contains("***") && !n.is_empty() && !n.eq_ignore_ascii_case(svc) && !svc.to_lowercase().starts_with(&n.to_lowercase()) {
            out.push(("account", format!("{t}:{}", n.to_lowercase()), format!("{} ({})", n, a["service"].as_str().unwrap_or(t))));
        }
    }
    for s in ssids(&std::fs::read_to_string(case.root.join("device/wifi_networks.txt")).unwrap_or_default()) {
        out.push(("wifi", s.clone(), s));
    }
    if let Some(v) = crate::agent::load(&case.root) {
        for b in v["sections"]["bluetooth"].as_array().into_iter().flatten() {
            if let Some(a) = b["address"].as_str() {
                out.push(("bluetooth", a.to_uppercase(), format!("{a} ({})", b["name"].as_str().unwrap_or(""))));
            }
        }
    }
    let stores = &crate::rules::r().stores;
    for p in case.packages.iter().filter(|p| case.third_party.contains(&p.name) && p.name != crate::agent::PKG) {
        if !p.installer.as_deref().is_some_and(|i| crate::rules::app_matches(stores, i)) {
            out.push(("sideloaded_app", p.name.clone(), p.name.clone()));
        }
    }
    out
}

/// Values found in at least two of the cases.
pub fn link(cases: &[PathBuf]) -> Links {
    let mut all: Links = BTreeMap::new();
    for root in cases {
        let c = Case::load(root);
        let label = case_label(root);
        for (kind, key, shown) in items(&c) {
            let e = all.entry(kind).or_default().entry(key).or_insert_with(|| (shown, BTreeSet::new()));
            e.1.insert(label.clone());
        }
    }
    for v in all.values_mut() {
        v.retain(|_, (_, cs)| cs.len() >= 2);
    }
    all.retain(|_, v| !v.is_empty());
    all
}

/// Seal or case ID from the manifest, else the directory name.
pub fn case_label(root: &Path) -> String {
    let m: serde_json::Value = std::fs::read_to_string(root.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let dir = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    match (m["case"]["seal"].as_str(), m["case"]["case_id"].as_str()) {
        (Some(s), _) => format!("{s} ({dir})"),
        (None, Some(id)) => format!("{id} ({dir})"),
        _ => dir,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_wifi() {
        assert_eq!(phone_key("+33 6 12 34 56 78"), phone_key("0612345678"));
        assert_eq!(phone_key("33612345678@s.whatsapp.net"), Some("612345678".into()));
        let t = "Network Id      SSID                         Security type\n0      Freebox-1234 wpa2-psk\n1      \"Cafe du port\" open\n";
        assert_eq!(ssids(t), vec!["Freebox-1234".to_string(), "Cafe du port".to_string()]);
    }
}
