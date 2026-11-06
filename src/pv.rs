//! `apex pv`: a French *procès-verbal de constatations* for one or several
//! exhibits (one APEX case per seal), self-contained HTML, printable.
//!
//! It states facts only: what the phone was, its state at reception, what was
//! done (from the audit log), with which hashes, and what was observed. Every
//! statement comes from the hashed case files; nothing is typed by hand except
//! the service, the officer and the place.

use crate::case::Case;
use crate::ioc::IocSet;
use crate::models::Severity;
use serde_json::Value;
use std::fmt::Write;
use std::path::Path;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

pub struct Header {
    pub service: Option<String>,
    pub officer: Option<String>,
    pub place: Option<String>,
}

const CSS: &str = r#"
body{margin:0;background:#fff;color:#111;font:14px/1.55 Georgia,"Times New Roman",serif}
main{max-width:820px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:20px;text-align:center;text-transform:uppercase;letter-spacing:.04em;margin:0 0 4px}
.sub{text-align:center;margin:0 0 24px}
h2{font-size:16px;margin:28px 0 8px;border-bottom:1px solid #999;padding-bottom:4px}
h3{font-size:14px;margin:18px 0 6px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:6px 0}
th,td{border:1px solid #bbb;padding:4px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{width:34%;background:#f3f3f3;font-weight:normal}
code{font-family:ui-monospace,Menlo,monospace;font-size:12px;overflow-wrap:anywhere}
.sign{margin-top:48px;display:flex;justify-content:space-between}
.sign div{width:45%;border-top:1px solid #111;padding-top:6px;text-align:center}
@media print{main{padding:0}h2{break-after:avoid}table{break-inside:avoid}}
"#;

/// The wipe-risk lines of `seizure`, in French.
fn fr_wipe(w: &str) -> String {
    w.replace(": account signed in, erase possible from the web unless the owner turned it off", " : compte connecté, effacement possible depuis le web sauf désactivation par le propriétaire")
        .replace("managed device (MDM owner ", "appareil géré (propriétaire MDM ")
        .replace("): its console can wipe the phone", ") : sa console d'administration peut effacer le téléphone")
        .replace("active device admin ", "administrateur de l'appareil actif ")
        .replace(": may hold the wipe-data policy", " : peut disposer du droit d'effacement")
}

fn kv(h: &mut String, rows: &[(&str, String)]) {
    h.push_str("<table>");
    for (k, v) in rows.iter().filter(|(_, v)| !v.is_empty()) {
        let _ = write!(h, "<tr><th>{k}</th><td>{v}</td></tr>");
    }
    h.push_str("</table>");
}

fn setting(case: &Case, file: &str, key: &str) -> Option<String> {
    crate::artifacts::setting(&std::fs::read_to_string(case.root.join("device").join(file)).unwrap_or_default(), key)
}

fn on_off(v: Option<String>) -> String {
    match v.as_deref() {
        Some("1") => "activé".into(),
        Some("0") => "désactivé".into(),
        _ => String::new(),
    }
}

/// Battery level and charging state from `dumpsys battery`.
fn battery(case: &Case) -> String {
    let t = std::fs::read_to_string(case.root.join("device/battery.txt")).unwrap_or_default();
    let get = |k: &str| t.lines().find_map(|l| l.trim().strip_prefix(k).map(|v| v.trim().to_string()));
    let level = get("level:");
    let charging = ["AC powered:", "USB powered:", "Wireless powered:"].iter().any(|k| get(k).as_deref() == Some("true"));
    match level {
        Some(l) => format!("{l} %{}", if charging { ", en charge" } else { ", sur batterie" }),
        None => String::new(),
    }
}

fn exhibit(h: &mut String, n: usize, root: &Path, iocs: &IocSet) {
    let case = Case::load(root);
    let manifest: Value = std::fs::read_to_string(root.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let ids = crate::seizure::identifiers(&case);
    let d = &ids["device"];
    let t = &ids["telephony"];
    let join = |v: &Value| match v {
        Value::Array(a) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "),
        v => v.as_str().unwrap_or("").to_string(),
    };
    let seal = manifest["case"]["seal"].as_str().map(String::from).unwrap_or_else(|| format!("pièce n°{n}"));
    let _ = write!(h, "<h2>{}. {}</h2>", n, esc(&seal));

    h.push_str("<h3>Description de l'appareil</h3>");
    kv(
        h,
        &[
            ("Marque, modèle", esc(&format!("{} {}", join(&d["manufacturer"]), join(&d["model"])))),
            ("Nom de l'appareil", esc(&join(&d["device_name"]))),
            ("Numéro de série", esc(&join(&d["serial"]))),
            ("IMEI", esc(&join(&t["imei"]))),
            ("Numéro de ligne", esc(&join(&t["line_number"]))),
            ("ICCID (carte SIM)", esc(&join(&t["iccid"]))),
            ("IMSI", esc(&join(&t["imsi"]))),
            ("Opérateur", esc(&join(&t["sim_operator"]))),
            ("Système", esc(&format!("Android {}", join(&d["android_release"])))),
            ("Empreinte du système", format!("<code>{}</code>", esc(&join(&d["build_fingerprint"])))),
        ],
    );

    h.push_str("<h3>État constaté</h3>");
    let pkgs = case.packages.iter().map(|p| p.name.clone()).collect();
    let rd = |f: &str| std::fs::read_to_string(root.join("device").join(f)).unwrap_or_default();
    let (wipe, online) = crate::seizure::wipe_risks(&rd("accounts.txt"), &pkgs, &rd("device_policy.txt"), &rd("connectivity.txt"), None);
    let imported = manifest["operation"] == "ffs_import";
    let clock = match (case.capture_local, &case.utc_offset) {
        (Some(t), o) => format!("{} (UTC{}){}", t.format("%d/%m/%Y %H:%M:%S"), o.as_deref().unwrap_or("?"), case.clock_skew_s.map(|s| format!(", écart de {s} s avec l'horloge de l'examinateur")).unwrap_or_default()),
        _ => String::new(),
    };
    kv(
        h,
        &[
            ("Horloge de l'appareil", esc(&clock)),
            ("Batterie", esc(&battery(&case))),
            ("Mode avion", on_off(setting(&case, "settings_global.txt", "airplane_mode_on"))),
            ("Wi-Fi", on_off(setting(&case, "settings_global.txt", "wifi_on"))),
            ("Bluetooth", on_off(setting(&case, "settings_global.txt", "bluetooth_on"))),
            ("Connexion réseau", if imported { String::new() } else if online { "en ligne au moment de l'opération".into() } else { "hors ligne".into() }),
            (
                "Effacement à distance",
                if wipe.is_empty() { "aucun service d'effacement à distance détecté".into() } else { esc(&wipe.iter().map(|w| fr_wipe(w)).collect::<Vec<_>>().join(" ; ")) },
            ),
        ],
    );

    h.push_str("<h3>Opérations réalisées</h3>");
    let s = &manifest["session"];
    let op = match manifest["operation"].as_str() {
        Some("device_triage") => "Triage (état volatil et identifiants) par liaison ADB, sans root",
        Some("device_acquire") => "Acquisition logique par liaison ADB, sans root",
        Some("ffs_import") => "Exploitation d'une extraction complète du système de fichiers réalisée par ailleurs",
        Some(o) => o,
        None => "",
    };
    let audit = std::fs::read_to_string(root.join("audit.jsonl")).unwrap_or_default();
    kv(
        h,
        &[
            ("Nature", esc(op)),
            ("Début (UTC)", esc(s["started_utc"].as_str().unwrap_or(""))),
            ("Fin (UTC)", esc(s["ended_utc"].as_str().unwrap_or(""))),
            ("Liaison", esc(s["transport"].as_str().unwrap_or(""))),
            ("Source", esc(s["source"].as_str().unwrap_or(""))),
            ("Commandes émises", if audit.is_empty() { String::new() } else { format!("{} (journal <code>audit.jsonl</code>, horodaté et haché)", audit.lines().count()) }),
            ("Réquisition / mandat", esc(manifest["case"]["mandate"].as_str().unwrap_or(""))),
            ("Outil", esc(&format!("APEX {}", manifest["tool"]["version"].as_str().unwrap_or("")))),
        ],
    );

    h.push_str("<h3>Intégrité</h3>");
    let msha = std::fs::read_to_string(root.join("manifest.json.sha256")).unwrap_or_default();
    let verify = match crate::verify::verify_dir(root.to_path_buf()) {
        Ok(r) if r.passed() => format!("vérifiée : {} fichiers conformes au manifeste", r.matched.len()),
        Ok(r) => format!("ÉCHEC : {} fichier(s) manquant(s)", r.missing.len()),
        Err(e) => format!("non vérifiable : {e}"),
    };
    let tsa = crate::tsa::describe(root);
    kv(
        h,
        &[
            ("Empreinte SHA-256 du manifeste", format!("<code>{}</code>", esc(msha.split_whitespace().next().unwrap_or("")))),
            ("Contrôle d'intégrité", esc(&verify)),
            ("Horodatage RFC 3161", esc(&tsa.unwrap_or_default())),
        ],
    );

    h.push_str("<h3>Constatations</h3>");
    let mut f = case.findings(iocs);
    f.retain(|x| x.severity >= Severity::Medium);
    f.sort_by(|a, b| b.severity.cmp(&a.severity));
    if f.is_empty() {
        h.push_str("<p>Aucun élément de gravité moyenne ou supérieure n'a été relevé par l'analyse automatique.</p>");
    } else {
        h.push_str("<p>L'analyse automatique relève les éléments suivants, à apprécier par l'enquêteur (indices et non preuves ; intitulés de l'outil, en anglais) :</p><table>");
        for x in f {
            let sev = match x.severity {
                Severity::Critical => "critique",
                Severity::High => "élevée",
                _ => "moyenne",
            };
            let _ = write!(h, "<tr><th>{sev}</th><td>{}</td></tr>", esc(&x.title));
        }
        h.push_str("</table>");
    }
    let comms = crate::comms::counts(&crate::comms::load(&case));
    if !comms.is_empty() {
        let list: Vec<String> = comms.iter().map(|(k, (n, r))| format!("{n} {k}{}", if *r > 0 { format!(" (dont {r} supprimé(s) récupéré(s))") } else { String::new() })).collect();
        let _ = write!(h, "<p>Communications extraites en exécution du mandat : {}. Le détail figure dans l'export <code>apex comms</code>.</p>", esc(&list.join(", ")));
    }
}

pub fn render(cases: &[&Path], head: &Header, iocs: &IocSet) -> String {
    let mut h = String::new();
    let first: Value = cases
        .first()
        .and_then(|c| std::fs::read_to_string(c.join("manifest.json")).ok())
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let dossier = first["case"]["case_id"].as_str().unwrap_or("");
    let officer = head.officer.clone().or_else(|| first["case"]["examiner"].as_str().map(String::from)).unwrap_or_default();
    let now = chrono::Local::now();
    let _ = write!(h, "<!doctype html><html lang=\"fr\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Procès-verbal {}</title><style>{CSS}</style></head><body><main>", esc(dossier));
    h.push_str("<h1>Procès-verbal de constatations</h1><p class=\"sub\">Exploitation de téléphone(s) mobile(s)</p>");
    kv(
        &mut h,
        &[
            ("Dossier", esc(dossier)),
            ("Service", esc(head.service.as_deref().unwrap_or(""))),
            ("Rédacteur", esc(&officer)),
            ("Lieu", esc(head.place.as_deref().unwrap_or(""))),
            ("Date de rédaction", now.format("%d/%m/%Y à %H:%M").to_string()),
            ("Pièces", cases.len().to_string()),
        ],
    );
    let _ = write!(
        h,
        "<p>{} a procédé à l'exploitation de la ou des pièces ci-dessous au moyen de l'outil APEX. Les constatations qui suivent sont établies à partir des fichiers produits par l'outil, dont l'intégrité est garantie par les empreintes SHA-256 consignées dans le manifeste de chaque pièce.</p>",
        if officer.is_empty() { "L'examinateur".to_string() } else { esc(&officer) }
    );
    for (i, c) in cases.iter().enumerate() {
        exhibit(&mut h, i + 1, c, iocs);
    }
    h.push_str("<h2>Méthode et limites</h2><ul>");
    for n in first["methodology"].as_array().into_iter().flatten() {
        let _ = write!(h, "<li>{}</li>", esc(n.as_str().unwrap_or("")));
    }
    h.push_str("<li>Les éléments relevés automatiquement sont des indices à confirmer par l'enquêteur ; des applications légitimes peuvent présenter les mêmes caractéristiques.</li></ul>");
    h.push_str("<p>Dont acte.</p><div class=\"sign\"><div>Le rédacteur</div><div>Visa</div></div></main></body></html>\n");
    h
}
