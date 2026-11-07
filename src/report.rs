//! `apex report CASE`: a single self-contained HTML case report (no external
//! assets), for a non-technical reader or a case file. Prints cleanly.

use crate::case::Case;
use crate::ioc::IocSet;
use crate::models::{Finding, Severity};
use serde_json::Value;
use std::fmt::Write;

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn val(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "—".into(),
        Value::Array(a) => a.iter().map(val).collect::<Vec<_>>().join(", "),
        Value::Object(o) => o.iter().map(|(k, v)| format!("{k}: {}", val(v))).collect::<Vec<_>>().join("; "),
        v => v.to_string(),
    }
}

fn mb(b: u64) -> String {
    format!("{:.1} MB", b as f64 / 1_048_576.0)
}

const SEVS: [Severity; 5] = [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info];

const CSS: &str = r#"
:root{--bg:#fff;--fg:#1d1d1f;--mut:#6e6e73;--line:#e5e5ea;--card:#f7f7f9;
--critical:#b0002a;--high:#d1402f;--medium:#b7791f;--low:#2b6cb0;--info:#6e6e73}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#f2f2f4;--mut:#a1a1a6;--line:#2c2c30;--card:#1c1c1f;
--critical:#ff5c7a;--high:#ff7a66;--medium:#e0b050;--low:#6aa7ff;--info:#a1a1a6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1000px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:26px;margin:0 0 4px}h2{font-size:18px;margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.mut{color:var(--mut)}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
th{color:var(--mut);font-weight:600}.kv th{width:30%}
.counts{display:flex;gap:8px;flex-wrap:wrap}.count{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 14px;min-width:90px}
.count b{display:block;font-size:22px}
.sev{display:inline-block;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.03em;min-width:72px}
.critical{color:var(--critical)}.high{color:var(--high)}.medium{color:var(--medium)}.low{color:var(--low)}.info{color:var(--info)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}
summary{cursor:pointer;padding:10px 12px;list-style-position:outside}details>div{padding:0 12px 12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:2px 12px;margin:8px 0 0;font-size:13px}dt{color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}
.tbl{overflow-x:auto}.ok{color:#2f855a}.bad{color:var(--critical)}
@media print{details{break-inside:avoid}details:not([open])>div{display:block}body{font-size:12px}}
"#;

pub fn render(case: &Case, iocs: &IocSet, extra: Vec<Finding>) -> String {
    let manifest: Value = std::fs::read_to_string(case.root.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let ids: Value = std::fs::read_to_string(case.root.join("device/identifiers.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut findings = case.findings(iocs);
    findings.extend(extra);
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.title.cmp(&b.title)));

    let mut h = String::new();
    let title = manifest["case"]["case_id"].as_str().map(|c| format!("APEX case report — {c}")).unwrap_or_else(|| "APEX case report".into());
    let _ = write!(h, "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>{CSS}</style></head><body><main>", esc(&title));
    let _ = write!(
        h,
        "<h1>{}</h1><p class=\"mut\">{} {} · generated {} · apex {}</p>",
        esc(&title),
        esc(ids["manufacturer"].as_str().unwrap_or("")),
        esc(ids["model"].as_str().unwrap_or("")),
        chrono::Utc::now().format("%Y-%m-%d %H:%M UTC"),
        env!("CARGO_PKG_VERSION")
    );

    // --- Case & acquisition.
    let integrity = match crate::verify::verify_dir(case.root.clone()) {
        Ok(r) if r.passed() => format!("<span class=\"ok\">verified</span> ({} artifacts match the manifest)", r.matched.len()),
        Ok(r) => format!("<span class=\"bad\">FAILED</span> ({} missing, manifest {})", r.missing.len(), if r.manifest_ok == Some(false) { "altered" } else { "ok" }),
        Err(e) => format!("<span class=\"bad\">not verifiable</span>: {}", esc(&e)),
    };
    let mut kv: Vec<(&str, String)> = Vec::new();
    for (k, label) in [("case_id", "Case"), ("examiner", "Examiner"), ("notes", "Notes")] {
        if let Some(v) = manifest["case"][k].as_str() {
            kv.push((label, esc(v)));
        }
    }
    let session = &manifest["session"];
    let imported = manifest["operation"] == "ffs_import";
    if imported {
        kv.push(("Source extraction", esc(manifest["session"]["source"].as_str().unwrap_or("?"))));
    }
    kv.push((if imported { "Imported (UTC)" } else { "Acquired (UTC)" }, esc(&format!("{} → {}", session["started_utc"].as_str().unwrap_or("?"), session["ended_utc"].as_str().unwrap_or("?")))));
    kv.push(("Device clock at capture", esc(&format!("{} {}", case.capture_local.map(|t| t.to_string()).unwrap_or("?".into()), case.utc_offset.as_deref().unwrap_or("")))));
    if let Some(s) = case.clock_skew_s {
        kv.push(("Clock skew vs examiner", format!("{s} s")));
    }
    kv.push(("Time zone", esc(&case.tz.map(|t| t.to_string()).unwrap_or("unknown".into()))));
    kv.push(("Transport", esc(session["transport"].as_str().unwrap_or("?"))));
    kv.push(("Commands issued", session["command_count"].to_string()));
    kv.push(("Integrity", integrity));
    for (k, label) in [("serial", "Serial"), ("android_release", "Android"), ("security_patch", "Security patch"), ("build_fingerprint", "Build")] {
        kv.push((label, esc(&val(&ids[k]))));
    }
    h.push_str("<h2>Case and acquisition</h2><table class=\"kv\">");
    for (k, v) in kv {
        let _ = write!(h, "<tr><th>{k}</th><td>{v}</td></tr>");
    }
    h.push_str("</table>");

    // --- Identifiers for legal requests.
    let idv = crate::seizure::identifiers(case);
    h.push_str("<h2>Identifiers for legal requests</h2><table class=\"kv\">");
    for key in ["device", "telephony", "network"] {
        for (k, v) in idv[key].as_object().into_iter().flatten() {
            let _ = write!(h, "<tr><th>{}</th><td>{}</td></tr>", esc(&k.replace('_', " ")), esc(&val(v)));
        }
    }
    for a in idv["accounts"].as_array().into_iter().flatten() {
        let _ = write!(h, "<tr><th>{}</th><td>{}</td></tr>", esc(a["service"].as_str().unwrap_or("")), esc(a["name"].as_str().unwrap_or("")));
    }
    for a in idv["apps_of_interest"].as_array().into_iter().flatten() {
        let _ = write!(h, "<tr><th>{}</th><td>{} · {}</td></tr>", esc(a["operator"].as_str().unwrap_or("")), esc(a["category"].as_str().unwrap_or("")), esc(a["package"].as_str().unwrap_or("")));
    }
    h.push_str("</table>");

    // --- Findings.
    h.push_str("<h2>Findings</h2><div class=\"counts\">");
    for s in SEVS {
        let n = findings.iter().filter(|f| f.severity == s).count();
        let _ = write!(h, "<div class=\"count\"><b class=\"{0}\">{n}</b><span class=\"mut\">{0}</span></div>", s.value());
    }
    h.push_str("</div>");
    if findings.is_empty() {
        h.push_str("<p>No investigation finding.</p>");
    }
    for f in &findings {
        let open = if f.severity >= Severity::High { " open" } else { "" };
        let _ = write!(
            h,
            "<details{open}><summary><span class=\"sev {0}\">{0}</span> {1}</summary><div><p>{2}</p><dl><dt>ID</dt><dd>{3}</dd>",
            f.severity.value(),
            esc(&f.title),
            esc(&f.description),
            esc(&f.id)
        );
        if let Some(m) = &f.mitre {
            let _ = write!(h, "<dt>MITRE ATT&amp;CK</dt><dd>{}</dd>", esc(m));
        }
        for (k, v) in &f.metadata {
            let _ = write!(h, "<dt>{}</dt><dd>{}</dd>", esc(k), esc(&val(v)));
        }
        h.push_str("</dl></div></details>");
    }

    // --- Communications (under mandate): counts only, content goes through `apex comms`.
    let comms = crate::comms::load(case);
    if !comms.is_empty() {
        let _ = write!(h, "<h2>Communications (mandate {})</h2><table><tr><th>Kind</th><th>Records</th><th>Recovered (deleted)</th></tr>", esc(manifest["case"]["mandate"].as_str().unwrap_or("not recorded")));
        for (k, (n, r)) in crate::comms::counts(&comms) {
            let _ = write!(h, "<tr><td>{}</td><td>{n}</td><td>{r}</td></tr>", esc(&k));
        }
        h.push_str("</table><p class=\"mut\">Content is exported separately with <code>apex comms</code> (CSV, JSON).</p>");
    }

    // --- Media with a location.
    let files = crate::media::storage_files(case);
    if !files.is_empty() {
        let metas = crate::par_map(&files, |p| crate::media::file_meta(p));
        let located: Vec<(String, crate::media::Meta)> = files
            .iter()
            .zip(metas)
            .filter(|(_, m)| m.lat.is_some() && m.lon.is_some())
            .map(|(p, m)| (p.strip_prefix(case.root.join("storage")).unwrap_or(p).to_string_lossy().into_owned(), m))
            .collect();
        let _ = write!(h, "<h2>Media ({} files, {} with a location)</h2>", files.len(), located.len());
        if !located.is_empty() {
            h.push_str("<div class=\"tbl\"><table><tr><th>File</th><th>Taken</th><th>Location</th></tr>");
            for (rel, m) in located.iter().take(200) {
                let (la, lo) = (m.lat.unwrap(), m.lon.unwrap());
                let _ = write!(
                    h,
                    "<tr><td>{}</td><td>{}</td><td><a href=\"https://www.openstreetmap.org/?mlat={la:.6}&amp;mlon={lo:.6}#map=17/{la:.6}/{lo:.6}\">{la:.6}, {lo:.6}</a></td></tr>",
                    esc(rel),
                    esc(&m.taken.as_deref().map(|t| case.iso(t)).unwrap_or_default())
                );
            }
            h.push_str("</table></div><p class=\"mut\">Full inventory, KML and GeoJSON: <code>apex media</code>.</p>");
        }
    }

    // --- Apps.
    let traffic = crate::history::traffic_by_package(case);
    let mut apps: Vec<&crate::case::Pkg> = case.packages.iter().filter(|p| case.third_party.contains(&p.name)).collect();
    apps.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = write!(h, "<h2>User-installed apps ({})</h2><div class=\"tbl\"><table><tr><th>Package</th><th>Installer</th><th>Flags</th><th>Users</th><th>Traffic ↓ / ↑</th></tr>", apps.len());
    for p in apps {
        let mut flags = Vec::new();
        if case.sideloaded(p) {
            flags.push("sideloaded");
        }
        if case.launchable.as_ref().is_some_and(|l| !l.contains(&p.name)) {
            flags.push("hidden");
        }
        if case.accessibility.contains(&p.name) {
            flags.push("accessibility");
        }
        if case.admins.contains(&p.name) {
            flags.push("device admin");
        }
        if case.notif_listeners.contains(&p.name) {
            flags.push("notification listener");
        }
        let mut users: Vec<String> = Vec::new();
        if case.third_party_main.contains(&p.name) {
            users.push("0".into());
        }
        users.extend(case.profile_apps.iter().filter(|(_, s)| s.contains(&p.name)).map(|(u, _)| u.to_string()));
        let t = traffic.get(&p.name).map(|t| format!("{} / {}", mb(t.rx), mb(t.tx))).unwrap_or_default();
        let _ = write!(
            h,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&p.name),
            esc(p.installer.as_deref().unwrap_or("none (adb or preload)")),
            flags.join(", "),
            users.join(", "),
            t
        );
    }
    h.push_str("</table></div>");

    if !case.users.is_empty() {
        h.push_str("<h2>Users and profiles</h2><table><tr><th>ID</th><th>Name</th><th>Kind</th><th>Running</th></tr>");
        for u in &case.users {
            let _ = write!(h, "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>", u.id, esc(&u.name), u.kind(), if u.running { "yes" } else { "no" });
        }
        h.push_str("</table>");
    }

    // --- Method.
    h.push_str("<h2>Method and limits</h2><ul>");
    for n in manifest["methodology"].as_array().into_iter().flatten() {
        let _ = write!(h, "<li>{}</li>", esc(n.as_str().unwrap_or("")));
    }
    h.push_str("<li>Findings are indicators for an examiner to confirm, not proof. Legitimate apps (MDM, accessibility tools, backup) can match capability-based findings.</li>");
    h.push_str("<li>The full event timeline is produced separately with <code>apex timeline</code>.</li></ul>");
    h.push_str("</main></body></html>\n");
    h
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes() {
        assert_eq!(super::esc("<a href=\"x\">&</a>"), "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;");
    }
}
