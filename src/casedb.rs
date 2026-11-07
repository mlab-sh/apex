//! `apex db`: one SQLite file per case with everything APEX knows about it,
//! for SQL queries by an examiner or an agent. Built from the hashed case
//! files (acquisition, import, agent), never from the phone; rebuild it at will.

use crate::case::Case;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE identifiers(section TEXT, key TEXT, value TEXT);
CREATE TABLE accounts(service TEXT, type TEXT, name TEXT, source TEXT);
CREATE TABLE sims(slot INTEGER, carrier TEXT, number TEXT, iccid TEXT, mcc TEXT, mnc TEXT, country TEXT, embedded INTEGER);
CREATE TABLE packages(
  package TEXT PRIMARY KEY, label TEXT, version TEXT, system INTEGER, enabled INTEGER,
  installer TEXT, initiator TEXT, first_install TEXT, last_update TEXT,
  uid INTEGER, target_sdk INTEGER, apk TEXT, cert_sha256 TEXT, cert_sha1 TEXT,
  of_interest TEXT                 -- operator / category when it holds data worth a legal request
);
CREATE TABLE permissions(package TEXT, permission TEXT, granted INTEGER);
CREATE TABLE findings(id TEXT, severity TEXT, title TEXT, description TEXT, category TEXT, metadata TEXT);
CREATE TABLE events(               -- the timeline
  time TEXT,                       -- phone local time, ISO 8601 with UTC offset
  kind TEXT, source TEXT, package TEXT, message TEXT
);
CREATE TABLE usage(time TEXT, time_ms INTEGER, event TEXT, package TEXT, class TEXT);
CREATE TABLE comms(
  time TEXT, time_ms INTEGER, kind TEXT, direction TEXT, peer TEXT, text TEXT,
  extra TEXT, source TEXT, recovered INTEGER
);
CREATE TABLE contacts(name TEXT, kind TEXT, value TEXT, account TEXT, starred INTEGER, last_updated TEXT);
CREATE TABLE media(path TEXT, size INTEGER, mime TEXT, taken TEXT, modified TEXT, owner_package TEXT,
  latitude REAL, longitude REAL, make TEXT, model TEXT, sha256 TEXT, hash_set TEXT, source TEXT);
CREATE TABLE bluetooth(name TEXT, address TEXT, type INTEGER);
CREATE TABLE entities(kind TEXT, value TEXT, count INTEGER, sources TEXT);
CREATE TABLE captures(capture TEXT, label TEXT, package TEXT, seq INTEGER, screen INTEGER, side TEXT, text TEXT, described INTEGER);
CREATE INDEX events_time ON events(time);
CREATE INDEX comms_time ON comms(time_ms);
CREATE INDEX comms_peer ON comms(peer);
CREATE INDEX usage_time ON usage(time_ms);
CREATE VIEW messages AS SELECT * FROM comms WHERE kind NOT IN ('contact','calendar','web','download','location','wallet');
";

fn usage_name(t: i64) -> &'static str {
    match t {
        1 => "app_resumed",
        2 => "app_paused",
        7 => "user_interaction",
        15 => "screen_on",
        16 => "screen_off",
        17 => "keyguard_shown",
        18 => "keyguard_hidden (unlocked)",
        19 => "foreground_service_start",
        20 => "foreground_service_stop",
        26 => "device_shutdown",
        27 => "device_startup",
        _ => "other",
    }
}

pub struct Counts(pub Vec<(&'static str, i64)>);

/// Build `out` from the case (and capture directories). Overwrites `out`.
pub fn build(case: &Case, iocs: &crate::ioc::IocSet, captures: &[PathBuf], out: &Path) -> Result<Counts, String> {
    let _ = std::fs::remove_file(out);
    let c = Connection::open(out).map_err(|e| e.to_string())?;
    let r = (|| -> rusqlite::Result<()> {
        c.execute_batch(SCHEMA)?;
        c.execute_batch("BEGIN")?;
        fill(&c, case, iocs, captures)?;
        c.execute_batch("COMMIT")
    })();
    r.map_err(|e| format!("{}: {e}", out.display()))?;
    let mut counts = Vec::new();
    for t in ["packages", "findings", "events", "usage", "comms", "contacts", "media", "entities", "captures", "accounts"] {
        counts.push((t, c.query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0)).unwrap_or(0)));
    }
    Ok(Counts(counts))
}

fn s(v: &Value) -> Option<String> {
    match v {
        Value::Null => None,
        Value::String(x) => Some(x.clone()),
        x => Some(x.to_string()),
    }
}

fn fill(c: &Connection, case: &Case, iocs: &crate::ioc::IocSet, captures: &[PathBuf]) -> rusqlite::Result<()> {
    let when = |ms: i64| if ms > 0 { case.local_from_epoch_ms(ms).map(|t| case.iso(&t)) } else { None };
    let manifest: Value = std::fs::read_to_string(case.root.join("manifest.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let agent = crate::agent::load(&case.root);

    // meta
    let mut meta: Vec<(String, String)> = vec![
        ("apex_version".into(), env!("CARGO_PKG_VERSION").into()),
        ("built_utc".into(), chrono::Utc::now().to_rfc3339()),
        ("case_dir".into(), case.root.display().to_string()),
        ("operation".into(), manifest["operation"].as_str().unwrap_or("").into()),
        ("manifest_sha256".into(), std::fs::read_to_string(case.root.join("manifest.json.sha256")).unwrap_or_default().split_whitespace().next().unwrap_or("").into()),
        ("session_start_utc".into(), manifest["session"]["started_utc"].as_str().unwrap_or("").into()),
        ("session_end_utc".into(), manifest["session"]["ended_utc"].as_str().unwrap_or("").into()),
        ("agent".into(), if agent.is_some() { "yes".into() } else { "no".into() }),
    ];
    for (k, v) in manifest["case"].as_object().into_iter().flatten() {
        meta.push((format!("case_{k}"), s(v).unwrap_or_default()));
    }
    for (k, v) in &meta {
        c.execute("INSERT OR REPLACE INTO meta VALUES (?1, ?2)", params![k, v])?;
    }

    // identifiers + accounts
    let ids = crate::seizure::identifiers(case);
    for sec in ["device", "telephony", "network"] {
        for (k, v) in ids[sec].as_object().into_iter().flatten() {
            let vals: Vec<String> = match v {
                Value::Array(a) => a.iter().filter_map(s).collect(),
                x => s(x).into_iter().collect(),
            };
            for x in vals {
                c.execute("INSERT INTO identifiers VALUES (?1, ?2, ?3)", params![sec, k, x])?;
            }
        }
    }
    for a in ids["accounts"].as_array().into_iter().flatten() {
        c.execute("INSERT INTO accounts VALUES (?1, ?2, ?3, 'dumpsys account')", params![s(&a["service"]), s(&a["type"]), s(&a["name"])])?;
    }

    let of_interest: std::collections::BTreeMap<String, String> =
        crate::appdata::apps_of_interest(case.third_party.iter()).into_iter().map(|(p, cat, op)| (p, format!("{op} ({cat})"))).collect();

    // agent sections
    if let Some(a) = &agent {
        let sec = &a["sections"];
        for x in sec["accounts"].as_array().into_iter().flatten() {
            c.execute("INSERT INTO accounts VALUES (?1, ?2, ?3, 'agent')", params![crate::seizure::service(x["type"].as_str().unwrap_or("")), s(&x["type"]), s(&x["name"])])?;
        }
        for x in sec["telephony"].as_array().into_iter().flatten().filter(|x| x.get("slot").is_some()) {
            c.execute(
                "INSERT INTO sims VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                params![x["slot"].as_i64(), s(&x["carrier"]), s(&x["number"]), s(&x["iccid"]), s(&x["mcc"]), s(&x["mnc"]), s(&x["country"]), x["embedded"].as_bool().map(|b| b as i64)],
            )?;
        }
        for p in sec["packages"].as_array().into_iter().flatten() {
            let pkg = p["package"].as_str().unwrap_or("");
            if pkg == crate::agent::PKG {
                continue;
            }
            let cert = p["certs"].as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null);
            c.execute(
                "INSERT OR REPLACE INTO packages VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
                params![
                    pkg,
                    s(&p["label"]),
                    s(&p["version_name"]),
                    p["system"].as_bool().map(|b| b as i64),
                    p["enabled"].as_bool().map(|b| b as i64),
                    s(&p["installer"]),
                    s(&p["initiator"]),
                    when(p["first_install_ms"].as_i64().unwrap_or(0)),
                    when(p["last_update_ms"].as_i64().unwrap_or(0)),
                    p["uid"].as_i64(),
                    p["target_sdk"].as_i64(),
                    s(&p["apk"]),
                    s(&cert["sha256"]),
                    s(&cert["sha1"]),
                    of_interest.get(pkg)
                ],
            )?;
            for perm in p["permissions"].as_array().into_iter().flatten() {
                c.execute("INSERT INTO permissions VALUES (?1, ?2, ?3)", params![pkg, s(&perm["name"]), perm["granted"].as_bool().map(|b| b as i64)])?;
            }
        }
        for e in sec["usage"].as_array().into_iter().flatten() {
            let ms = e["time_ms"].as_i64().unwrap_or(0);
            c.execute("INSERT INTO usage VALUES (?1,?2,?3,?4,?5)", params![when(ms), ms, usage_name(e["type"].as_i64().unwrap_or(0)), s(&e["package"]), s(&e["class"])])?;
        }
        for b in sec["bluetooth"].as_array().into_iter().flatten() {
            c.execute("INSERT INTO bluetooth VALUES (?1,?2,?3)", params![s(&b["name"]), s(&b["address"]), b["type"].as_i64()])?;
        }
        for x in sec["contacts"].as_array().into_iter().flatten() {
            let mt = x["mimetype"].as_str().unwrap_or("");
            let kind = mt.rsplit('/').next().unwrap_or(mt).trim_end_matches("_v2");
            if !matches!(kind, "phone" | "email" | "name" | "postal-address" | "organization" | "im" | "nickname" | "website" | "note" | "contact_event" | "relation") && !kind.starts_with("vnd.") {
                continue;
            }
            c.execute(
                "INSERT INTO contacts VALUES (?1,?2,?3,?4,?5,?6)",
                params![s(&x["display_name"]), kind, s(&x["data1"]), x["account_type"].as_str().map(|t| format!("{t} {}", x["account_name"].as_str().unwrap_or(""))), x["starred"].as_i64(), when(x["contact_last_updated_timestamp"].as_i64().unwrap_or(0))],
            )?;
        }
        for m in sec["media"].as_array().into_iter().flatten() {
            let ms = |k: &str| m[k].as_i64().unwrap_or(0);
            // MediaStore dates: datetaken in ms, date_added / date_modified in s.
            let taken = if ms("datetaken") > 0 { ms("datetaken") } else { 0 };
            c.execute(
                "INSERT INTO media VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,NULL,NULL,'agent (MediaStore)')",
                params![s(&m["_data"]), m["_size"].as_i64(), s(&m["mime_type"]), when(taken), when(ms("date_modified") * 1000), s(&m["owner_package_name"]), m["gps_lat"].as_f64(), m["gps_lon"].as_f64(), s(&m["exif_make"]), s(&m["exif_model"])],
            )?;
        }
    }
    // Without the agent: packages from the case's lists.
    if c.query_row("SELECT count(*) FROM packages", [], |r| r.get::<_, i64>(0))? == 0 {
        for p in &case.packages {
            c.execute(
                "INSERT OR REPLACE INTO packages(package, system, installer, apk, of_interest) VALUES (?1,?2,?3,?4,?5)",
                params![p.name, case.system.contains(&p.name) as i64, p.installer, p.path, of_interest.get(&p.name)],
            )?;
        }
    }

    // findings, timeline, comms, media (storage), entities
    for f in case.findings(iocs) {
        c.execute(
            "INSERT INTO findings VALUES (?1,?2,?3,?4,?5,?6)",
            params![f.id, f.severity.value(), f.title, f.description, f.category, serde_json::to_string(&f.metadata).unwrap_or_default()],
        )?;
    }
    for e in case.timeline() {
        c.execute("INSERT INTO events VALUES (?1,?2,?3,?4,?5)", params![case.iso(&e.local), e.desc, e.source, e.package, e.message])?;
    }
    for x in crate::comms::load(case) {
        c.execute(
            "INSERT INTO comms VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![when(x.time_ms), x.time_ms, x.kind, x.direction, x.peer, x.text, x.extra, x.source, x.recovered as i64],
        )?;
    }
    for it in crate::media::inventory(case, &Default::default(), iocs) {
        c.execute(
            "INSERT INTO media VALUES (?1,?2,NULL,?3,NULL,NULL,?4,?5,?6,?7,?8,?9,'storage')",
            params![it.rel, it.size as i64, it.meta.taken, it.meta.lat, it.meta.lon, it.meta.make, it.meta.model, it.sha256, it.alert],
        )?;
    }
    for (kind, vals) in crate::search::extract(&crate::search::sources(case)) {
        for (v, (n, srcs)) in vals {
            c.execute("INSERT INTO entities VALUES (?1,?2,?3,?4)", params![kind, v, n as i64, srcs.join(", ")])?;
        }
    }

    // screen captures
    for dir in captures {
        let Ok(cap) = Connection::open_with_flags(dir.join("capture.db"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY) else { continue };
        let m = |k: &str| cap.query_row("SELECT value FROM meta WHERE key=?1", [k], |r| r.get::<_, String>(0)).unwrap_or_default();
        let (label, pkg) = (m("label"), m("package"));
        let Ok(mut st) = cap.prepare("SELECT seq, screen, side, text, described FROM lines ORDER BY seq") else { continue };
        let rows: Vec<(i64, i64, String, String, i64)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.flatten().collect();
        for (seq, screen, side, text, d) in rows {
            c.execute("INSERT INTO captures VALUES (?1,?2,?3,?4,?5,?6,?7,?8)", params![dir.display().to_string(), label, pkg, seq, screen, side, text, d])?;
        }
    }
    Ok(())
}
