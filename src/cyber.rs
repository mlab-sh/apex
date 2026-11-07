//! Cyber findings, all computed locally from the case files. Text-based checks
//! use the lists in `rules` (built-in, extended by the examiner's rules file).

use crate::case::Case;
use crate::models::{Finding, Severity};
use crate::rules::{self, app_matches, domain_in};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};
use std::io::Read;

fn f(id: &str, title: String, desc: String, sev: Severity) -> Finding {
    Finding::new(id, title, desc, sev, "cyber")
}

fn read(case: &Case, rel: &str) -> String {
    std::fs::read_to_string(case.root.join(rel)).unwrap_or_default()
}

fn sev(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Medium,
    }
}

// ---------------------------------------------------------------- shared facts

struct Facts {
    agent: BTreeMap<String, Value>,
    third: Vec<String>,
}

impl Facts {
    fn new(case: &Case) -> Facts {
        let agent = crate::agent::load(&case.root)
            .map(|v| v["sections"]["packages"].as_array().into_iter().flatten().filter_map(|p| Some((p["package"].as_str()?.to_string(), p.clone()))).collect())
            .unwrap_or_default();
        let mut third: Vec<String> = case.third_party.iter().filter(|p| p.as_str() != crate::agent::PKG).cloned().collect();
        third.sort();
        Facts { agent, third }
    }

    fn granted(&self, case: &Case, pkg: &str) -> HashSet<String> {
        if let Some(p) = self.agent.get(pkg) {
            return p["permissions"].as_array().into_iter().flatten().filter(|x| x["granted"].as_bool() == Some(true)).filter_map(|x| x["name"].as_str()).map(|s| s.trim_start_matches("android.permission.").to_string()).collect();
        }
        read(case, &format!("apps/{pkg}/dumpsys_package.txt"))
            .lines()
            .filter(|l| l.contains("granted=true"))
            .filter_map(|l| l.trim().split(':').next())
            .map(|s| s.trim_start_matches("android.permission.").to_string())
            .collect()
    }

    fn installer(&self, case: &Case, pkg: &str) -> Option<String> {
        self.agent.get(pkg).and_then(|p| p["installer"].as_str().map(String::from)).or_else(|| case.packages.iter().find(|x| x.name == pkg).and_then(|x| x.installer.clone()))
    }

    fn from_store(&self, case: &Case, pkg: &str) -> bool {
        self.installer(case, pkg).is_some_and(|i| app_matches(&rules::r().stores, &i))
    }

    fn hidden(case: &Case, pkg: &str) -> bool {
        case.launchable.as_ref().is_some_and(|l| !l.contains(pkg))
    }

    fn privileged(case: &Case, pkg: &str) -> bool {
        case.accessibility.contains(pkg) || case.admins.contains(pkg) || case.notif_listeners.contains(pkg)
    }

    /// Third-party apps worth a closer look: not from a store, hidden or privileged.
    fn suspicious(&self, case: &Case) -> Vec<String> {
        self.third.iter().filter(|p| !self.from_store(case, p) || Self::hidden(case, p) || Self::privileged(case, p)).cloned().collect()
    }

    fn installed_ms(&self, pkg: &str) -> Option<i64> {
        self.agent.get(pkg).and_then(|p| p["first_install_ms"].as_i64()).filter(|t| *t > 0)
    }
}

/// DEX files of an app's pulled APKs.
fn dex(case: &Case, pkg: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(case.root.join("apps").join(pkg)).into_iter().flatten().flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("apk") {
            continue;
        }
        let Ok(mut z) = std::fs::File::open(&p).map_err(|_| ()).and_then(|f| zip::ZipArchive::new(f).map_err(|_| ())) else { continue };
        let names: Vec<String> = z.file_names().filter(|n| n.starts_with("classes") && n.ends_with(".dex")).map(String::from).collect();
        for n in names {
            let mut b = Vec::new();
            if z.by_name(&n).map(|mut e| e.read_to_end(&mut b)).is_ok() {
                out.push(b);
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------- compromise

/// CA certificates installed by the user (APEX agent, AndroidCAStore).
fn user_ca(case: &Case) -> Vec<Finding> {
    let Some(v) = crate::agent::load(&case.root) else { return Vec::new() };
    v["sections"]["ca_certs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|c| c["user"].as_bool() == Some(true))
        .map(|c| {
            let subj = c["subject"].as_str().unwrap_or("");
            f(
                "CASE_USER_CA_CERT",
                format!("Certificate authority installed by the user: {subj}"),
                format!(
                    "A root certificate added by the user lets whoever holds its key read the phone's encrypted traffic (interception proxy, stalkerware, corporate inspection). Issuer: {}, valid {} to {}, SHA-256 {}.",
                    c["issuer"].as_str().unwrap_or(""),
                    c["not_before"].as_str().unwrap_or(""),
                    c["not_after"].as_str().unwrap_or(""),
                    c["sha256"].as_str().unwrap_or("")
                ),
                Severity::High,
            )
            .meta("certificate", c.clone())
        })
        .collect()
}

/// Accessibility + two of: overlay, SMS, notification access, installing apps.
fn banking_trojan(case: &Case, fx: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in &fx.third {
        if !case.accessibility.contains(p) {
            continue;
        }
        let g = fx.granted(case, p);
        let mut traits = vec!["accessibility service enabled (reads and drives the screen)"];
        if g.contains("SYSTEM_ALERT_WINDOW") {
            traits.push("draws over other apps (fake login screens)");
        }
        if g.contains("READ_SMS") || g.contains("RECEIVE_SMS") {
            traits.push("reads SMS (one-time codes)");
        }
        if case.notif_listeners.contains(p) {
            traits.push("reads notifications");
        }
        if g.contains("REQUEST_INSTALL_PACKAGES") {
            traits.push("installs other apps");
        }
        if traits.len() < 3 {
            continue;
        }
        let store = fx.from_store(case, p);
        out.push(
            f(
                "CASE_BANKING_TROJAN_PROFILE",
                format!("{p}: banking-trojan profile"),
                format!("{p} combines: {}. Banking trojans (Anatsa, Hook, Octo…) use exactly this set to steal credentials and codes{}.", traits.join("; "), if store { "" } else { "; it was not installed from a store" }),
                if store { Severity::Medium } else { Severity::High },
            )
            .meta("package", json!(p))
            .meta("traits", json!(traits)),
        );
    }
    out
}

fn root(case: &Case) -> Vec<Finding> {
    let r = &rules::r().root;
    let mut ev: Vec<String> = Vec::new();
    for p in case.packages.iter().filter(|p| r.packages.contains(&p.name)) {
        ev.push(format!("package {} installed", p.name));
    }
    let ps = read(case, "device/processes.txt");
    for name in &r.processes {
        if ps.lines().any(|l| l.split_whitespace().skip(3).any(|t| t.rsplit('/').next() == Some(name.as_str()))) {
            ev.push(format!("process {name} running"));
        }
    }
    let socks = read(case, "device/net_sockets.txt");
    for port in &r.ports {
        let hex = format!(":{port:04X} ");
        if socks.lines().any(|l| l.contains(&hex) && l.split_whitespace().nth(3) == Some("0A")) {
            ev.push(format!("TCP port {port} listening (instrumentation server)"));
        }
    }
    let su = read(case, "device/su_check.txt");
    // `ls -l` of the usual su paths: a line without an error is an existing file.
    if su.lines().any(|l| l.contains("/su") && !l.contains("No such file") && !l.contains("Permission denied") && !l.contains("not found")) {
        ev.push("su binary present".into());
    }
    let strong = !ev.is_empty();
    let gp = read(case, "device/getprop.txt");
    let prop = |k: &str| gp.lines().find_map(|l| l.trim().strip_prefix(&format!("[{k}]: [")).map(|v| v.trim_end_matches(']').to_string()));
    for (k, bad, what) in [
        ("ro.debuggable", "1", "debuggable build"),
        ("ro.secure", "0", "insecure build (ro.secure=0)"),
        ("ro.boot.verifiedbootstate", "orange", "bootloader unlocked (verified boot orange)"),
        ("ro.boot.flash.locked", "0", "bootloader unlocked"),
        ("ro.boot.selinux", "permissive", "SELinux permissive"),
    ] {
        if prop(k).as_deref() == Some(bad) {
            ev.push(what.to_string());
        }
    }
    if prop("ro.build.tags").is_some_and(|t| t.contains("test-keys")) {
        ev.push("build signed with test keys (custom ROM)".into());
    }
    if ev.is_empty() {
        return Vec::new();
    }
    vec![f(
        "CASE_ROOT_OR_INSTRUMENTATION",
        "Phone rooted, unlocked or instrumented".into(),
        format!("{}. A rooted or instrumented phone can hide apps and alter what any tool reads: weigh the whole extraction accordingly.", ev.join("; ")),
        if strong { Severity::High } else { Severity::Medium },
    )
    .meta("evidence", json!(ev))]
}

/// Signature rules (strings in the apps' code).
fn signatures(case: &Case, fx: &Facts) -> Vec<Finding> {
    let rs = &rules::r().signatures.rule;
    let mut out = Vec::new();
    // Only apps not from a store, hidden or privileged: store apps use the same APIs legitimately.
    for p in &fx.suspicious(case) {
        let dx = dex(case, p);
        if dx.is_empty() {
            continue;
        }
        for r in rs {
            let found: Vec<&String> = r.strings.iter().filter(|s| dx.iter().any(|d| contains(d, s.as_bytes()))).collect();
            let need = match r.condition.as_str() {
                "any" => 1,
                "all" => r.strings.len(),
                n => n.parse().unwrap_or(r.strings.len()),
            };
            if found.len() >= need.max(1) {
                out.push(
                    f("CASE_SIGNATURE_MATCH", format!("{p}: {}", r.name), format!("{} Strings found in its code: {}.", r.description, found.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")), sev(&r.severity))
                        .meta("package", json!(p))
                        .meta("rule", json!(r.name)),
                );
            }
        }
    }
    out
}

/// Native crashes of media / messaging / system processes (bugreport tombstones),
/// plus the examiner's spyware indicators.
fn spyware_traces(case: &Case) -> Vec<Finding> {
    let r = &rules::r().spyware;
    let mut out = Vec::new();
    let mut crashes: Vec<(String, String)> = Vec::new();
    if let Ok(mut z) = std::fs::File::open(case.root.join("device/bugreport.zip")).map_err(|_| ()).and_then(|f| zip::ZipArchive::new(f).map_err(|_| ())) {
        let names: Vec<String> = z.file_names().filter(|n| n.contains("data/tombstones/tombstone_") && !n.ends_with(".pb")).map(String::from).collect();
        for n in names {
            let mut t = String::new();
            if z.by_name(&n).map(|mut e| e.read_to_string(&mut t)).is_err() {
                continue;
            }
            let proc_ = t.lines().find_map(|l| l.split(">>> ").nth(1).and_then(|x| x.split(" <<<").next())).unwrap_or("").to_string();
            let when = t.lines().find_map(|l| l.trim().strip_prefix("Timestamp: ")).unwrap_or("").to_string();
            if r.crash_processes.iter().any(|c| proc_.contains(c.as_str())) {
                crashes.push((when, proc_));
            }
        }
    }
    if !crashes.is_empty() {
        crashes.sort();
        out.push(
            f(
                "CASE_SYSTEM_CRASHES",
                format!("{} native crash(es) of media, messaging or system processes", crashes.len()),
                format!(
                    "Exploits sent by message or media often crash these processes before succeeding. Crashes also happen for ordinary bugs: look for repeats close in time and compare with message reception. {}",
                    crashes.iter().rev().take(15).map(|(w, p)| format!("{w} {p}")).collect::<Vec<_>>().join("; ")
                ),
                Severity::Low,
            )
            .meta("crashes", json!(crashes)),
        );
    }
    let ps = read(case, "device/processes.txt");
    let files = format!("{}\n{}", read(case, "device/sdcard_listing.txt"), read(case, "device/local_tmp.txt"));
    let mut hits: Vec<String> = Vec::new();
    hits.extend(r.processes.iter().filter(|p| ps.contains(p.as_str())).map(|p| format!("process {p}")));
    hits.extend(r.paths.iter().filter(|p| files.contains(p.rsplit('/').next().unwrap_or(p))).map(|p| format!("file {p}")));
    if !r.domains.is_empty() {
        let text: String = crate::search::sources(case).into_iter().map(|(_, t)| t).collect::<Vec<_>>().join("\n");
        hits.extend(r.domains.iter().filter(|d| text.contains(d.as_str())).map(|d| format!("domain {d}")));
    }
    if !hits.is_empty() {
        out.push(f("CASE_SPYWARE_INDICATOR", format!("{} spyware indicator(s) from the rules file", hits.len()), hits.join("; "), Severity::Critical).meta("indicators", json!(hits)));
    }
    out
}

fn persistence(case: &Case, fx: &Facts) -> Vec<Finding> {
    let jobs = read(case, "device/jobscheduler.txt");
    let alarms = read(case, "device/alarm.txt");
    let mut out = Vec::new();
    for p in fx.suspicious(case) {
        let g = fx.granted(case, &p);
        let mut m = Vec::new();
        if g.contains("RECEIVE_BOOT_COMPLETED") {
            m.push("starts at boot");
        }
        if case.admins.contains(&p) {
            m.push("device administrator (blocks uninstall)");
        }
        if case.accessibility.contains(&p) {
            m.push("accessibility service (restarted by the system)");
        }
        if case.notif_listeners.contains(&p) {
            m.push("notification listener (kept bound by the system)");
        }
        if jobs.contains(&p) {
            m.push("scheduled jobs");
        }
        if alarms.contains(&p) {
            m.push("alarms");
        }
        if g.contains("FOREGROUND_SERVICE") {
            m.push("foreground service");
        }
        if m.len() >= 2 {
            out.push(
                f("CASE_PERSISTENCE", format!("{p}: keeps itself running ({} mechanisms)", m.len()), format!("{p}, an app not from a store, hidden or privileged, uses: {}.", m.join(", ")), if m.len() >= 3 { Severity::Medium } else { Severity::Low })
                    .meta("package", json!(p))
                    .meta("mechanisms", json!(m)),
            );
        }
    }
    out
}

// ---------------------------------------------------------------- reconstruction

/// Message → download → install → permissions, for each app not from a store.
fn infection_chains(case: &Case, fx: &Facts, comms: &[crate::comms::Comm]) -> Vec<Finding> {
    let mut out = Vec::new();
    let day = 86_400_000i64;
    for p in fx.third.iter().filter(|p| !fx.from_store(case, p)) {
        let Some(t) = fx.installed_ms(p) else { continue };
        let at = |ms: i64| case.local_from_epoch_ms(ms).map(|s| s.get(..19).unwrap_or(&s).to_string()).unwrap_or_default();
        // (device-local time "YYYY-MM-DD HH:MM:SS", step): sorts as text.
        let mut steps: Vec<(String, String)> = Vec::new();
        for c in comms.iter().filter(|c| c.time_ms > t - 7 * day && c.time_ms <= t) {
            if c.kind == "download" && c.text.to_ascii_lowercase().ends_with(".apk") {
                steps.push((at(c.time_ms), format!("{} downloaded {} from {}", at(c.time_ms), c.text, c.peer)));
            } else if c.kind != "download" && c.kind != "web" && (c.text.contains("http://") || c.text.contains("https://")) {
                steps.push((at(c.time_ms), format!("{} {} {} {} with a link: {}", at(c.time_ms), c.kind, c.direction, c.peer, c.text.chars().take(160).collect::<String>())));
            }
        }
        let a = fx.agent.get(p.as_str()).cloned().unwrap_or(Value::Null);
        let by = a["initiator"].as_str().or(a["installer"].as_str()).unwrap_or("unknown");
        steps.push((at(t), format!("{} {p} installed (by {by})", at(t))));
        let mut seen = HashSet::new();
        for op in case.appops.iter().filter(|o| &o.package == p) {
            let when = op.time.get(..19).unwrap_or(&op.time).to_string();
            if seen.insert(op.op.clone()) && when >= at(t) {
                steps.push((when.clone(), format!("{when} first use of {}", op.op)));
            }
        }
        if case.accessibility.contains(p) {
            steps.push(("~1".into(), "accessibility service enabled at acquisition".into()));
        }
        if case.admins.contains(p) {
            steps.push(("~2".into(), "device administrator at acquisition".into()));
        }
        // Keep chains with a lead: a link or a download just before, or an app with privileges.
        if steps.len() < 2 || !(steps.iter().any(|(_, x)| x.contains(" with a link: ") || x.contains(" downloaded ")) || Facts::privileged(case, p)) {
            continue;
        }
        steps.sort();
        let lines: Vec<String> = steps.into_iter().map(|s| s.1).collect();
        out.push(
            f(
                "CASE_INFECTION_CHAIN",
                format!("{p}: how it got on the phone"),
                format!("{}. Check each step against the timeline before using it in a report.", lines.join(" → ")),
                if Facts::privileged(case, p) { Severity::High } else { Severity::Medium },
            )
            .meta("package", json!(p))
            .meta("steps", json!(lines)),
        );
    }
    out
}

/// Network endpoints hard-coded in suspicious apps: URLs, IP addresses, Telegram
/// bot tokens, Firebase databases.
pub fn endpoints(dexes: &[Vec<u8>]) -> Vec<(String, String)> {
    use regex::bytes::Regex;
    let ignore = &rules::r().endpoints.ignore_domains;
    let url = Regex::new(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})(:\d{2,5})?[^\s\x00-\x1f\x22\x27<>]*").unwrap();
    let ip = Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(:\d{2,5})?\b").unwrap();
    let tg = Regex::new(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b").unwrap();
    let fb = Regex::new(r"[a-z0-9-]+\.(?:firebaseio\.com|firebaseapp\.com|firebasedatabase\.app)").unwrap();
    let mut out: Vec<(String, String)> = Vec::new();
    let mut seen = HashSet::new();
    let mut add = |k: &str, v: String| {
        if seen.insert(v.clone()) {
            out.push((k.to_string(), v));
        }
    };
    for d in dexes {
        for c in url.captures_iter(d) {
            let host = String::from_utf8_lossy(&c[1]).to_ascii_lowercase();
            if !ignore.iter().any(|i| domain_in(&host, i)) {
                add("url", String::from_utf8_lossy(&c[0]).into_owned());
            }
        }
        for c in ip.captures_iter(d) {
            let o: Vec<u32> = (1..=4).filter_map(|i| std::str::from_utf8(&c[i]).ok()?.parse().ok()).collect();
            let public = o.len() == 4 && o.iter().all(|x| *x <= 255) && !matches!(o[0], 0 | 10 | 127 | 255) && !(o[0] == 192 && o[1] == 168) && !(o[0] == 172 && (16..=31).contains(&o[1])) && !(o[0] == 169 && o[1] == 254) && o[0] < 224;
            // Version strings ("1.2.3.4") are common: keep addresses with a port, or not starting with a small number.
            // Without a port, dotted numbers are mostly version strings.
            if public && c.get(5).is_some() {
                add("ip", String::from_utf8_lossy(&c[0]).into_owned());
            }
        }
        for m in tg.find_iter(d) {
            add("telegram_bot_token", String::from_utf8_lossy(m.as_bytes()).into_owned());
        }
        for m in fb.find_iter(d) {
            add("firebase", String::from_utf8_lossy(m.as_bytes()).into_owned());
        }
    }
    out
}

fn app_endpoints(case: &Case, fx: &Facts) -> Vec<Finding> {
    let mut out = Vec::new();
    for p in fx.suspicious(case) {
        let e = endpoints(&dex(case, &p));
        if e.is_empty() {
            continue;
        }
        let strong = e.iter().any(|(k, _)| k == "telegram_bot_token" || k == "ip");
        out.push(
            f(
                "CASE_APP_ENDPOINTS",
                format!("{p}: {} network endpoint(s) in its code", e.len()),
                format!(
                    "Hard-coded in an app not from a store, hidden or privileged: {}. Servers to identify, block or requisition (hosting provider, Telegram, Google for Firebase).",
                    e.iter().take(25).map(|(k, v)| format!("{v} ({k})")).collect::<Vec<_>>().join(", ")
                ),
                if strong { Severity::Medium } else { Severity::Info },
            )
            .meta("package", json!(p))
            .meta("endpoints", json!(e.iter().map(|(k, v)| json!({"kind": k, "value": v})).collect::<Vec<_>>())),
        );
    }
    out
}

/// Background uploads in most of the measured periods: scheduled exfiltration.
fn periodic_uploads(case: &Case, fx: &Facts) -> Vec<Finding> {
    let r = &rules::r().uploads;
    let traffic = crate::history::traffic_by_package(case);
    let mut out = Vec::new();
    for p in &fx.third {
        let Some(t) = traffic.get(p) else { continue };
        let keys: Vec<i64> = t.buckets.keys().copied().collect();
        if keys.len() < 2 {
            continue;
        }
        let step = keys.windows(2).map(|w| w[1] - w[0]).filter(|d| *d > 0).min().unwrap_or(7200);
        let span = ((keys[keys.len() - 1] - keys[0]) / step + 1) as u32;
        let up = t.buckets.values().filter(|(_, tx)| *tx >= r.min_kb * 1024).count() as u32;
        if t.bg_tx == 0 || up < r.min_periods || span == 0 || up * 100 / span < r.min_share_pct {
            continue;
        }
        out.push(
            f(
                "CASE_PERIODIC_UPLOAD",
                format!("{p}: sends data in {}% of the periods", up * 100 / span),
                format!(
                    "{p} sent more than {} KB in {up} of {span} periods of {} h, {:.1} MB in the background in total. Regular uploads, even when the phone is not used, are the pattern of scheduled exfiltration (or of a backup or sync app: check what it is).",
                    r.min_kb,
                    step / 3600,
                    t.bg_tx as f64 / 1e6
                ),
                if fx.from_store(case, p) { Severity::Low } else { Severity::Medium },
            )
            .meta("package", json!(p)),
        );
    }
    out
}

fn anti_forensics(case: &Case, comms: &[crate::comms::Comm]) -> Vec<Finding> {
    let r = rules::r();
    let mut ev: Vec<String> = Vec::new();
    let changes = crate::history::package_changes(case);
    let now = case.capture_local.map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string());
    let days_before = |local: &str| -> Option<i64> {
        let a = chrono::NaiveDateTime::parse_from_str(local.get(..19)?, "%Y-%m-%d %H:%M:%S").ok()?;
        let b = chrono::NaiveDateTime::parse_from_str(now.as_deref()?.get(..19)?, "%Y-%m-%d %H:%M:%S").ok()?;
        Some((b - a).num_days())
    };
    if let Some(c) = changes.iter().rev().find(|c| c.kind == "first_boot") {
        if days_before(&c.local).is_some_and(|d| (0..=30).contains(&d)) {
            ev.push(format!("phone set up or reset on {} (less than 30 days before the acquisition)", c.local));
        }
    }
    let mut un: Vec<&crate::history::PkgChange> = changes.iter().filter(|c| c.kind == "uninstall" && c.package != crate::agent::PKG && days_before(&c.local).is_some_and(|d| (0..=14).contains(&d))).collect();
    un.sort_by(|a, b| a.local.cmp(&b.local));
    for w in un.windows(3) {
        if w[0].local.get(..13) == w[2].local.get(..13) {
            ev.push(format!("{} apps uninstalled within an hour on {}", un.iter().filter(|c| c.local.get(..13) == w[0].local.get(..13)).count(), w[0].local.get(..13).unwrap_or("")));
            break;
        }
    }
    let rec = comms.iter().filter(|c| c.recovered).count();
    if rec > 0 {
        ev.push(format!("{rec} deleted message(s) or call(s) recovered"));
    }
    let global = read(case, "device/settings_global.txt");
    if crate::artifacts::setting(&global, "auto_time").as_deref() == Some("0") {
        ev.push("automatic date and time turned off (the clock can be set by hand)".into());
    }
    for p in case.packages.iter().filter(|p| app_matches(&r.anti_forensics, &p.name)) {
        ev.push(format!("data-wiping app installed: {}", p.name));
    }
    for c in changes.iter().filter(|c| c.kind == "uninstall" && app_matches(&r.anti_forensics, &c.package)) {
        ev.push(format!("data-wiping app {} uninstalled on {}", c.package, c.local));
    }
    if ev.is_empty() {
        return Vec::new();
    }
    vec![f(
        "CASE_ANTI_FORENSICS",
        format!("{} sign(s) of cleaning before the seizure", ev.len()),
        format!("{}. Each can have an innocent reason; together and close to the seizure they suggest an attempt to remove traces.", ev.join("; ")),
        if ev.len() >= 2 { Severity::Medium } else { Severity::Low },
    )
    .meta("signs", json!(ev))]
}

fn vaults(case: &Case) -> Vec<Finding> {
    let r = &rules::r().vault;
    let listing = read(case, "device/sdcard_listing.txt");
    case.packages
        .iter()
        .filter(|p| app_matches(r, &p.name))
        .map(|p| {
            let short = p.name.rsplit('.').next().unwrap_or(&p.name).to_ascii_lowercase();
            let dirs: Vec<&str> = listing.lines().filter(|l| l.ends_with(':') && (l.contains(&p.name) || l.to_ascii_lowercase().contains(&short))).take(10).collect();
            f(
                "CASE_VAULT_APP",
                format!("App to hide content: {}", p.name),
                format!("{} hides photos, files or apps behind a code or a decoy (calculator, gallery). Its content is often in its private storage (lab extraction) or in hidden folders{}.", p.name, if dirs.is_empty() { String::new() } else { format!(": {}", dirs.join(", ")) }),
                Severity::Medium,
            )
            .meta("package", json!(p.name))
        })
        .collect()
}

/// BIP39 recovery phrases (checksum verified) and WIF private keys in any text.
pub fn seeds(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let langs: Vec<bip39::Language> = rules::r()
        .seeds
        .languages
        .iter()
        .filter_map(|l| match l.to_ascii_lowercase().as_str() {
            "english" => Some(bip39::Language::English),
            "french" => Some(bip39::Language::French),
            "spanish" => Some(bip39::Language::Spanish),
            "italian" => Some(bip39::Language::Italian),
            _ => None,
        })
        .collect();
    let words: Vec<String> = text.split(|c: char| !c.is_alphabetic()).filter(|w| !w.is_empty()).map(|w| w.to_lowercase()).collect();
    for lang in langs {
        let list = lang.word_list();
        let mut run: Vec<&str> = Vec::new();
        // A phrase is a run of exactly 12-24 list words between non-list words:
        // inside longer runs of ordinary English, 1 window in 16 passes the checksum.
        let flush = |run: &mut Vec<&str>, out: &mut Vec<(String, String)>| {
            if matches!(run.len(), 12 | 15 | 18 | 21 | 24) {
                let phrase = run.join(" ");
                if bip39::Mnemonic::parse_in_normalized(lang, &phrase).is_ok() && !out.iter().any(|(_, p)| *p == phrase) {
                    out.push(("bip39".into(), phrase));
                }
            }
            run.clear();
        };
        for w in &words {
            if list.binary_search(&w.as_str()).is_ok() || list.contains(&w.as_str()) {
                run.push(w);
            } else {
                flush(&mut run, &mut out);
            }
        }
        flush(&mut run, &mut out);
    }
    let wif = regex::Regex::new(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b").unwrap();
    for m in wif.find_iter(text) {
        if crate::search::base58check_ok(m.as_str()) {
            out.push(("wif_private_key".into(), m.as_str().to_string()));
        }
    }
    out
}

fn seed_findings(case: &Case) -> Vec<Finding> {
    let mut out = Vec::new();
    // What the user wrote or kept: messages, clipboard, notes, files, app data; not system dumps.
    let user = |src: &str| src == "communications" || src.starts_with("storage/") || src.starts_with("comms/") || src.starts_with("backup/");
    for (src, text) in crate::search::sources(case).into_iter().filter(|(s, _)| user(s)) {
        for (kind, v) in seeds(&text) {
            let shown = if kind == "bip39" { format!("{} … ({} words)", v.split(' ').take(2).collect::<Vec<_>>().join(" "), v.split(' ').count()) } else { format!("{}…", &v[..6]) };
            out.push(
                f(
                    "CASE_CRYPTO_SEED",
                    format!("Crypto wallet {} in {src}: {shown}", if kind == "bip39" { "recovery phrase" } else { "private key" }),
                    format!("A {} with a valid checksum gives full control of the wallet's funds: secure it as evidence and consider a seizure of the funds. The full value is in the finding's metadata.", if kind == "bip39" { "BIP39 recovery phrase" } else { "WIF private key" }),
                    Severity::High,
                )
                .meta("kind", json!(kind))
                .meta("source", json!(src))
                .meta("value", json!(v)),
            );
        }
    }
    out
}

/// One message: lure, brand named but foreign domain, URL shortener.
pub fn smishing_reasons(text: &str) -> Vec<String> {
    let r = &rules::r().smishing;
    let low = text.to_lowercase();
    let url = regex::Regex::new(r"(?i)\b(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,24})(?:/[^\s]*)?").unwrap();
    let domains: Vec<String> = url.captures_iter(text).map(|c| c[1].to_ascii_lowercase()).filter(|d| d.contains('.') && !d.chars().all(|c| c.is_ascii_digit() || c == '.')).collect();
    if domains.is_empty() {
        return Vec::new();
    }
    let mut why = Vec::new();
    for b in &r.brands {
        let named = b.keywords.iter().any(|k| low.contains(&k.to_lowercase()));
        let tokens: Vec<String> = b.domains.iter().filter_map(|d| d.split('.').next().map(String::from)).collect();
        for d in &domains {
            let official = b.domains.iter().any(|o| domain_in(d, o));
            let lookalike = tokens.iter().any(|t| t.len() >= 4 && d.contains(t.as_str()));
            if !official && (named || lookalike) {
                why.push(format!("names {} but links to {d}", b.name));
            }
        }
    }
    for d in &domains {
        if r.shorteners.iter().any(|s| domain_in(d, s)) {
            why.push(format!("hides its target behind a URL shortener ({d})"));
        }
    }
    let lures: Vec<&String> = r.keywords.iter().filter(|k| low.contains(&k.to_lowercase())).collect();
    if !why.is_empty() && !lures.is_empty() {
        why.push(format!("lure words: {}", lures.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")));
    }
    why
}

fn smishing(comms: &[crate::comms::Comm]) -> Vec<Finding> {
    comms
        .iter()
        .filter(|c| matches!(c.kind, "sms" | "mms" | "whatsapp" | "telegram" | "signal") && c.direction != "out")
        .filter_map(|c| {
            let why = smishing_reasons(&c.text);
            let brand = why.iter().any(|w| w.starts_with("names "));
            (brand || why.len() >= 2).then(|| {
                f(
                    "CASE_SMISHING",
                    format!("Phishing message from {}", c.peer),
                    format!("{}: \"{}\". The phone may have been infected or the owner defrauded from this link: compare with the downloads and installs that followed.", why.join("; "), c.text.chars().take(200).collect::<String>()),
                    if brand { Severity::High } else { Severity::Medium },
                )
                .meta("peer", json!(c.peer))
                .meta("time_ms", json!(c.time_ms))
            })
        })
        .take(30)
        .collect()
}

/// Every cyber finding of a case.
pub fn findings(case: &Case) -> Vec<Finding> {
    let fx = Facts::new(case);
    let comms = crate::comms::load(case);
    let mut out = Vec::new();
    out.extend(user_ca(case));
    out.extend(banking_trojan(case, &fx));
    out.extend(root(case));
    out.extend(signatures(case, &fx));
    out.extend(spyware_traces(case));
    out.extend(persistence(case, &fx));
    out.extend(infection_chains(case, &fx, &comms));
    out.extend(app_endpoints(case, &fx));
    out.extend(periodic_uploads(case, &fx));
    out.extend(anti_forensics(case, &comms));
    out.extend(vaults(case));
    out.extend(seed_findings(case));
    out.extend(smishing(&comms));
    if let Some(p) = &rules::get().1 {
        for x in out.iter_mut() {
            *x = x.clone().meta("rules_file", json!(p.display().to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smishing_messages() {
        assert!(smishing_reasons("La Poste: votre colis est bloqué, payez les frais de port sur https://laposte-suivi.info/x").iter().any(|w| w.contains("La Poste")));
        assert!(smishing_reasons("Votre colis: https://www.laposte.fr/outils/suivre-vos-envois").is_empty());
        assert!(smishing_reasons("Dernier rappel amende: bit.ly/3xYz").iter().any(|w| w.contains("shortener")));
        assert!(smishing_reasons("rdv 20h").is_empty());
    }

    #[test]
    fn recovery_phrases() {
        let t = "notes perso: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about. fin";
        assert_eq!(seeds(t), vec![("bip39".to_string(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string())]);
        assert!(seeds("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon").is_empty());
    }

    #[test]
    fn endpoints_in_code() {
        let d = b"\x00https://c2.evil-host.xyz:8443/gate.php\x00http://schemas.android.com/apk/res/android\x00185.12.44.7:4444\x001.2.3.4\x00123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0\x00evilapp-1234.firebaseio.com".to_vec();
        let e = endpoints(&[d]);
        let v: Vec<&str> = e.iter().map(|(_, v)| v.as_str()).collect();
        assert!(v.contains(&"https://c2.evil-host.xyz:8443/gate.php"));
        assert!(v.contains(&"185.12.44.7:4444"));
        assert!(!v.iter().any(|x| x.contains("schemas.android.com")) && !v.contains(&"1.2.3.4"));
        assert!(seeds(&format!("{} about", "abandon ".repeat(14))).is_empty(), "a window inside a longer run is not a phrase");
        assert!(e.iter().any(|(k, _)| k == "telegram_bot_token") && e.iter().any(|(k, _)| k == "firebase"));
    }
}
