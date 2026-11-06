//! Investigation over an `apex device acquire` case directory (offline).
//!
//! Parses the collected text artifacts and turns them into findings that a
//! package-by-package scan cannot see:
//! - hidden apps (no launcher icon),
//! - a stalkerware *capability profile* per app (accessibility, notification
//!   listener, device admin, sideload, hidden, sensitive app-ops used),
//! - when sensitive permissions were last *used* (mic, camera, location, SMS…),
//! - STIX2 / bundled indicator matches,
//! and builds a unified timeline (Timesketch-compatible CSV or JSONL).
//!
//! Every parser is best-effort: `dumpsys` formats vary across Android versions
//! and OEMs, so a missing or unrecognised artifact yields no finding, never an
//! error. Timestamps from the device are device-local; `device/clock.txt`
//! (written by acquire) provides the UTC offset and the clock skew.

use crate::ioc::{self, IocSet};
use crate::models::{Finding, Severity};
use fancy_regex::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

/// App-ops worth surfacing: (op, human label).
const SENSITIVE_OPS: &[(&str, &str)] = &[
    ("RECORD_AUDIO", "microphone"),
    ("CAMERA", "camera"),
    ("FINE_LOCATION", "precise location"),
    ("COARSE_LOCATION", "approximate location"),
    ("MONITOR_LOCATION", "location monitoring"),
    ("MONITOR_HIGH_POWER_LOCATION", "location monitoring"),
    ("READ_SMS", "SMS read"),
    ("RECEIVE_SMS", "SMS receive"),
    ("SEND_SMS", "SMS send"),
    ("READ_CALL_LOG", "call log"),
    ("PROCESS_OUTGOING_CALLS", "outgoing calls"),
    ("READ_CONTACTS", "contacts"),
    ("PROJECT_MEDIA", "screen capture"),
    ("READ_CLIPBOARD", "clipboard"),
    ("READ_MEDIA_IMAGES", "photos"),
    ("READ_EXTERNAL_STORAGE", "storage"),
    ("GET_ACCOUNTS", "accounts"),
    ("BODY_SENSORS", "body sensors"),
];

/// One `pm list packages -f -i -u` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Pkg {
    pub name: String,
    pub path: String,
    pub installer: Option<String>,
}


/// One app-op access with its device-local time (`YYYY-MM-DD HH:MM:SS`).
#[derive(Debug, Clone, PartialEq)]
pub struct OpAccess {
    pub package: String,
    pub op: String,
    pub time: String,
}

/// A single timeline row (Timesketch CSV columns).
#[derive(Debug, Clone)]
pub struct Event {
    /// Device-local `YYYY-MM-DD HH:MM:SS[.fff]`.
    pub local: String,
    pub desc: String,
    pub source: String,
    pub package: String,
    pub message: String,
}

// ---------------------------------------------------------------- parsers

pub fn parse_packages(text: &str) -> Vec<Pkg> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("package:") else { continue };
        let (left, installer) = match rest.split_once(" installer=") {
            Some((l, i)) => (l.trim(), Some(i.trim().to_string()).filter(|i| !i.is_empty() && i != "null")),
            None => (rest.trim(), None),
        };
        // `path=name`; the path itself may contain '=' (base64 dir names).
        let (path, name) = left.rsplit_once('=').unwrap_or(("", left));
        if !name.is_empty() {
            out.push(Pkg { name: name.to_string(), path: path.to_string(), installer });
        }
    }
    out
}

/// Packages that own a launcher activity (`cmd package query-activities`).
pub fn parse_launchable(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("packageName="))
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Packages named in a `settings` component list (`pkg/.Cls:pkg2/.Cls2`).
pub fn setting_packages(settings: &str, key: &str) -> HashSet<String> {
    settings
        .lines()
        .filter_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .flat_map(|v| v.split(':'))
        .filter_map(|c| c.split('/').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "null")
        .collect()
}

/// Every `Access:` time per (package, op) in `dumpsys appops`.
///
/// Handles the Android 10+ layout (`Package x:` / `OP (mode):` / `Access: [state] date`)
/// and the colon-style discrete-ops layout (`Package: x` / `Op: OP`).
pub fn parse_appops(text: &str) -> Vec<OpAccess> {
    // `OP (mode):`, OEM ops like `MIUIOP(10008) (allow):`, or `Op: OP`.
    let op_re = Regex::new(r"^(?:Op:\s*([A-Z][A-Z0-9_]+)|([A-Z][A-Z0-9_]*(?:\(\d+\))?)\s*\(\w+\):)\s*$").unwrap();
    let time_re = Regex::new(r"(?:Access|Last access)\S*:?\s*(?:\[[^\]]*\]\s*)?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})").unwrap();
    let mut out = Vec::new();
    let (mut pkg, mut op) = (String::new(), String::new());
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with("Uid ") || line.starts_with("Uid:") {
            pkg.clear();
            op.clear();
        } else if let Some(p) = line.strip_prefix("Package") {
            let p = p.trim_start_matches(':').trim().trim_end_matches(':').trim();
            if !p.is_empty() && p.contains('.') && !p.contains(' ') {
                pkg = p.to_string();
                op.clear();
            }
        } else if let Ok(Some(c)) = op_re.captures(line) {
            op = c.get(1).or(c.get(2)).map(|m| m.as_str().to_string()).unwrap_or_default();
        }
        if pkg.is_empty() || op.is_empty() {
            continue;
        }
        if let Ok(Some(c)) = time_re.captures(line) {
            out.push(OpAccess { package: pkg.clone(), op: op.clone(), time: c[1].to_string() });
        }
    }
    out
}

/// `dumpsys usagestats` events: `time="…" type=X package=Y [class=Z]`.
pub fn parse_usagestats(text: &str) -> Vec<Event> {
    let re = Regex::new(r#"time="(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"\s+type=(\S+)\s+package=(\S+)(?:\s+class=(\S+))?"#).unwrap();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Ok(Some(c)) = re.captures(line) {
            let key = line.trim().to_string();
            if !seen.insert(key) {
                continue; // the same event appears under several interval sections
            }
            let class = c.get(4).map(|m| format!(" ({})", m.as_str())).unwrap_or_default();
            out.push(Event {
                local: c[1].to_string(),
                desc: format!("usage:{}", &c[2]),
                source: "usagestats".into(),
                package: c[3].to_string(),
                message: format!("{} {}{class}", &c[2], &c[3]),
            });
        }
    }
    out
}

/// `firstInstallTime` / `lastUpdateTime` from a `dumpsys package <pkg>`.
pub fn parse_install_times(text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        for (key, desc) in [("firstInstallTime=", "app:installed"), ("lastUpdateTime=", "app:updated")] {
            if let Some(v) = t.strip_prefix(key) {
                let v = v.trim();
                if v.len() >= 19 && !out.iter().any(|(d, x): &(&str, String)| *d == desc && x == v) {
                    out.push((desc, v[..19].to_string()));
                }
            }
        }
    }
    out
}

/// `logcat -v threadtime`: `MM-DD HH:MM:SS.mmm  pid  tid L Tag: msg` (no year).
pub fn parse_logcat(text: &str, year: i32, capture_month: u32) -> Vec<Event> {
    let re = Regex::new(r"^(\d{2})-(\d{2}) (\d{2}:\d{2}:\d{2}\.\d{3})\s+\d+\s+\d+\s+([VDIWEF])\s+(.*)$").unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        let Ok(Some(c)) = re.captures(line) else { continue };
        let month: u32 = c[1].parse().unwrap_or(1);
        // A month after the capture month belongs to the previous year.
        let y = if month > capture_month { year - 1 } else { year };
        out.push(Event {
            local: format!("{y}-{}-{} {}", &c[1], &c[2], &c[3]),
            desc: format!("logcat:{}", &c[4]),
            source: "logcat".into(),
            package: String::new(),
            message: c[5].to_string(),
        });
    }
    out
}

/// `date '+%Y-%m-%dT%H:%M:%S%z'` → (local datetime, "+hh:mm").
pub fn parse_clock(text: &str) -> Option<(chrono::NaiveDateTime, String)> {
    let t = text.trim();
    let dt = chrono::DateTime::parse_from_str(t, "%Y-%m-%dT%H:%M:%S%z").ok()?;
    let off = dt.offset().to_string(); // "+01:00"
    Some((dt.naive_local(), off))
}

// ---------------------------------------------------------------- case

/// Everything loaded from a case directory.
pub struct Case {
    pub root: PathBuf,
    pub packages: Vec<Pkg>,
    /// User-installed packages (`pm list packages -3`). Not "path under /data":
    /// Play-updated system apps (GMS, WebView…) live there too.
    pub third_party: HashSet<String>,
    /// Third-party apps of the main user only (`third_party` adds other users').
    pub third_party_main: HashSet<String>,
    /// `pm list users`, and each non-primary user's third-party apps.
    pub users: Vec<crate::history::User>,
    pub profile_apps: BTreeMap<u32, BTreeSet<String>>,
    /// System packages (`pm list packages -s -u`): shipped with the firmware.
    pub system: HashSet<String>,
    pub launchable: Option<HashSet<String>>,
    pub accessibility: HashSet<String>,
    pub notif_listeners: HashSet<String>,
    pub admins: HashSet<String>,
    pub appops: Vec<OpAccess>,
    /// UTC offset of the device clock at capture, e.g. "+01:00".
    pub utc_offset: Option<String>,
    /// Device time zone (`persist.sys.timezone`), for per-event DST-correct offsets.
    pub tz: Option<chrono_tz::Tz>,
    /// Device clock minus host clock at capture, in seconds.
    pub clock_skew_s: Option<i64>,
    pub capture_local: Option<chrono::NaiveDateTime>,
}

fn read(root: &Path, rel: &str) -> Option<String> {
    std::fs::read(root.join(rel)).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

impl Case {
    /// Whether `dir` looks like an `apex device acquire` output.
    pub fn is_case(dir: &Path) -> bool {
        dir.join("device").join("packages.txt").is_file()
    }

    pub fn load(root: &Path) -> Case {
        let packages = read(root, "device/packages.txt").map(|t| parse_packages(&t)).unwrap_or_default();
        let launchable = read(root, "device/launcher_activities.txt").map(|t| parse_launchable(&t)).filter(|s| !s.is_empty());
        let secure = read(root, "device/settings_secure.txt").unwrap_or_default();
        let admins = read(root, "device/device_policy.txt")
            .map(|t| {
                crate::adb_checks::parse_device_admins(&t)
                    .into_iter()
                    .filter_map(|c| c.split('/').next().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let appops = read(root, "device/appops.txt").map(|t| parse_appops(&t)).unwrap_or_default();

        let clock = read(root, "device/clock.txt").and_then(|t| parse_clock(&t));
        let clock_skew_s = clock.as_ref().and_then(|(local, off)| {
            // Host UTC when the `date` command ran, from the hashed audit log.
            let audit = read(root, "audit.jsonl")?;
            let line = audit.lines().find(|l| l.contains("\"shell: date "))?;
            let v: serde_json::Value = serde_json::from_str(line).ok()?;
            let host = chrono::DateTime::parse_from_rfc3339(v["ts_utc"].as_str()?).ok()?;
            let dev = chrono::DateTime::parse_from_str(&format!("{}{}", local.format("%Y-%m-%dT%H:%M:%S"), off), "%Y-%m-%dT%H:%M:%S%:z").ok()?;
            Some((dev - host).num_seconds())
        });

        let tz = read(root, "device/getprop.txt").and_then(|t| {
            t.lines()
                .find_map(|l| l.trim().strip_prefix("[persist.sys.timezone]: ["))
                .and_then(|v| v.trim_end_matches(']').parse::<chrono_tz::Tz>().ok())
        });

        let third_party_main: HashSet<String> = match read(root, "device/packages_3.txt") {
            Some(t) => parse_packages(&t).into_iter().map(|p| p.name).collect(),
            // Older cases: acquire pulled exactly the third-party apps into apps/.
            None => std::fs::read_dir(root.join("apps"))
                .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect())
                .unwrap_or_default(),
        };

        let system: HashSet<String> = match read(root, "device/packages_system.txt") {
            Some(t) => parse_packages(&t).into_iter().map(|p| p.name).collect(),
            // Older cases: anything not living under /data shipped with the firmware.
            None => packages.iter().filter(|p| !p.path.is_empty() && !p.path.starts_with("/data/")).map(|p| p.name.clone()).collect(),
        };

        let (users, profile_apps) = crate::history::load_users(root);
        let mut third_party = third_party_main.clone();
        third_party.extend(profile_apps.values().flatten().cloned());

        Case {
            root: root.to_path_buf(),
            tz,
            third_party,
            third_party_main,
            users,
            profile_apps,
            system,
            packages,
            launchable,
            accessibility: setting_packages(&secure, "enabled_accessibility_services"),
            notif_listeners: setting_packages(&secure, "enabled_notification_listeners"),
            admins,
            appops,
            utc_offset: clock.as_ref().map(|c| c.1.clone()),
            clock_skew_s,
            capture_local: clock.map(|c| c.0),
        }
    }

    pub fn package_names(&self) -> Vec<String> {
        self.packages.iter().map(|p| p.name.clone()).collect()
    }

    /// Installed by hand: through a package-installer UI, by another user app,
    /// or with no installer at all (adb). Not sideloaded: app stores, and system /
    /// OEM components installing preloads (e.g. `android` during setup).
    pub fn sideloaded(&self, p: &Pkg) -> bool {
        match p.installer.as_deref() {
            Some(i) if crate::adb_checks::KNOWN_STORES.contains(&i) => false,
            Some(i) if i.ends_with("packageinstaller") => true,
            Some(i) => !(i == "android" || self.system.contains(i)),
            // No installer: adb, or a preload shipped in the userdata image.
            None => !is_preload_path(&p.path, &p.name),
        }
    }

    /// Epoch milliseconds → device-local `YYYY-MM-DD HH:MM:SS.fff`.
    pub fn local_from_epoch_ms(&self, ms: i64) -> Option<String> {
        let utc = chrono::DateTime::from_timestamp_millis(ms)?;
        let local = match (self.tz, &self.utc_offset) {
            (Some(tz), _) => utc.with_timezone(&tz).naive_local(),
            (None, Some(o)) => utc.with_timezone(&chrono::FixedOffset::from_str_offset(o)?).naive_local(),
            (None, None) => utc.naive_utc(),
        };
        Some(local.format("%Y-%m-%d %H:%M:%S%.3f").to_string())
    }

    /// Investigation findings for the whole case.
    pub fn findings(&self, iocs: &IocSet) -> Vec<Finding> {
        let mut out = Vec::new();

        // Stalkerware by exact package name, across *all* packages (incl. system / uninstalled-with-data).
        if let Some(f) = crate::adb_checks::stalkerware_finding(&self.package_names()) {
            out.push(f);
        }

        // Last access per (package, sensitive op).
        let mut used: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
        for a in &self.appops {
            if let Some((_, label)) = SENSITIVE_OPS.iter().find(|(op, _)| *op == a.op) {
                let e = used.entry(a.package.as_str()).or_default().entry(label).or_insert(a.time.as_str());
                if a.time.as_str() > *e {
                    *e = a.time.as_str();
                }
            }
        }

        for p in self.packages.iter().filter(|p| self.third_party.contains(&p.name)) {
            let hidden = self.launchable.as_ref().is_some_and(|l| !l.contains(&p.name));
            let side = self.sideloaded(p);
            let ops = used.get(p.name.as_str());

            // Capability profile: each signal is a piece of the stalkerware toolkit.
            let mut signals: Vec<&str> = Vec::new();
            let mut score = 0;
            for (on, pts, label) in [
                (self.accessibility.contains(&p.name), 3, "accessibility service enabled"),
                (self.admins.contains(&p.name), 3, "active device admin"),
                (self.notif_listeners.contains(&p.name), 2, "notification listener enabled"),
                (hidden, 2, "no launcher icon (hidden)"),
                (side, 1, "sideloaded (package installer, another app or adb)"),
                (ops.is_some(), 1, "used sensitive permissions"),
            ] {
                if on {
                    score += pts;
                    signals.push(label);
                }
            }

            if score >= 4 {
                let sev = if score >= 6 { Severity::High } else { Severity::Medium };
                out.push(
                    Finding::new(
                        "CASE_STALKERWARE_PROFILE",
                        format!("Stalkerware-like capability profile: {}", p.name),
                        format!(
                            "'{}' combines {} (score {score}). Stalkerware needs exactly this toolkit; renaming the package does not hide it. Legitimate apps (MDM, accessibility tools, password managers) can match too: confirm with the user before acting, and do not remove it abruptly in an abusive context.",
                            p.name,
                            signals.join(", ")
                        ),
                        sev,
                        "investigation",
                    )
                    .mitre("T1418")
                    .meta("package", json!(p.name))
                    .meta("score", json!(score))
                    .meta("signals", json!(signals))
                    .meta("installer", json!(p.installer)),
                );
            } else if hidden {
                out.push(
                    Finding::new(
                        "CASE_HIDDEN_APP",
                        format!("App without a launcher icon: {}", p.name),
                        format!("'{}' is user-installed but has no launcher activity, so it does not appear in the app drawer. Common for keyboards, plugins and widgets; also how monitoring apps hide.", p.name),
                        Severity::Low,
                        "investigation",
                    )
                    .meta("package", json!(p.name)),
                );
            }

            if let Some(ops) = ops {
                // Per-event offset (DST-aware), not the capture-time one.
                let ops: BTreeMap<&str, String> = ops.iter().map(|(l, t)| (*l, self.iso(t))).collect();
                let list: Vec<String> = ops.iter().map(|(l, t)| format!("{l} (last {t})")).collect();
                let sev = if hidden || (side && score >= 3) { Severity::Medium } else { Severity::Info };
                out.push(
                    Finding::new(
                        "CASE_SENSITIVE_USE",
                        format!("Sensitive permissions used: {}", p.name),
                        format!("'{}' actually used: {}.", p.name, list.join(", ")),
                        sev,
                        "investigation",
                    )
                    .meta("package", json!(p.name))
                    .meta("last_access", json!(ops)),
                );
            }
        }

        if let Some(skew) = self.clock_skew_s.filter(|s| s.abs() > 60) {
            out.push(
                Finding::new(
                    "CASE_CLOCK_SKEW",
                    "Device clock differs from the examiner's clock",
                    format!("The device clock was {skew}s off the host's UTC clock at capture. Correct device timestamps by this amount when correlating with external logs."),
                    Severity::Info,
                    "investigation",
                )
                .meta("skew_seconds", json!(skew)),
            );
        }

        let (p1, net_hits) = crate::artifacts::findings(self, iocs);
        out.extend(p1);
        out.extend(crate::history::findings(self, iocs));
        out.extend(crate::seizure::wipe_finding(self));
        out.extend(self.comms_media_findings());
        let mut hits = iocs.scan_dir(&self.root, &self.package_names());
        hits.extend(net_hits);
        out.extend(ioc_findings(&hits));
        out
    }

    fn comms_media_findings(&self) -> Vec<Finding> {
        let mut out = Vec::new();
        let items = crate::comms::load(self);
        if !items.is_empty() {
            let counts = crate::comms::counts(&items);
            let list: Vec<String> = counts.iter().map(|(k, (n, _))| format!("{n} {k}")).collect();
            out.push(
                Finding::new(
                    "CASE_COMMUNICATIONS",
                    format!("{} communication record(s) collected under mandate", items.len()),
                    format!("{}. Export them with `apex comms`.", list.join(", ")),
                    Severity::Info,
                    "investigation",
                )
                .meta("counts", json!(counts.iter().map(|(k, (n, r))| (k.clone(), json!({"total": n, "recovered": r}))).collect::<serde_json::Map<_, _>>())),
            );
            let rec: Vec<&crate::comms::Comm> = items.iter().filter(|c| c.recovered).collect();
            if !rec.is_empty() {
                let by: BTreeMap<&str, usize> = rec.iter().fold(BTreeMap::new(), |mut m, c| {
                    *m.entry(c.kind).or_default() += 1;
                    m
                });
                out.push(
                    Finding::new(
                        "CASE_DELETED_COMMS_RECOVERED",
                        format!("{} deleted communication record(s) recovered", rec.len()),
                        format!(
                            "Rows deleted from the app databases were recovered from the write-ahead log and free pages ({}). Deletion shortly before a seizure can matter; check their dates in the timeline.",
                            by.iter().map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(", ")
                        ),
                        Severity::Medium,
                        "investigation",
                    )
                    .meta("recovered", json!(by)),
                );
            }
        }
        let files = crate::media::storage_files(self);
        if !files.is_empty() {
            let metas = crate::par_map(&files, |p| crate::media::file_meta(p));
            let located = metas.iter().filter(|m| m.lat.is_some()).count();
            out.push(
                Finding::new(
                    "CASE_MEDIA",
                    format!("{} media / storage file(s), {located} with a location", files.len()),
                    "Shared storage was collected. `apex media` exports the inventory (hashes, EXIF), a KML / GeoJSON map of located photos and videos, and matches hash sets.".to_string(),
                    Severity::Info,
                    "investigation",
                )
                .meta("files", json!(files.len()))
                .meta("located", json!(located)),
            );
        }
        out
    }

    /// Unified, chronologically sorted timeline.
    pub fn timeline(&self) -> Vec<Event> {
        let mut ev: Vec<Event> = Vec::new();

        // Install / update times from each acquired app's dumpsys.
        if let Ok(rd) = std::fs::read_dir(self.root.join("apps")) {
            for e in rd.flatten() {
                let pkg = e.file_name().to_string_lossy().into_owned();
                if let Some(t) = read(&e.path(), "dumpsys_package.txt") {
                    for (desc, when) in parse_install_times(&t) {
                        ev.push(Event { local: when, desc: desc.into(), source: "dumpsys package".into(), package: pkg.clone(), message: format!("{desc} {pkg}") });
                    }
                }
            }
        }
        for a in &self.appops {
            ev.push(Event {
                local: a.time.clone(),
                desc: format!("appop:{}", a.op),
                source: "appops".into(),
                package: a.package.clone(),
                message: format!("{} accessed {}", a.package, a.op),
            });
        }
        if let Some(t) = read(&self.root, "device/usagestats.txt") {
            ev.extend(parse_usagestats(&t));
        }
        if let Some(t) = read(&self.root, "device/logcat.txt") {
            use chrono::Datelike;
            let now = self.capture_local.unwrap_or_else(|| chrono::Local::now().naive_local());
            ev.extend(parse_logcat(&t, now.year(), now.month()));
        }
        ev.extend(crate::artifacts::events(self));
        ev.extend(crate::history::events(self));
        ev.extend(crate::comms::events(self));
        ev.extend(crate::media::events(self));
        ev.sort_by(|a, b| a.local.cmp(&b.local).then(a.message.cmp(&b.message)));
        // appops lists one access under several states/attribution tags.
        ev.dedup_by(|a, b| a.local == b.local && a.desc == b.desc && a.package == b.package && a.message == b.message);
        ev
    }

    /// ISO-8601 with the offset in force *at that moment* in the device's time
    /// zone (DST-aware). Falls back to the capture-time offset, then to none.
    pub fn iso(&self, local: &str) -> String {
        use chrono::{Offset, TimeZone};
        let t = local.replacen(' ', "T", 1);
        let naive = chrono::NaiveDateTime::parse_from_str(&t, "%Y-%m-%dT%H:%M:%S%.f").ok();
        if let (Some(tz), Some(n)) = (self.tz, naive) {
            // Ambiguous (DST fall-back hour): take the earlier; a skipped hour has no offset.
            if let Some(dt) = tz.from_local_datetime(&n).earliest() {
                return format!("{t}{}", dt.offset().fix());
            }
        }
        match &self.utc_offset {
            Some(o) => format!("{t}{o}"),
            None => t,
        }
    }
}

/// One critical finding per matched indicator value.
pub fn ioc_findings(hits: &[ioc::Hit]) -> Vec<Finding> {
    ioc::group(hits)
        .into_iter()
        .map(|((kind, value), (malware, sources))| {
            let sources: Vec<String> = sources.into_iter().collect::<BTreeSet<_>>().into_iter().collect();
            let seen = sources.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            let (id, title, desc) = match malware.strip_prefix("hash set: ") {
                Some(set) => ("HASH_SET_MATCH", format!("File matches alert hash set {set}: {}", sources.first().cloned().unwrap_or_default()), format!("{} {value} is listed in the alert hash set {set}. File(s): {seen}.", kind.label())),
                None => ("IOC_MATCH", format!("Indicator of compromise: {malware}"), format!("{} '{value}' matches a known indicator of {malware}. Seen in: {seen}.", kind.label())),
            };
            Finding::new(id, title, desc, Severity::Critical, "ioc")
            .meta("kind", json!(kind.label()))
            .meta("value", json!(value))
            .meta("malware", json!(malware))
            .meta("sources", json!(sources))
        })
        .collect()
}

/// Write the timeline as CSV (Timesketch columns) or JSONL (by extension).
pub fn write_timeline(case: &Case, events: &[Event], out: &Path) -> Result<(), String> {
    let jsonl = out.extension().is_some_and(|e| e == "jsonl");
    let mut s = String::new();
    if !jsonl {
        s.push_str("datetime,timestamp_desc,source,package,message\n");
    }
    let esc = |v: &str| format!("\"{}\"", v.replace('"', "\"\""));
    for e in events {
        let dt = case.iso(&e.local);
        if jsonl {
            s.push_str(&json!({"datetime": dt, "timestamp_desc": e.desc, "source": e.source, "package": e.package, "message": e.message}).to_string());
        } else {
            s.push_str(&[esc(&dt), esc(&e.desc), esc(&e.source), esc(&e.package), esc(&e.message)].join(","));
        }
        s.push('\n');
    }
    std::fs::write(out, s).map_err(|e| format!("cannot write {}: {e}", out.display()))
}

/// Count events per source, for the CLI summary.
pub fn per_source(events: &[Event]) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for e in events {
        *m.entry(e.source.clone()).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packages_with_base64_paths_and_installer() {
        let t = "package:/data/app/~~ab==/com.foo-x1==/base.apk=com.foo  installer=com.android.vending\n\
                 package:/system/app/Bar/Bar.apk=com.bar  installer=null\n";
        let p = parse_packages(t);
        assert_eq!(p[0], Pkg { name: "com.foo".into(), path: "/data/app/~~ab==/com.foo-x1==/base.apk".into(), installer: Some("com.android.vending".into()) });
        assert_eq!(p[1].installer, None);
    }

    #[test]
    fn preload_vs_runtime_install_paths() {
        assert!(is_preload_path("/data/app/Podcasts/base.apk", "com.google.android.apps.podcasts"));
        assert!(!is_preload_path("/data/app/~~STaw==/com.x-n_Rh==/base.apk", "com.x"));
        assert!(!is_preload_path("/data/app/com.x-1/base.apk", "com.x"));
        assert!(!is_preload_path("/system/app/X/X.apk", "com.x"));
    }

    #[test]
    fn launcher_and_settings() {
        let l = parse_launchable("  ActivityInfo:\n    packageName=com.a\n    packageName=com.b extra\n");
        assert!(l.contains("com.a") && l.contains("com.b"));
        let s = "enabled_accessibility_services=com.spy/.Svc:com.tb/com.tb.A\nother=1\n";
        let a = setting_packages(s, "enabled_accessibility_services");
        assert_eq!(a, HashSet::from(["com.spy".to_string(), "com.tb".to_string()]));
    }

    #[test]
    fn appops_modern_layout() {
        let t = "  Uid 10234:\n    state=cch\n    Package com.spy:\n      RECORD_AUDIO (allow):\n        null=[\n          Access: [fg-s] 2026-11-01 22:14:03.120 (-4d1h)\n        ]\n      CAMERA (allow):\n        Access: [top-s] 2026-10-30 08:00:00.000 (-6d)\n  Uid 10300:\n    COARSE_LOCATION: mode=ignore\n    Access: [fg] 2026-01-01 00:00:00.000\n";
        let a = parse_appops(t);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0], OpAccess { package: "com.spy".into(), op: "RECORD_AUDIO".into(), time: "2026-11-01 22:14:03".into() });
        assert_eq!(a[1].op, "CAMERA");
    }

    #[test]
    fn appops_miui_layout_keeps_ops_apart() {
        // Real Android 13 / MIUI output (note the missing space after `[pers-s]`).
        let t = "    Package com.android.dynsystem:\n      MANAGE_EXTERNAL_STORAGE (default): \n        null=[\n          Reject: [pers-s]2026-05-04 20:34:38.893 (-185d)\n        ]\n      BLUETOOTH_CONNECT (allow): \n        null=[\n          Access: [pers-s] 2026-01-18 21:10:27.729 (-291d)\n        ]\n      MIUIOP(10008) (allow): \n        null=[\n          Access: [pers-s]2026-11-06 14:19:47.887 (-14m)\n        ]\n";
        let a = parse_appops(t);
        let ops: Vec<(&str, &str)> = a.iter().map(|x| (x.op.as_str(), x.time.as_str())).collect();
        assert_eq!(ops, vec![("BLUETOOTH_CONNECT", "2026-01-18 21:10:27"), ("MIUIOP(10008)", "2026-11-06 14:19:47")]);
    }

    #[test]
    fn usagestats_dedup_and_logcat_year() {
        let u = "  time=\"2026-11-05 10:00:00\" type=ACTIVITY_RESUMED package=com.a class=com.a.Main\n  time=\"2026-11-05 10:00:00\" type=ACTIVITY_RESUMED package=com.a class=com.a.Main\n";
        assert_eq!(parse_usagestats(u).len(), 1);
        let l = "12-31 23:59:59.000  100  101 I Tag: old\n11-05 10:00:00.000  100  101 W Tag: new\n";
        let e = parse_logcat(l, 2026, 11);
        assert_eq!(e[0].local, "2025-12-31 23:59:59.000");
        assert_eq!(e[1].local, "2026-11-05 10:00:00.000");
    }

    #[test]
    fn install_times_and_clock() {
        let d = "    firstInstallTime=2026-01-02 03:04:05\n    lastUpdateTime=2026-02-03 04:05:06\n    firstInstallTime=2026-01-02 03:04:05\n";
        assert_eq!(parse_install_times(d), vec![("app:installed", "2026-01-02 03:04:05".to_string()), ("app:updated", "2026-02-03 04:05:06".to_string())]);
        let (_, off) = parse_clock("2026-11-06T14:00:00+0100\n").unwrap();
        assert_eq!(off, "+01:00");
    }

    #[test]
    fn iso_uses_dst_offset_of_the_event_not_of_the_capture() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = Case::load(dir.path());
        c.utc_offset = Some("+01:00".into()); // captured in winter
        c.tz = Some(chrono_tz::Europe::Paris);
        assert_eq!(c.iso("2026-08-04 22:24:09"), "2026-08-04T22:24:09+02:00");
        assert_eq!(c.iso("2026-11-06 14:40:21.050"), "2026-11-06T14:40:21.050+01:00");
        c.tz = None;
        assert_eq!(c.iso("2026-08-04 22:24:09"), "2026-08-04T22:24:09+01:00");
    }

    #[test]
    fn capability_profile_flags_hidden_accessibility_app() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("device");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("packages.txt"), "package:/data/app/x/base.apk=com.spy\npackage:/data/app/y/base.apk=com.ok  installer=com.android.vending\n").unwrap();
        std::fs::write(d.join("launcher_activities.txt"), "packageName=com.ok\n").unwrap();
        // com.gms: Play-updated system app under /data, not third-party → never flagged.
        std::fs::write(d.join("packages_3.txt"), "package:com.spy\npackage:com.ok\n").unwrap();
        std::fs::write(d.join("settings_secure.txt"), "enabled_accessibility_services=com.spy/.S\nenabled_notification_listeners=com.spy/.N\n").unwrap();
        let case = Case::load(dir.path());
        let f = case.findings(&IocSet::default());
        let p = f.iter().find(|f| f.id == "CASE_STALKERWARE_PROFILE").expect("profile finding");
        assert_eq!(p.severity, Severity::High); // 3 + 2 + 2 + 1 = 8
        assert!(!f.iter().any(|f| f.title.contains("com.ok")));
    }
}

/// A preload shipped in the OEM's userdata image lives in a plain directory
/// (`/data/app/Podcasts/`). Anything installed at runtime gets a generated one:
/// `/data/app/~~<hash>==/<pkg>-<hash>==/` (Android 11+) or `/data/app/<pkg>-<n>/`.
pub fn is_preload_path(path: &str, pkg: &str) -> bool {
    match path.strip_prefix("/data/app/").and_then(|r| r.split('/').next()) {
        Some(dir) => !(dir.starts_with("~~") || dir.starts_with(&format!("{pkg}-"))),
        None => false,
    }
}

/// "+01:00" → FixedOffset.
trait FromStrOffset: Sized {
    fn from_str_offset(s: &str) -> Option<Self>;
}

impl FromStrOffset for chrono::FixedOffset {
    fn from_str_offset(s: &str) -> Option<Self> {
        let sign = if s.starts_with('-') { -1 } else { 1 };
        let (h, m) = s.trim_start_matches(['+', '-']).split_once(':')?;
        chrono::FixedOffset::east_opt(sign * (h.parse::<i32>().ok()? * 3600 + m.parse::<i32>().ok()? * 60))
    }
}
