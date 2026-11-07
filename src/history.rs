//! Longer-term history from a `device acquire` case (offline):
//! - users and profiles (work profile, secondary user, MIUI "second space"/clones),
//!   and apps installed only inside a profile;
//! - install / uninstall history (who removed what, when) from the package
//!   manager's warning log and the battery history in `bugreport.zip`;
//! - per-app network traffic over weeks (`dumpsys netstats --full --uid`).
//!
//! Best-effort like the rest of `case`: an unknown format yields nothing.

use crate::case::{Case, Event};
use crate::ioc::{IocSet, Kind};
use crate::models::{Finding, Severity};
use fancy_regex::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;

// ---------------------------------------------------------------- users

/// One `pm list users` entry: `UserInfo{10:Work profile:1030} running`.
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub flags: u32,
    pub running: bool,
}

impl User {
    /// What kind of user this is, from `UserInfo` flags.
    pub fn kind(&self) -> &'static str {
        const GUEST: u32 = 0x4;
        const RESTRICTED: u32 = 0x8;
        const MANAGED_PROFILE: u32 = 0x20;
        const PROFILE: u32 = 0x1000;
        if self.id == 0 {
            "main user"
        } else if self.flags & MANAGED_PROFILE != 0 {
            "work profile (managed)"
        } else if self.id == 999 || self.name.to_lowercase().contains("xspace") || self.name.to_lowercase().contains("clone") {
            "app clone space"
        } else if self.flags & GUEST != 0 {
            "guest user"
        } else if self.flags & RESTRICTED != 0 {
            "restricted profile"
        } else if self.flags & PROFILE != 0 {
            "profile"
        } else {
            "secondary user"
        }
    }
}

pub fn parse_users(text: &str) -> Vec<User> {
    text.lines()
        .filter_map(|l| {
            let l = l.trim();
            let inner = l.strip_prefix("UserInfo{")?;
            let (body, rest) = inner.split_once('}')?;
            let (id, tail) = body.split_once(':')?;
            let (name, flags) = tail.rsplit_once(':')?;
            Some(User {
                id: id.parse().ok()?,
                name: name.to_string(),
                flags: u32::from_str_radix(flags, 16).unwrap_or(0),
                running: rest.contains("running"),
            })
        })
        .collect()
}

/// Users, and the third-party apps of each non-primary user
/// (`device/packages_3_user<N>.txt`, written by acquire).
pub fn load_users(root: &Path) -> (Vec<User>, BTreeMap<u32, BTreeSet<String>>) {
    let users = std::fs::read_to_string(root.join("device/users.txt")).map(|t| parse_users(&t)).unwrap_or_default();
    let mut apps = BTreeMap::new();
    for u in users.iter().filter(|u| u.id != 0) {
        if let Ok(t) = std::fs::read_to_string(root.join(format!("device/packages_3_user{}.txt", u.id))) {
            apps.insert(u.id, crate::case::parse_packages(&t).into_iter().map(|p| p.name).collect());
        }
    }
    (users, apps)
}

// ---------------------------------------------------------------- package history

/// One install / uninstall / platform event from the package manager history.
#[derive(Debug, Clone, PartialEq)]
pub struct PkgChange {
    /// Device-local `YYYY-MM-DD HH:MM:SS`.
    pub local: String,
    /// `install`, `uninstall`, `first_boot`, `signature_changed`.
    pub kind: &'static str,
    pub package: String,
    /// Who did it (package of the calling app), for uninstalls.
    pub caller: Option<String>,
    pub user: Option<u32>,
    pub source: &'static str,
    pub raw: String,
}

/// Date of a "Package warning messages" line. The package manager formats it
/// with the device locale *at the time*, so try the common short formats.
fn parse_pm_date(s: &str) -> Option<chrono::NaiveDateTime> {
    use chrono::NaiveDateTime as N;
    let s = s.replace(['\u{202f}', '\u{a0}'], " ");
    for fmt in ["%d/%m/%Y %H:%M", "%m/%d/%y, %I:%M %p", "%m/%d/%y %I:%M %p", "%d.%m.%y %H:%M", "%d.%m.%Y %H:%M", "%Y-%m-%d %H:%M", "%d/%m/%y %H:%M", "%d-%m-%Y %H:%M"] {
        if let Ok(t) = N::parse_from_str(&s, fmt) {
            return Some(t);
        }
    }
    None
}

/// `dumpsys package messages` ("Package warning messages:" block, also inside
/// the bugreport): first boot, uninstalls with their caller, signature changes.
pub fn parse_package_messages(text: &str) -> Vec<PkgChange> {
    let line_re = Regex::new(r"^(\d[\d./-]+,? \d{1,2}:\d{2}(?:[\s\u{202f}\u{a0}]?[AaPp]\.?[Mm]\.?)?): (.+)$").unwrap();
    let unin = Regex::new(r"^Uninstall pkg: (\S+) u(\d+) flags:\d+ from u(\d+)/\d+ of (\S+)").unwrap();
    let mut out = Vec::new();
    for l in text.lines() {
        let Ok(Some(c)) = line_re.captures(l.trim_end()) else { continue };
        let Some(t) = parse_pm_date(&c[1]) else { continue };
        let local = t.format("%Y-%m-%d %H:%M:%S").to_string();
        let msg = c[2].trim().to_string();
        let ch = |kind, package: &str, caller: Option<String>, user| PkgChange {
            local: local.clone(),
            kind,
            package: package.to_string(),
            caller,
            user,
            source: "package manager log",
            raw: msg.clone(),
        };
        if let Ok(Some(u)) = unin.captures(msg.as_str()) {
            // A uid-2000 caller is the adb shell, whatever package name is logged.
            let caller = if &u[3] == "2000" { "adb shell".to_string() } else { u[4].to_string() };
            out.push(ch("uninstall", &u[1], Some(caller), u[2].parse().ok()));
        } else if let Some(fp) = msg.strip_prefix("First boot of ") {
            out.push(ch("first_boot", "", None, None));
            out.last_mut().unwrap().raw = format!("First boot of {fp}");
        } else if let Some(rest) = msg.strip_prefix("System package ") {
            if let Some(pkg) = rest.strip_suffix("; retaining data.").and_then(|r| r.strip_suffix(" signature changed")) {
                out.push(ch("signature_changed", pkg, None, None));
            }
        }
    }
    out.sort_by(|a, b| (&a.local, &a.package, a.kind).cmp(&(&b.local, &b.package, b.kind)));
    out.dedup_by(|a, b| a.local == b.local && a.package == b.package && a.kind == b.kind);
    out
}

/// `+1d04h49m12s480ms` / `0` → milliseconds.
fn rel_ms(s: &str) -> Option<i64> {
    let s = s.trim_start_matches('+');
    if s == "0" {
        return Some(0);
    }
    let mut total = 0i64;
    let mut num = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            num.push(c);
            continue;
        }
        let n: i64 = num.parse().ok()?;
        num.clear();
        total += n * match c {
            'd' => 86_400_000,
            'h' => 3_600_000,
            'm' if chars.peek() == Some(&'s') => {
                chars.next();
                1
            }
            'm' => 60_000,
            's' => 1000,
            _ => return None,
        };
    }
    num.is_empty().then_some(total)
}

/// Battery history (`dumpsys batterystats`, inside the bugreport):
/// `pkginst=` / `pkgunin=` events, timed from the nearest `TIME:` anchor.
/// Battery history spans weeks, far longer than logcat.
pub fn parse_battery_history(text: &str) -> Vec<PkgChange> {
    let anchor = Regex::new(r"^\s*(\+?[\dhdms]+) \(\d+\) TIME: (\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})").unwrap();
    let rel = Regex::new(r"^\s*(\+?[\dhdms]+) \(\d+\) ").unwrap();
    let ev = Regex::new(r#"pkg(inst|unin)=\d+:"([^"]+)""#).unwrap();
    let mut base: Option<(i64, chrono::NaiveDateTime)> = None;
    let mut out = Vec::new();
    for l in text.lines() {
        if let Ok(Some(c)) = anchor.captures(l) {
            base = rel_ms(&c[1]).zip(chrono::NaiveDateTime::parse_from_str(&c[2], "%Y-%m-%d-%H-%M-%S").ok());
            continue;
        }
        if !l.contains("pkginst=") && !l.contains("pkgunin=") {
            continue;
        }
        let (Some((b_ms, b_t)), Ok(Some(r))) = (base, rel.captures(l)) else { continue };
        let Some(ms) = rel_ms(&r[1]) else { continue };
        let t = b_t + chrono::Duration::milliseconds(ms - b_ms);
        for c in ev.captures_iter(l).flatten() {
            out.push(PkgChange {
                local: t.format("%Y-%m-%d %H:%M:%S").to_string(),
                kind: if &c[1] == "inst" { "install" } else { "uninstall" },
                package: c[2].to_string(),
                caller: None,
                user: None,
                source: "battery history",
                raw: l.trim().to_string(),
            });
        }
    }
    // The same event is logged several times within a second.
    out.dedup_by(|a, b| a.package == b.package && a.kind == b.kind && a.local[..16] == b.local[..16]);
    out
}

/// The main text of `device/bugreport.zip` (`main_entry.txt` names it).
pub fn bugreport_text(root: &Path) -> Option<String> {
    let f = std::fs::File::open(root.join("device/bugreport.zip")).ok()?;
    let mut z = zip::ZipArchive::new(f).ok()?;
    let mut name = String::new();
    if let Ok(mut e) = z.by_name("main_entry.txt") {
        e.read_to_string(&mut name).ok()?;
    }
    let name = match name.trim() {
        "" => z.file_names().find(|n| n.starts_with("bugreport-") && n.ends_with(".txt"))?.to_string(),
        n => n.to_string(),
    };
    let mut e = z.by_name(&name).ok()?;
    let mut buf = Vec::new();
    e.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Every package change the case can tell us about.
pub fn package_changes(case: &Case) -> Vec<PkgChange> {
    let br = bugreport_text(&case.root);
    let mut out = match std::fs::read_to_string(case.root.join("device/package_messages.txt")) {
        Ok(t) => parse_package_messages(&t),
        Err(_) => br.as_deref().map(parse_package_messages).unwrap_or_default(),
    };
    if let Some(t) = &br {
        out.extend(parse_battery_history(t));
    }
    out.sort_by(|a, b| a.local.cmp(&b.local));
    out
}

// ---------------------------------------------------------------- network traffic

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Traffic {
    pub rx: u64,
    pub tx: u64,
    /// Sent while the app was not in the foreground.
    pub bg_tx: u64,
    pub bg_rx: u64,
    pub mobile: u64,
    /// (bucket start epoch s, rx, tx)
    pub buckets: BTreeMap<i64, (u64, u64)>,
}

/// `dumpsys netstats --full --uid`, "UID stats" section → uid → traffic.
/// Only tag 0x0 rows (tagged rows are subsets of them).
pub fn parse_netstats(text: &str) -> BTreeMap<i64, Traffic> {
    let ident = Regex::new(r"type=(\d+).*\buid=(-?\d+) set=(\w+)(?: tag=(0x[0-9a-fA-F]+))?").unwrap();
    let bucket = Regex::new(r"^\s+st=(\d+) rb=(\d+) rp=\d+ tb=(\d+)").unwrap();
    let mut out: BTreeMap<i64, Traffic> = BTreeMap::new();
    let mut in_uid = false;
    // (uid, background, mobile) of the current ident, None to skip its buckets.
    let mut cur: Option<(i64, bool, bool)> = None;
    for l in text.lines() {
        if !l.starts_with(' ') && !l.is_empty() {
            in_uid = l.starts_with("UID stats");
            cur = None;
            continue;
        }
        if !in_uid {
            continue;
        }
        if l.trim_start().starts_with("ident=") {
            cur = ident.captures(l).ok().flatten().and_then(|c| {
                let tagged = c.get(4).is_some_and(|t| t.as_str() != "0x0");
                (!tagged).then(|| (c[2].parse().unwrap_or(-1), &c[3] == "DEFAULT", &c[1] == "0"))
            });
        } else if let (Some((uid, bg, mobile)), Ok(Some(b))) = (cur, bucket.captures(l)) {
            let (st, rb, tb): (i64, u64, u64) = (b[1].parse().unwrap_or(0), b[2].parse().unwrap_or(0), b[3].parse().unwrap_or(0));
            let t = out.entry(uid).or_default();
            t.rx += rb;
            t.tx += tb;
            if bg {
                t.bg_rx += rb;
                t.bg_tx += tb;
            }
            if mobile {
                t.mobile += rb + tb;
            }
            let e = t.buckets.entry(st).or_default();
            e.0 += rb;
            e.1 += tb;
        }
    }
    out
}

/// Traffic per third-party package (uid → package via `packages_uid.txt`;
/// profile uids `N*100000 + appId` fold onto the same app).
pub fn traffic_by_package(case: &Case) -> BTreeMap<String, Traffic> {
    let mut out: BTreeMap<String, Traffic> = BTreeMap::new();
    let Ok(t) = std::fs::read_to_string(case.root.join("device/netstats.txt")) else { return out };
    let uids = std::fs::read_to_string(case.root.join("device/packages_uid.txt")).map(|t| crate::artifacts::parse_uid_packages(&t)).unwrap_or_default();
    for (uid, tr) in parse_netstats(&t) {
        let Ok(uid) = u32::try_from(uid) else { continue };
        // A shared uid maps to several packages: attribute it to none rather than guess.
        let Some([pkg]) = uids.get(&(uid % 100_000)).map(Vec::as_slice) else { continue };
        if !case.third_party.contains(pkg) {
            continue;
        }
        let e = out.entry(pkg.clone()).or_default();
        e.rx += tr.rx;
        e.tx += tr.tx;
        e.bg_rx += tr.bg_rx;
        e.bg_tx += tr.bg_tx;
        e.mobile += tr.mobile;
        for (st, (r, x)) in tr.buckets {
            let b = e.buckets.entry(st).or_default();
            b.0 += r;
            b.1 += x;
        }
    }
    out
}

fn mb(b: u64) -> String {
    format!("{:.1} MB", b as f64 / 1_048_576.0)
}

// ---------------------------------------------------------------- findings & events

fn f(id: &str, title: String, desc: String, sev: Severity) -> Finding {
    Finding::new(id, title, desc, sev, "investigation")
}

/// Uploads below this are noise for the timeline and the background-upload check.
const UPLOAD_EVENT_BYTES: u64 = 1_048_576;
// ponytail: fixed threshold; per-app baselines would need several acquisitions (`apex diff`).
const BG_UPLOAD_BYTES: u64 = 20 * 1_048_576;

pub fn findings(case: &Case, iocs: &IocSet) -> Vec<Finding> {
    let mut out = Vec::new();

    // --- Users and profiles.
    for u in case.users.iter().filter(|u| u.id != 0) {
        let apps = case.profile_apps.get(&u.id);
        let managed = u.kind().starts_with("work profile");
        out.push(
            f(
                "CASE_USER_PROFILE",
                format!("Additional user on the phone: {} ({})", u.name, u.kind()),
                format!(
                    "User {} '{}' is a {}{}. Apps and data in it are separate from the main user's and do not show in the main app drawer.{}",
                    u.id,
                    u.name,
                    u.kind(),
                    if u.running { ", currently running" } else { "" },
                    if managed { " A work profile is controlled by its admin app (profile owner), which can see the profile's apps, network traffic and location." } else { "" }
                ),
                if managed { Severity::Medium } else { Severity::Info },
            )
            .meta("user_id", json!(u.id))
            .meta("flags", json!(format!("0x{:x}", u.flags)))
            .meta("third_party_apps", json!(apps)),
        );
        let main = &case.third_party_main;
        for pkg in apps.into_iter().flatten().filter(|p| !main.contains(*p)) {
            out.push(
                f(
                    "CASE_PROFILE_ONLY_APP",
                    format!("App installed only in user {}: {pkg}", u.id),
                    format!("'{pkg}' is installed in '{}' ({}) but not for the main user, so the phone's owner never sees it in their app list. Check why it is there and who set the profile up.", u.name, u.kind()),
                    Severity::Medium,
                )
                .mitre("T1628")
                .meta("package", json!(pkg))
                .meta("user_id", json!(u.id)),
            );
        }
    }

    // --- Install / uninstall history.
    // APEX's own agent (installed and removed by the acquisition) is in the
    // package manager log: in the timeline, not in the findings.
    let changes: Vec<PkgChange> = package_changes(case).into_iter().filter(|c| c.package != crate::agent::PKG).collect();
    let installed: BTreeSet<&str> = case.packages.iter().map(|p| p.name.as_str()).collect();
    let mut removed: BTreeMap<&str, &PkgChange> = BTreeMap::new();
    for c in changes.iter().filter(|c| c.kind == "uninstall") {
        // Static shared libraries (`name_<version>`) come and go with updates.
        let lib = c.package.rsplit_once('_').is_some_and(|(_, v)| v.chars().all(|d| d.is_ascii_digit()));
        if !lib && !installed.contains(c.package.as_str()) {
            removed.insert(c.package.as_str(), c);
        }
    }
    for (pkg, c) in &removed {
        let known = crate::stalkerware_iocs::STALKERWARE_PACKAGES.contains(pkg);
        let ioc = iocs.get(Kind::Package, pkg);
        if known || ioc.is_some() {
            out.push(
                f(
                    "CASE_STALKERWARE_REMOVED",
                    format!("Known stalkerware was installed, then removed: {pkg}"),
                    format!(
                        "'{pkg}' ({}) was uninstalled on {}{}. It is no longer on the phone, but it was: data it collected may already have been sent. Preserve this report; the remaining timeline shows what it could access while installed.",
                        ioc.map(String::as_str).unwrap_or("stalkerware indicator list"),
                        case.iso(&c.local),
                        c.caller.as_ref().map(|w| format!(" by {w}")).unwrap_or_default()
                    ),
                    Severity::High,
                )
                .mitre("T1630")
                .meta("package", json!(pkg))
                .meta("uninstalled", json!(case.iso(&c.local)))
                .meta("caller", json!(c.caller)),
            );
        }
    }
    let by_odd_caller: Vec<&PkgChange> = changes
        .iter()
        .filter(|c| c.kind == "uninstall")
        .filter(|c| {
            c.caller.as_deref().is_some_and(|w| {
                w == "adb shell" || (case.third_party.contains(w) && !crate::adb_checks::KNOWN_STORES.contains(&w))
            })
        })
        .collect();
    for c in &by_odd_caller {
        let who = c.caller.as_deref().unwrap_or_default();
        out.push(
            f(
                "CASE_UNINSTALL_BY_UNUSUAL_CALLER",
                format!("{} uninstalled by {who}", c.package),
                format!(
                    "'{}' was removed on {} by {who}, not through the launcher, settings or a store. {}",
                    c.package,
                    case.iso(&c.local),
                    if who == "adb shell" { "Someone had USB debugging access to the phone at that time." } else { "An app removing other apps is unusual (cleaners do; so does malware covering its tracks)." }
                ),
                Severity::Medium,
            )
            .mitre("T1630")
            .meta("package", json!(c.package))
            .meta("caller", json!(who))
            .meta("time", json!(case.iso(&c.local))),
        );
    }
    if !removed.is_empty() {
        let list: Vec<String> = removed.iter().map(|(p, c)| format!("{p} ({}{})", case.iso(&c.local), c.caller.as_ref().map(|w| format!(", by {w}")).unwrap_or_default())).collect();
        out.push(
            f(
                "CASE_APPS_REMOVED",
                format!("{} app(s) uninstalled and no longer on the phone", removed.len()),
                format!("Removed apps leave no APK but stay in the package manager and battery history: {}.", list.join("; ")),
                Severity::Info,
            )
            .meta("apps", json!(removed.iter().map(|(p, c)| json!({"package": p, "uninstalled": case.iso(&c.local), "caller": c.caller})).collect::<Vec<_>>())),
        );
    }
    if let Some(c) = changes.iter().rev().find(|c| c.kind == "first_boot") {
        out.push(
            f(
                "CASE_FIRST_BOOT",
                format!("Phone set up (or factory reset) on {}", &c.local[..10]),
                format!("The package manager recorded a first boot on {} ({}). Nothing on the phone predates it: earlier compromise left no trace here, and a recent reset can mean evidence was wiped.", case.iso(&c.local), c.raw),
                Severity::Info,
            )
            .meta("time", json!(case.iso(&c.local))),
        );
    }

    // --- Network traffic.
    let traffic = traffic_by_package(case);
    let mut top: Vec<(&String, &Traffic)> = traffic.iter().filter(|(_, t)| t.rx + t.tx > 0).collect();
    top.sort_by_key(|(_, t)| std::cmp::Reverse(t.rx + t.tx));
    if !top.is_empty() {
        let span = traffic.values().flat_map(|t| t.buckets.keys()).fold((i64::MAX, i64::MIN), |(a, b), s| (a.min(*s), b.max(*s)));
        let day = |s: i64| case.local_from_epoch_ms(s * 1000).map(|t| t[..10].to_string()).unwrap_or_default();
        let list: Vec<String> = top.iter().take(10).map(|(p, t)| format!("{p}: ↓{} ↑{}", mb(t.rx), mb(t.tx))).collect();
        out.push(
            f(
                "CASE_NET_USAGE",
                "Network usage per user-installed app".into(),
                format!("Traffic recorded by the system from {} to {} (top 10): {}.", day(span.0), day(span.1), list.join(", ")),
                Severity::Info,
            )
            .meta("apps", json!(top.iter().map(|(p, t)| json!({"package": p, "rx": t.rx, "tx": t.tx, "background_tx": t.bg_tx, "mobile": t.mobile})).collect::<Vec<_>>())),
        );
    }
    for (pkg, t) in &traffic {
        if t.bg_tx >= BG_UPLOAD_BYTES && t.bg_tx > t.bg_rx {
            out.push(
                f(
                    "CASE_BACKGROUND_UPLOAD",
                    format!("Uploads more than it downloads, in the background: {pkg}"),
                    format!("'{pkg}' sent {} while not on screen, more than it received ({}). Monitoring apps exfiltrate this way; backup and sync apps do too.", mb(t.bg_tx), mb(t.bg_rx)),
                    Severity::Medium,
                )
                .mitre("T1646")
                .meta("package", json!(pkg))
                .meta("background_tx", json!(t.bg_tx))
                .meta("background_rx", json!(t.bg_rx)),
            );
        }
    }
    out
}

pub fn events(case: &Case) -> Vec<Event> {
    let mut ev = Vec::new();
    for c in package_changes(case) {
        let message = match c.kind {
            "uninstall" => format!("{} uninstalled{}", c.package, c.caller.as_ref().map(|w| format!(" by {w}")).unwrap_or_default()),
            "install" => format!("{} installed or updated", c.package),
            "first_boot" => c.raw.clone(),
            _ => format!("{} {}", c.package, c.kind.replace('_', " ")),
        };
        ev.push(Event { local: c.local, desc: format!("package:{}", c.kind), source: c.source.into(), package: c.package, message });
    }
    for (pkg, t) in traffic_by_package(case) {
        for (st, (rx, tx)) in &t.buckets {
            if *tx >= UPLOAD_EVENT_BYTES {
                if let Some(local) = case.local_from_epoch_ms(st * 1000) {
                    ev.push(Event {
                        local,
                        desc: "net:upload".into(),
                        source: "netstats".into(),
                        package: pkg.clone(),
                        message: format!("{pkg} sent {} (received {}) in this period", mb(*tx), mb(*rx)),
                    });
                }
            }
        }
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users() {
        let u = parse_users("Users:\n\tUserInfo{0:Propriétaire:c13} running\n\tUserInfo{10:Work: profile:1030} running\n\tUserInfo{999:XSpace:801010}\n");
        assert_eq!(u.len(), 3);
        assert_eq!(u[1].name, "Work: profile");
        assert_eq!(u[1].kind(), "work profile (managed)");
        assert_eq!(u[2].kind(), "app clone space");
        assert!(!u[2].running);
    }

    #[test]
    fn package_messages() {
        let t = "Package warning messages:\n\
18/01/2026 20:07: First boot of Redmi/rosemary_eea/rosemary:13/TP1A:user/release-keys\n\
26/04/2026 15:08: System package com.google.android.federatedcompute signature changed; retaining data.\n\
11/04/2026 10:52: Uninstall pkg: com.block.juggle u0 flags:4 from u10153/2164 of com.miui.home\n\
4/12/26, 9:05\u{202f}PM: Uninstall pkg: com.spy.app u0 flags:0 from u2000/9999 of com.android.shell\n";
        let c = parse_package_messages(t);
        assert_eq!(c.len(), 4);
        assert_eq!(c[0].kind, "first_boot");
        assert_eq!(c[0].local, "2026-01-18 20:07:00");
        let j = c.iter().find(|c| c.package == "com.block.juggle").unwrap();
        assert_eq!((j.local.as_str(), j.caller.as_deref(), j.user), ("2026-04-11 10:52:00", Some("com.miui.home"), Some(0)));
        let s = c.iter().find(|c| c.package == "com.spy.app").unwrap();
        assert_eq!((s.local.as_str(), s.caller.as_deref()), ("2026-04-12 21:05:00", Some("adb shell")));
        assert!(c.iter().any(|c| c.kind == "signature_changed" && c.package == "com.google.android.federatedcompute"));
    }

    #[test]
    fn battery_history() {
        assert_eq!(rel_ms("+1d04h49m12s480ms"), Some(86_400_000 + 4 * 3_600_000 + 49 * 60_000 + 12_480));
        assert_eq!(rel_ms("+296ms"), Some(296));
        let t = "Battery History (97% used):\n\
                    0 (20) TIME: 2026-09-03-21-46-26\n\
       +1h26m16s540ms (38) TIME: 2026-09-03-23-12-42\n\
       +6h26m53s555ms (2) 064 c4800019 pkginst=511507674:\"com.instagram.barcelona\"\n\
       +6h26m53s601ms (2) 064 c4800019 pkginst=511507674:\"com.instagram.barcelona\"\n\
       +6h30m00s000ms (2) 064 c4800019 pkgunin=12:\"com.spy.app\"\n";
        let c = parse_battery_history(t);
        assert_eq!(c.len(), 2);
        // 23:12:42 + (6h26m53.555s - 1h26m16.540s) = 04:13:19.
        assert_eq!((c[0].local.as_str(), c[0].kind), ("2026-09-04 04:13:19", "install"));
        assert_eq!((c[1].package.as_str(), c[1].kind), ("com.spy.app", "uninstall"));
    }

    #[test]
    fn netstats() {
        let t = [
            "Xt stats:",
            "  ident=[{type=1}] uid=-1 set=ALL tag=0x0",
            "      st=1 rb=999 rp=1 tb=999 tp=1 op=0",
            "UID stats:",
            "  Complete history:",
            "  ident=[{type=1, ratType=COMBINED}] uid=10099 set=DEFAULT",
            "    NetworkStatsHistory: bucketDuration=7200",
            "      st=1793966400 rb=100 rp=1 tb=5000 tp=1 op=0",
            "      st=1793973600 rb=10 rp=1 tb=20 tp=1 op=0",
            "  ident=[{type=0, ratType=13}] uid=10099 set=FOREGROUND",
            "      st=1793966400 rb=1 rp=1 tb=2 tp=1 op=0",
            "  ident=[{type=1}] uid=10099 set=DEFAULT tag=0x7",
            "      st=1793966400 rb=77 rp=1 tb=77 tp=1 op=0",
            "InterfaceMapHelper:",
            "  ident=[{type=1}] uid=5 set=DEFAULT",
            "      st=1 rb=1 rp=1 tb=1 tp=1 op=0",
        ]
        .join("\n");
        let n = parse_netstats(&t);
        assert_eq!(n.len(), 1);
        let a = &n[&10099];
        assert_eq!((a.rx, a.tx, a.bg_rx, a.bg_tx, a.mobile), (111, 5022, 110, 5020, 3));
        assert_eq!(a.buckets[&1793966400], (101, 5002));
    }
}
