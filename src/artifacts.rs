//! P1 investigation artifacts of a `device acquire` case: network sockets,
//! processes, staging dirs, shared storage, roles, keyboards, VPN / DNS,
//! Wi-Fi and Bluetooth, uninstalled-with-data and system-impersonating apps,
//! plus extra timeline sources (camera service log, notifications, files).
//!
//! Same contract as `case`: every parser is best-effort and a missing or
//! unrecognised artifact yields nothing, never an error.

use crate::case::{Case, Event};
use crate::ioc::{Hit, IocSet, Kind};
use crate::models::{Finding, Severity};
use fancy_regex::Regex;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

/// Roles whose holder sees or controls sensitive data / flows.
const SENSITIVE_ROLES: &[(&str, &str)] = &[
    ("android.app.role.SMS", "default SMS app"),
    ("android.app.role.DIALER", "default phone app"),
    ("android.app.role.CALL_SCREENING", "call screening"),
    ("android.app.role.CALL_REDIRECTION", "call redirection"),
    ("android.app.role.ASSISTANT", "assistant"),
    ("android.app.role.BROWSER", "default browser"),
    ("android.app.role.HOME", "home screen (launcher)"),
    ("android.app.role.DEVICE_POLICY_MANAGEMENT", "device policy management"),
];

/// Package prefixes reserved for the platform / OEMs.
const SYSTEM_PREFIXES: &[&str] = &[
    "android.", "com.android.", "com.google.android.", "com.samsung.", "com.sec.", "com.miui.",
    "com.xiaomi.", "com.qualcomm.", "com.qti.", "com.mediatek.", "com.huawei.", "com.oppo.",
    "com.coloros.", "com.oneplus.", "com.motorola.", "com.lge.", "com.sonymobile.",
];

/// Bluetooth device names typical of item trackers.
const TRACKER_NAMES: &[&str] = &["airtag", "tile", "smarttag", "chipolo", "tracker", "find my", "pebblebee", "nut"];

/// World-writable staging locations exploits and droppers run from.
const STAGING: &[&str] = &["/data/local/tmp", "/sdcard", "/storage/emulated", "/mnt/sdcard"];

// ---------------------------------------------------------------- parsers

/// `pm list packages -U`: `package:x uid:10123` → uid → packages.
pub fn parse_uid_packages(text: &str) -> HashMap<u32, Vec<String>> {
    let mut m: HashMap<u32, Vec<String>> = HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("package:") else { continue };
        let mut it = rest.split_whitespace();
        let name = it.next().unwrap_or("");
        let uid = it
            .find_map(|t| t.strip_prefix("uid:"))
            .and_then(|u| u.split(',').next())
            .and_then(|u| u.parse().ok());
        if let (false, Some(uid)) = (name.is_empty(), uid) {
            m.entry(uid).or_default().push(name.to_string());
        }
    }
    m
}

/// One socket from `/proc/net/{tcp,tcp6,udp,udp6}`.
#[derive(Debug, Clone, PartialEq)]
pub struct Sock {
    pub proto: &'static str,
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: &'static str,
    pub uid: u32,
}

/// Kernel hex address → IP. IPv4 is one little-endian u32; IPv6 is four of
/// them. IPv4-mapped IPv6 is folded back to IPv4.
fn hex_ip(h: &str) -> Option<String> {
    let word = |s: &str| u32::from_str_radix(s, 16).ok().map(|v| v.to_le_bytes());
    match h.len() {
        8 => Some(Ipv4Addr::from(word(h)?).to_string()),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(&h[i * 8..i * 8 + 8])?);
            }
            let v6 = Ipv6Addr::from(b);
            Some(v6.to_ipv4_mapped().map(|v4| v4.to_string()).unwrap_or_else(|| v6.to_string()))
        }
        _ => None,
    }
}

fn tcp_state(s: &str) -> &'static str {
    match s {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Concatenated `/proc/net/*` tables. The header line of each table tells TCP
/// (no `drops` column) from UDP.
pub fn parse_proc_net(text: &str) -> Vec<Sock> {
    let mut out = Vec::new();
    let mut udp = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("sl ") {
            udp = t.contains("drops");
            continue;
        }
        let f: Vec<&str> = t.split_whitespace().collect();
        if f.len() < 8 || !f[0].ends_with(':') {
            continue;
        }
        let (Some((la, lp)), Some((ra, rp))) = (f[1].split_once(':'), f[2].split_once(':')) else { continue };
        let (Some(local_ip), Some(remote_ip)) = (hex_ip(la), hex_ip(ra)) else { continue };
        let state = tcp_state(f[3]);
        out.push(Sock {
            proto: if udp { "udp" } else { "tcp" },
            local_ip,
            local_port: u16::from_str_radix(lp, 16).unwrap_or(0),
            remote_ip,
            remote_port: u16::from_str_radix(rp, 16).unwrap_or(0),
            // UDP has no connection state; 07 just means "unconnected".
            state: if udp { if state == "CLOSE" { "UNCONN" } else { state } } else { state },
            uid: f[7].parse().unwrap_or(u32::MAX),
        });
    }
    out
}

fn is_unspecified_or_loopback(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().map(|a| a.is_unspecified() || a.is_loopback()).unwrap_or(true)
}

/// `ps -A -o USER,PID,PPID,NAME,ARGS` → (user, pid, name, args).
pub fn parse_ps(text: &str) -> Vec<(String, String, String, String)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let (user, pid, _ppid, name) = (it.next()?, it.next()?, it.next()?, it.next()?);
            Some((user.into(), pid.into(), name.into(), it.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

/// `ls -l /proc/[0-9]*/exe` → (pid, executable path). Only processes of the
/// shell user are readable without root, which is exactly where adb-launched
/// implants run. Shows the real binary even when argv[0] is disguised.
pub fn parse_proc_exe(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| {
            let (left, target) = l.split_once(" -> ")?;
            let pid = left.rsplit("/proc/").next()?.strip_suffix("/exe")?;
            Some((pid.to_string(), target.trim().to_string()))
        })
        .collect()
}

/// A file from an `ls -la` / `ls -laR` listing.
#[derive(Debug, Clone, PartialEq)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    /// Device-local `YYYY-MM-DD HH:MM`.
    pub mtime: String,
}

/// `ls -la[R]` output (toybox long format). Directories and `.`/`..` are skipped.
pub fn parse_ls(text: &str, base: &str) -> Vec<FileEntry> {
    let mut dir = base.trim_end_matches('/').to_string();
    let mut out = Vec::new();
    for line in text.lines() {
        if let Some(d) = line.strip_suffix(':').filter(|d| d.starts_with('/')) {
            dir = d.trim_end_matches('/').to_string();
            continue;
        }
        if !line.starts_with('-') {
            continue; // dirs, links, "total N"
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let name = f[7..].join(" ");
        out.push(FileEntry {
            path: format!("{dir}/{name}"),
            size: f[4].parse().unwrap_or(0),
            mtime: format!("{} {}", f[5], f[6]),
        });
    }
    out
}

/// `dumpsys role` → role name → holders.
pub fn parse_roles(text: &str) -> BTreeMap<String, Vec<String>> {
    let mut m = BTreeMap::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if let Some(n) = t.strip_prefix("name=") {
            cur = Some(n.to_string());
        } else if let (Some(h), Some(n)) = (t.strip_prefix("holders="), cur.as_ref()) {
            m.insert(n.clone(), h.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect());
        }
    }
    m
}

/// `key=value` lookup in a `settings list` dump.
pub fn setting(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "null")
}

/// `cmd wifi list-networks` → (SSID, security), deduplicated.
pub fn parse_wifi_networks(text: &str) -> Vec<(String, String)> {
    let mut seen = BTreeSet::new();
    for line in text.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[0].parse::<u32>().is_err() {
            continue;
        }
        let sec = f[f.len() - 1].trim_end_matches('^').to_string();
        seen.insert((f[1..f.len() - 1].join(" "), sec));
    }
    // One row per SSID: keep the weakest security seen (open beats psk).
    let mut by_ssid: BTreeMap<String, String> = BTreeMap::new();
    for (ssid, sec) in seen {
        by_ssid.entry(ssid).and_modify(|s| if sec == "open" { *s = sec.clone() }).or_insert(sec);
    }
    by_ssid.into_iter().collect()
}

/// Bonded devices from `dumpsys bluetooth_manager` → (address, name).
pub fn parse_bt_bonded(text: &str) -> Vec<(String, String)> {
    let mac = Regex::new(r"^([0-9A-Fa-fX]{2}(?::[0-9A-Fa-fX]{2}){5})\s*(.*)$").unwrap();
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("Bonded devices") {
            inside = true;
            continue;
        }
        if !inside {
            continue;
        }
        match mac.captures(t) {
            Ok(Some(c)) => {
                // Name follows the last `]` of the "[ DUAL ][ 0x…]" tags, if any.
                let rest = &c[2];
                let name = rest.rsplit(']').next().unwrap_or(rest).trim().to_string();
                out.push((c[1].to_string(), name));
            }
            _ if t.is_empty() => {}
            _ => inside = false,
        }
    }
    out
}

/// `media.camera` service log lines: `MM-DD HH:MM:SS : EVENT …`.
pub fn parse_camera_log(text: &str) -> Vec<(String, String, String)> {
    let re = Regex::new(r"^\s*(\d{2}-\d{2} \d{2}:\d{2}:\d{2}) : (.+)$").unwrap();
    let pkg = Regex::new(r"package (\S+?)[\s,)]").unwrap();
    text.lines()
        .filter_map(|l| {
            let c = re.captures(l).ok()??;
            let msg = c[2].trim().to_string();
            let p = pkg.captures(format!("{msg} ").as_str()).ok().flatten().map(|m| m[1].to_string()).unwrap_or_default();
            Some((c[1].to_string(), p, msg))
        })
        .collect()
}

/// Active notifications (`dumpsys notification`): (package, creation epoch ms).
pub fn parse_notifications(text: &str) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let mut pkg: Option<String> = None;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("NotificationRecord(") {
            pkg = t.split("pkg=").nth(1).and_then(|r| r.split_whitespace().next()).map(str::to_string);
        } else if let Some(ms) = t.strip_prefix("mCreationTimeMs=") {
            // take() only here: the record's other lines must not consume the package.
            if let (Some(p), Ok(ms)) = (pkg.take(), ms.trim().parse::<i64>()) {
                if ms > 0 {
                    out.push((p, ms));
                }
            }
        }
    }
    out
}

/// Whether `dumpsys connectivity` shows a live network (a `NetworkAgentInfo`,
/// not a `NetworkRequest` that merely accepts VPN) carrying the VPN transport.
pub fn vpn_active(text: &str) -> bool {
    text.lines().filter(|l| l.contains("NetworkAgentInfo") && !l.contains("NOT_VPN")).any(|l| {
        l.split("Transports: ")
            .nth(1)
            .and_then(|r| r.split_whitespace().next())
            .is_some_and(|tr| tr.split('|').any(|x| x == "VPN"))
    })
}

// ---------------------------------------------------------------- findings

fn read(case: &Case, rel: &str) -> Option<String> {
    std::fs::read(case.root.join(rel)).ok().map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn f(id: &str, title: String, desc: String, sev: Severity) -> Finding {
    Finding::new(id, title, desc, sev, "investigation")
}

/// P1 findings, plus IOC hits on live connection endpoints.
pub fn findings(case: &Case, iocs: &IocSet) -> (Vec<Finding>, Vec<Hit>) {
    let mut out = Vec::new();
    let mut hits = Vec::new();
    let third = |p: &str| case.third_party.contains(p);
    let pkg_of = |name: &str| case.packages.iter().find(|p| p.name == name);
    let side = |name: &str| pkg_of(name).is_some_and(|p| case.sideloaded(p));
    let secure = read(case, "device/settings_secure.txt").unwrap_or_default();
    let global = read(case, "device/settings_global.txt").unwrap_or_default();

    // --- System-namespace impersonation: a sideloaded app posing as platform/OEM.
    for p in case.packages.iter().filter(|p| third(&p.name) && case.sideloaded(p)) {
        if SYSTEM_PREFIXES.iter().any(|pre| p.name.starts_with(pre)) {
            out.push(
                f(
                    "CASE_SYSTEM_IMPERSONATION",
                    format!("Sideloaded app in a system namespace: {}", p.name),
                    format!("'{}' uses a package name reserved for the platform or the phone maker, but was installed by {} rather than shipped with the system or a store. Malware names itself like this to look harmless in app lists.", p.name, p.installer.as_deref().unwrap_or("adb / unknown")),
                    Severity::High,
                )
                .mitre("T1036")
                .meta("package", json!(p.name))
                .meta("installer", json!(p.installer)),
            );
        }
    }

    // --- Uninstalled but data kept (`pm uninstall -k`), excluding system apps removed for the user.
    if let Some(installed) = read(case, "device/packages_uid.txt").map(|t| parse_uid_packages(&t)) {
        let installed: BTreeSet<&str> = installed.values().flatten().map(|s| s.as_str()).collect();
        let gone: Vec<&str> = case
            .packages
            .iter()
            .map(|p| p.name.as_str())
            .filter(|n| !installed.contains(n) && !case.system.contains(*n))
            .collect();
        if !gone.is_empty() {
            out.push(
                f(
                    "CASE_UNINSTALLED_DATA_KEPT",
                    format!("{} app(s) uninstalled with their data kept", gone.len()),
                    format!("These apps are no longer installed but Android still holds their data: {}. This is what `pm uninstall -k` leaves behind, for example when an app was removed shortly before the examination.", gone.join(", ")),
                    Severity::Low,
                )
                .meta("packages", json!(gone)),
            );
        }
    }

    // --- Roles held by third-party apps.
    if let Some(roles) = read(case, "device/role.txt").map(|t| parse_roles(&t)) {
        for (role, label) in SENSITIVE_ROLES {
            for h in roles.get(*role).into_iter().flatten().filter(|h| third(h)) {
                let sev = if side(h) { Severity::Medium } else { Severity::Low };
                out.push(
                    f(
                        "CASE_ROLE_HOLDER",
                        format!("Third-party app is the {label}: {h}"),
                        format!("'{h}' holds {role}. Whoever holds this role sees or controls the matching data flow (messages, calls, browsing, home screen…). Check the user chose it."),
                        sev,
                    )
                    .meta("package", json!(h))
                    .meta("role", json!(role)),
                );
            }
        }
    }

    // --- Third-party keyboards: they see everything typed.
    let enabled_ime = crate::case::setting_packages(&secure, "enabled_input_methods");
    let default_ime = setting(&secure, "default_input_method").and_then(|v| v.split('/').next().map(str::to_string));
    for ime in enabled_ime.iter().filter(|p| third(p)) {
        let is_default = default_ime.as_deref() == Some(ime.as_str());
        let sev = if side(ime) { Severity::High } else if is_default { Severity::Medium } else { Severity::Low };
        out.push(
            f(
                "CASE_THIRD_PARTY_KEYBOARD",
                format!("Third-party keyboard enabled: {ime}"),
                format!("'{ime}' is an enabled input method{}. A keyboard receives every character typed, passwords included.", if is_default { " and the current default" } else { "" }),
                sev,
            )
            .mitre("T1417")
            .meta("package", json!(ime))
            .meta("default", json!(is_default)),
        );
    }

    // --- VPN / DNS: who can see or redirect all traffic.
    if let Some(vpn) = setting(&secure, "always_on_vpn_app") {
        let lockdown = setting(&secure, "always_on_vpn_lockdown").as_deref() == Some("1");
        let sev = if third(&vpn) && side(&vpn) { Severity::High } else { Severity::Low };
        out.push(
            f(
                "CASE_ALWAYS_ON_VPN",
                format!("Always-on VPN: {vpn}"),
                format!("All traffic is routed through the VPN app '{vpn}'{}. The VPN operator can see and alter unencrypted traffic and every DNS lookup.", if lockdown { " with lockdown (no traffic allowed outside it)" } else { "" }),
                sev,
            )
            .meta("package", json!(vpn))
            .meta("lockdown", json!(lockdown)),
        );
    } else if read(case, "device/connectivity.txt").is_some_and(|t| vpn_active(&t)) {
        out.push(f(
            "CASE_VPN_ACTIVE",
            "A VPN was active at acquisition".into(),
            "`dumpsys connectivity` shows a network with the VPN transport. Identify the VPN app and check the user set it up.".into(),
            Severity::Low,
        ));
    }
    if setting(&global, "private_dns_mode").as_deref() == Some("hostname") {
        let host = setting(&global, "private_dns_specifier").unwrap_or_default();
        out.push(
            f(
                "CASE_PRIVATE_DNS",
                format!("Custom Private DNS resolver: {host}"),
                format!("Every DNS lookup goes to '{host}' over DNS-over-TLS. Its operator sees which services the phone contacts. Check the user configured it."),
                Severity::Low,
            )
            .meta("hostname", json!(host)),
        );
    }

    // --- Network sockets, per app; IOC match on remote endpoints.
    if let Some(net) = read(case, "device/net_sockets.txt") {
        let uids = read(case, "device/packages_uid.txt").map(|t| parse_uid_packages(&t)).unwrap_or_default();
        let owner = |uid: u32| uids.get(&uid).map(|v| v.join("|")).unwrap_or_else(|| format!("uid {uid}"));
        let mut remote: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for s in parse_proc_net(&net) {
            let who = owner(s.uid);
            if !is_unspecified_or_loopback(&s.remote_ip) {
                remote.entry(who.clone()).or_default().insert(format!("{}:{} {}/{}", s.remote_ip, s.remote_port, s.proto, s.state));
                if let Some(m) = iocs.get(Kind::Ip, &s.remote_ip) {
                    hits.push(Hit { kind: Kind::Ip, value: s.remote_ip.clone(), malware: m.clone(), source: format!("device/net_sockets.txt ({who})") });
                }
            }
            // A user app accepting connections from the network.
            let listening = s.state == "LISTEN" || (s.proto == "udp" && s.state == "UNCONN");
            let apps = uids.get(&s.uid).cloned().unwrap_or_default();
            if listening && s.local_ip.parse::<std::net::IpAddr>().is_ok_and(|a| !a.is_loopback()) && apps.iter().any(|p| third(p)) {
                out.push(
                    f(
                        "CASE_APP_LISTENING",
                        format!("App listens on the network: {who} ({}/{})", s.proto, s.local_port),
                        format!("'{who}' has a {} socket open on {}:{}, reachable from other devices on the network. Uncommon for user apps; remote-access tools do this.", s.proto, s.local_ip, s.local_port),
                        Severity::Medium,
                    )
                    .meta("package", json!(who))
                    .meta("port", json!(s.local_port)),
                );
            }
        }
        if !remote.is_empty() {
            let n: usize = remote.values().map(|v| v.len()).sum();
            out.push(
                f(
                    "CASE_NET_CONNECTIONS",
                    format!("{n} network connection(s) at acquisition"),
                    format!("Open sockets with a remote endpoint, by app: {}.", remote.iter().map(|(k, v)| format!("{k} ({})", v.len())).collect::<Vec<_>>().join(", ")),
                    Severity::Info,
                )
                .meta("connections", json!(remote)),
            );
        }
    }

    // --- Processes running from world-writable staging locations, or from a
    // deleted binary. The real executable (/proc/PID/exe) wins over argv, which
    // an implant can disguise.
    let ps = read(case, "device/processes.txt").map(|t| parse_ps(&t)).unwrap_or_default();
    let mut exe: BTreeMap<String, String> = read(case, "device/proc_exe.txt").map(|t| parse_proc_exe(&t).into_iter().collect()).unwrap_or_default();
    for (_, pid, name, args) in &ps {
        let argv0 = args.split_whitespace().next().unwrap_or(name);
        exe.entry(pid.clone()).or_insert_with(|| argv0.to_string());
    }
    for (pid, path) in &exe {
        let deleted = path.ends_with(" (deleted)");
        if !(deleted || STAGING.iter().any(|s| path.starts_with(s))) {
            continue;
        }
        let (user, args) = ps.iter().find(|p| &p.1 == pid).map(|p| (p.0.clone(), p.3.clone())).unwrap_or_default();
        let why = if deleted { "from a binary deleted after launch (a classic way to leave no file behind)" } else { "from a world-writable staging location, where exploits and droppers put their binaries" };
        out.push(
            f(
                "CASE_STAGING_PROCESS",
                format!("Process running from {}: {path}", if deleted { "a deleted file" } else { "a staging directory" }),
                format!("PID {pid} ({}) runs {path}{} {why}. Legitimate software almost never does this.", if user.is_empty() { "?" } else { &user }, if args.is_empty() || args.starts_with(path.as_str()) { String::new() } else { format!(" (shown in ps as '{args}')") }),
                Severity::High,
            )
            .meta("pid", json!(pid))
            .meta("user", json!(user))
            .meta("exe", json!(path))
            .meta("args", json!(args)),
        );
    }

    // --- Leftovers in /data/local/tmp (the shell user's scratch dir).
    if let Some(ls) = read(case, "device/local_tmp.txt") {
        let files: Vec<FileEntry> = parse_ls(&ls, "/data/local/tmp").into_iter().filter(|e| !e.path.ends_with("/apex_screen.png")).collect();
        if !files.is_empty() {
            let list: Vec<String> = files.iter().map(|e| format!("{} ({} B, {})", e.path, e.size, e.mtime)).collect();
            out.push(
                f(
                    "CASE_LOCAL_TMP_FILES",
                    format!("{} file(s) in /data/local/tmp", files.len()),
                    format!("/data/local/tmp is where adb-pushed tools and exploits are staged. Found: {}.", list.join(", ")),
                    Severity::Medium,
                )
                .meta("files", json!(list)),
            );
        }
    }

    // --- APKs on shared storage: traces of manual sideloading.
    if let Some(ls) = read(case, "device/sdcard_listing.txt") {
        let apks: Vec<String> = parse_ls(&ls, "/storage/emulated/0")
            .into_iter()
            .filter(|e| e.path.to_ascii_lowercase().ends_with(".apk") || e.path.to_ascii_lowercase().ends_with(".xapk"))
            .map(|e| format!("{} ({} B, {})", e.path, e.size, e.mtime))
            .collect();
        if !apks.is_empty() {
            out.push(
                f(
                    "CASE_APK_ON_STORAGE",
                    format!("{} APK file(s) on shared storage", apks.len()),
                    format!("Installable packages were downloaded or copied to the phone: {}. Compare their dates with app install times in the timeline.", apks.join(", ")),
                    Severity::Low,
                )
                .meta("files", json!(apks)),
            );
        }
    }

    // --- Saved Wi-Fi networks and Bluetooth pairings: places and devices.
    if let Some(w) = read(case, "device/wifi_networks.txt") {
        let nets = parse_wifi_networks(&w);
        if !nets.is_empty() {
            let open: Vec<&str> = nets.iter().filter(|(_, s)| s == "open").map(|(n, _)| n.as_str()).collect();
            out.push(
                f(
                    "CASE_WIFI_SAVED",
                    format!("{} saved Wi-Fi network(s)", nets.len()),
                    format!("Saved networks: {}. They show where the phone has been{}.", nets.iter().map(|(n, s)| format!("{n} ({s})")).collect::<Vec<_>>().join(", "), if open.is_empty() { String::new() } else { format!("; {} open network(s) auto-join without encryption", open.len()) }),
                    if open.is_empty() { Severity::Info } else { Severity::Low },
                )
                .meta("networks", json!(nets)),
            );
        }
    }
    if let Some(bt) = read(case, "device/bluetooth.txt") {
        let bonded = parse_bt_bonded(&bt);
        for (addr, name) in &bonded {
            let low = name.to_ascii_lowercase();
            if TRACKER_NAMES.iter().any(|t| low.split(|c: char| !c.is_ascii_alphanumeric() && c != ' ').any(|w| w.contains(t))) {
                out.push(
                    f(
                        "CASE_BT_TRACKER",
                        format!("Paired with a Bluetooth tracker: {name}"),
                        format!("The phone is paired with '{name}' ({addr}), which looks like an item tracker. Check who owns it."),
                        Severity::Medium,
                    )
                    .meta("address", json!(addr))
                    .meta("name", json!(name)),
                );
            }
        }
        if !bonded.is_empty() {
            out.push(
                f(
                    "CASE_BT_BONDED",
                    format!("{} paired Bluetooth device(s)", bonded.len()),
                    format!("Paired devices: {}.", bonded.iter().map(|(a, n)| format!("{n} ({a})")).collect::<Vec<_>>().join(", ")),
                    Severity::Info,
                )
                .meta("devices", json!(bonded)),
            );
        }
    }

    (out, hits)
}

/// Extra timeline sources.
pub fn events(case: &Case) -> Vec<Event> {
    use chrono::Datelike;
    let mut ev = Vec::new();
    let now = case.capture_local.unwrap_or_else(|| chrono::Local::now().naive_local());

    if let Some(t) = read(case, "device/camera.txt") {
        for (when, pkg, msg) in parse_camera_log(&t) {
            let month: u32 = when[..2].parse().unwrap_or(1);
            let y = if month > now.month() { now.year() - 1 } else { now.year() };
            ev.push(Event { local: format!("{y}-{when}"), desc: "camera:event".into(), source: "media.camera".into(), package: pkg, message: msg });
        }
    }
    if let Some(t) = read(case, "device/notification.txt") {
        for (pkg, ms) in parse_notifications(&t) {
            if let Some(local) = case.local_from_epoch_ms(ms) {
                ev.push(Event { local, desc: "notification:posted".into(), source: "notification".into(), message: format!("notification from {pkg}"), package: pkg });
            }
        }
    }
    for (rel, base) in [("device/sdcard_listing.txt", "/storage/emulated/0"), ("device/local_tmp.txt", "/data/local/tmp")] {
        if let Some(t) = read(case, rel) {
            for e in parse_ls(&t, base) {
                ev.push(Event { local: format!("{}:00", e.mtime), desc: "file:modified".into(), source: "file listing".into(), package: String::new(), message: format!("{} ({} B)", e.path, e.size) });
            }
        }
    }
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_net_real_lines() {
        // Real lines from the test phone (tcp, tcp6 IPv4-mapped, udp).
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 901FA8C0:93E4 0474D9AC:01BB 08 00000000:00000082 00:00000000 00000000 10173        0 198630 1 0000000000000000 21 4 28 10 -1\n\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   7: 0000000000000000FFFF0000901FA8C0:B258 0000000000000000FFFF0000BC477D4A:146C 01 00000000:00000000 00:00000000 00000000 10159        0 693913 1 0000000000000000 23 4 29 10 -1\n\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
  595: 901FA8C0:0044 011FA8C0:0043 01 00000000:00000000 00:00000000 00000000  1073        0 49304 2 0000000000000000 0\n";
        let s = parse_proc_net(t);
        assert_eq!(s.len(), 3);
        assert_eq!((s[0].local_ip.as_str(), s[0].remote_ip.as_str(), s[0].remote_port, s[0].state, s[0].uid), ("192.168.31.144", "172.217.116.4", 443, "CLOSE_WAIT", 10173));
        assert_eq!((s[1].remote_ip.as_str(), s[1].remote_port, s[1].state), ("74.125.71.188", 5228, "ESTABLISHED"));
        assert_eq!((s[2].proto, s[2].remote_ip.as_str(), s[2].remote_port), ("udp", "192.168.31.1", 67));
    }

    #[test]
    fn uid_packages_and_ps() {
        let u = parse_uid_packages("package:com.a uid:10148\npackage:com.b uid:1000\npackage:com.c uid:1000\n");
        assert_eq!(u[&1000], vec!["com.b", "com.c"]);
        let p = parse_ps("USER PID PPID NAME ARGS\nshell 4242 1 /data/local/tmp/x /data/local/tmp/x -d\nroot 1 0 init init second_stage\n");
        assert_eq!(p[0], ("shell".into(), "4242".into(), "/data/local/tmp/x".into(), "/data/local/tmp/x -d".into()));
        // Real line from the test phone: argv shows "sleep", exe shows the implant.
        let e = parse_proc_exe("lrwxrwxrwx 1 shell shell 0 2026-11-06 16:21 /proc/2518/exe -> /data/local/tmp/apex_test/sleep\n");
        assert_eq!(e, vec![("2518".to_string(), "/data/local/tmp/apex_test/sleep".to_string())]);
    }

    #[test]
    fn ls_recursive_with_spaces() {
        let t = "/storage/emulated/0/Download:\ntotal 12755\ndrwxrwx--- 2 root everybody     3488 2026-04-12 21:36 DuckDuckGo\n-rw-rw---- 1 root everybody 12713646 2026-04-11 11:46 base.apk\n-rw-rw---- 1 root everybody 10 2026-04-11 11:47 my file.txt\n";
        let e = parse_ls(t, "/sdcard");
        assert_eq!(e[0], FileEntry { path: "/storage/emulated/0/Download/base.apk".into(), size: 12713646, mtime: "2026-04-11 11:46".into() });
        assert_eq!(e[1].path, "/storage/emulated/0/Download/my file.txt");
    }

    #[test]
    fn roles_wifi_bt_camera_notifications() {
        let r = parse_roles("      {\n        name=android.app.role.CALL_SCREENING\n        fallback_enabled=false\n        holders=com.cbouvat.android.saracroche\n      }\n      {\n        name=android.app.role.SYSTEM_SUPERVISION\n      }\n");
        assert_eq!(r["android.app.role.CALL_SCREENING"], vec!["com.cbouvat.android.saracroche"]);
        assert!(!r.contains_key("android.app.role.SYSTEM_SUPERVISION"));

        let w = parse_wifi_networks("Network Id      SSID                         Security type\n0            arasaka                          wpa2-psk\n0            arasaka                          wpa3-sae^\n2            Gare SNCF wifi                   open\n");
        assert_eq!(w, vec![("Gare SNCF wifi".to_string(), "open".to_string()), ("arasaka".to_string(), "wpa2-psk".to_string())]);

        let b = parse_bt_bonded("Bonded devices:\n  XX:XX:XX:XX:3C:D2 [BR/EDR][ 0x240404 ] JBL Flip 5\n  AA:BB:CC:DD:EE:FF [ LE ] Tile Mate\n\nOther stuff:\n");
        assert_eq!(b, vec![("XX:XX:XX:XX:3C:D2".to_string(), "JBL Flip 5".to_string()), ("AA:BB:CC:DD:EE:FF".to_string(), "Tile Mate".to_string())]);

        let c = parse_camera_log("== Camera service events log (most recent at top): ==\n  11-06 14:19:16 : ADD device 0, reason: (Device added)\n  11-05 09:00:01 : CONNECT device 0 client for package com.spy (PID 4242)\n");
        assert_eq!(c[1], ("11-05 09:00:01".to_string(), "com.spy".to_string(), "CONNECT device 0 client for package com.spy (PID 4242)".to_string()));

        let n = parse_notifications("    NotificationRecord(0x0067: pkg=com.whatsapp user=UserHandle{0} id=1\n      uid=10152 userId=0\n      icon=Icon(typ=RESOURCE pkg=android id=0x01)\n            when=1793972014933\n      mCreationTimeMs=1793972014934\n    NotificationRecord(0x0068: pkg=android user=UserHandle{-1}\n      mCreationTimeMs=0\n");
        assert_eq!(n, vec![("com.whatsapp".to_string(), 1793972014934)]);
        assert!(vpn_active("  NetworkAgentInfo{network{101} ... Transports: VPN|WIFI Capabilities: INTERNET&VALIDATED"));
        assert!(!vpn_active("  NetworkAgentInfo{network{100} ... Transports: WIFI Capabilities: NOT_VPN&FOREGROUND"));
        // Real false positive from the test phone: a request that accepts any transport.
        assert!(!vpn_active("      NetworkRequest [ LISTEN id=325, [ Transports: CELLULAR|WIFI|BLUETOOTH|ETHERNET|VPN Capabilities: INTERNET&NOT_RESTRICTED&TRUSTED&NOT_VPN&FOREGROUND Uid: 10099 RequestorPkg: com.facebook.services ] ]"));
    }
}
