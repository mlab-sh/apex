//! `apex import`: turn a **full file-system extraction** (FFS) of an Android
//! phone — made by a lab tool (Cellebrite, GrayKey, Magnet…), a rooted `tar`, or
//! a TWRP backup — into an APEX case directory, so `analyze`, `timeline`,
//! `report`, `diff` and `identifiers` work on phones APEX could never connect to
//! (locked, broken, seized).
//!
//! Accepts a directory, a `.zip`, a `.tar` or a `.tar.gz`. The extraction root is
//! found by locating `data/system/packages.xml` (or `packages.list`), whatever
//! the prefix. System XML is read in both text and binary (ABX) form.
//!
//! The source is only read. Every source file used is hashed into the case
//! manifest, and every generated file is hashed too, so `apex verify` works.

use crate::abx::{self, Elem};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Small files read into memory (paths relative to the extraction root).
fn wanted_small(rel: &str) -> bool {
    const EXACT: &[&str] = &[
        "data/system/packages.xml",
        "data/system/packages.list",
        "data/system/uiderrors.txt",
        "data/system/device_policies.xml",
        "data/system/device_owner_2.xml",
        "data/misc/apexdata/com.android.wifi/WifiConfigStore.xml",
        "data/misc/wifi/WifiConfigStore.xml",
        "data/misc/bluedroid/bt_config.conf",
        "data/misc/bluetooth/bt_config.conf",
        "system/build.prop",
        "system/system/build.prop",
        "vendor/build.prop",
        "product/etc/build.prop",
    ];
    EXACT.contains(&rel)
        || (rel.starts_with("data/system/users/") && (rel.ends_with(".xml") || rel.contains("/accounts.db")))
        || rel.starts_with("data/system_ce/0/accounts_ce.db")
        || rel.starts_with("data/system_de/0/accounts_de.db")
        || rel.starts_with("data/property/")
}

fn is_apk(rel: &str) -> bool {
    rel.starts_with("data/app/") && rel.ends_with(".apk")
}

/// Directories whose file listing (name, size, time) feeds the staging / storage findings.
const LISTED: &[(&str, &str)] = &[("data/local/tmp/", "/data/local/tmp"), ("data/media/0/", "/storage/emulated/0")];

#[derive(Clone, Copy)]
enum MTime {
    Epoch(i64),
    /// Zip entries carry a DOS time with no zone: taken as device-local.
    Local(chrono::NaiveDateTime),
}

struct Listed {
    device_path: String,
    size: u64,
    mtime: Option<MTime>,
}

/// One pass over every regular file of the source.
fn walk(src: &Path, visit: &mut dyn FnMut(&str, u64, Option<MTime>, &mut dyn Read) -> Result<(), String>) -> Result<(), String> {
    let name = src.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let norm = |p: &str| p.replace('\\', "/").trim_start_matches("./").trim_start_matches('/').to_string();
    if src.is_dir() {
        for e in walkdir::WalkDir::new(src).follow_links(false).into_iter().flatten() {
            if !e.file_type().is_file() {
                continue;
            }
            let rel = norm(&e.path().strip_prefix(src).unwrap_or(e.path()).to_string_lossy());
            let md = e.metadata().ok();
            let mt = md.as_ref().and_then(|m| m.modified().ok()).and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| MTime::Epoch(d.as_secs() as i64));
            let mut f = std::fs::File::open(e.path()).map_err(|er| format!("{}: {er}", e.path().display()))?;
            visit(&rel, md.map(|m| m.len()).unwrap_or(0), mt, &mut f)?;
        }
    } else if name.ends_with(".zip") || name.ends_with(".ufdr") {
        let f = std::fs::File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
        let mut z = zip::ZipArchive::new(f).map_err(|e| format!("{}: {e}", src.display()))?;
        for i in 0..z.len() {
            let mut e = z.by_index(i).map_err(|e| e.to_string())?;
            if !e.is_file() {
                continue;
            }
            let rel = norm(e.name());
            let mt = e.last_modified().and_then(|d| {
                chrono::NaiveDate::from_ymd_opt(d.year() as i32, d.month() as u32, d.day() as u32)?.and_hms_opt(d.hour() as u32, d.minute() as u32, d.second() as u32)
            });
            let size = e.size();
            visit(&rel, size, mt.map(MTime::Local), &mut e)?;
        }
    } else if name.ends_with(".tar") || name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let f = std::fs::File::open(src).map_err(|e| format!("{}: {e}", src.display()))?;
        let r: Box<dyn Read> = if name.ends_with(".tar") { Box::new(f) } else { Box::new(flate2::read::GzDecoder::new(f)) };
        let mut a = tar::Archive::new(r);
        for e in a.entries().map_err(|e| e.to_string())? {
            let mut e = e.map_err(|e| e.to_string())?;
            if !e.header().entry_type().is_file() {
                continue;
            }
            let rel = norm(&e.path().map_err(|e| e.to_string())?.to_string_lossy());
            let (size, mt) = (e.header().size().unwrap_or(0), e.header().mtime().ok().map(|t| MTime::Epoch(t as i64)));
            visit(&rel, size, mt, &mut e)?;
        }
    } else {
        return Err(format!("{}: expected a directory, .zip, .tar or .tar.gz", src.display()));
    }
    Ok(())
}

/// Prefix before `data/system/packages.{xml,list}` (e.g. `Dump/` or `fs/`).
fn find_root(src: &Path) -> Result<String, String> {
    let mut root = None;
    walk(src, &mut |rel, _, _, _| {
        for marker in ["data/system/packages.xml", "data/system/packages.list"] {
            if let Some(p) = rel.strip_suffix(marker) {
                if p.is_empty() || p.ends_with('/') {
                    root.get_or_insert(p.to_string());
                }
            }
        }
        Ok(())
    })?;
    root.ok_or_else(|| "no data/system/packages.xml in this extraction: is it a full file-system extraction of an Android phone?".into())
}

// ---------------------------------------------------------------- converters

/// `persistent_properties` protobuf: repeated { 1: name, 2: value }.
pub fn parse_persistent_properties(b: &[u8]) -> Vec<(String, String)> {
    fn varint(b: &[u8], i: &mut usize) -> Option<u64> {
        let mut v = 0u64;
        for s in 0..10 {
            let x = *b.get(*i)?;
            *i += 1;
            v |= ((x & 0x7f) as u64) << (7 * s);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    fn fields(b: &[u8]) -> Vec<(u64, &[u8])> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            let Some(key) = varint(b, &mut i) else { break };
            match key & 7 {
                2 => {
                    let Some(n) = varint(b, &mut i) else { break };
                    let Some(v) = b.get(i..i + n as usize) else { break };
                    i += n as usize;
                    out.push((key >> 3, v));
                }
                0 => {
                    if varint(b, &mut i).is_none() {
                        break;
                    }
                }
                _ => break,
            }
        }
        out
    }
    fields(b)
        .into_iter()
        .filter(|(f, _)| *f == 1)
        .filter_map(|(_, rec)| {
            let fs = fields(rec);
            let get = |n| fs.iter().find(|(f, _)| *f == n).map(|(_, v)| String::from_utf8_lossy(v).into_owned());
            Some((get(1)?, get(2).unwrap_or_default()))
        })
        .collect()
}

fn hex_ms(v: &str) -> Option<i64> {
    i64::from_str_radix(v, 16).ok().filter(|x| *x > 0)
}

fn local(ms: i64, tz: Option<chrono_tz::Tz>) -> Option<String> {
    let utc = chrono::DateTime::from_timestamp_millis(ms)?;
    let t = match tz {
        Some(tz) => utc.with_timezone(&tz).naive_local(),
        None => utc.naive_utc(),
    };
    Some(t.format("%Y-%m-%d %H:%M:%S").to_string())
}

/// `packages.xml` → (name, codePath, installer, system, uid, version, it, ut).
#[derive(Debug, Clone, PartialEq)]
pub struct XPkg {
    pub name: String,
    pub code_path: String,
    pub installer: Option<String>,
    pub system: bool,
    pub uid: Option<String>,
    pub version: Option<String>,
    pub first_install_ms: Option<i64>,
    pub last_update_ms: Option<i64>,
}

pub fn parse_packages_xml(root: &Elem) -> Vec<XPkg> {
    let Some(top) = root.children.iter().find(|c| c.name == "packages") else { return Vec::new() };
    top.children
        .iter()
        .filter(|e| e.name == "package")
        .filter_map(|p| {
            let flags: i64 = p.attr("publicFlags").or(p.attr("flags")).and_then(|f| f.parse().ok()).unwrap_or(0);
            Some(XPkg {
                name: p.attr("name")?.to_string(),
                code_path: p.attr("codePath").unwrap_or("").to_string(),
                installer: p.attr("installer").filter(|i| !i.is_empty()).map(String::from),
                system: flags & 1 != 0,
                uid: p.attr("userId").or(p.attr("sharedUserId")).map(String::from),
                version: p.attr("version").map(String::from),
                first_install_ms: p.attr("it").and_then(hex_ms),
                last_update_ms: p.attr("ut").and_then(hex_ms),
            })
        })
        .collect()
}

/// `package-restrictions.xml`: packages *not* installed for that user.
pub fn not_installed(root: &Elem) -> BTreeSet<String> {
    root.all("pkg").into_iter().filter(|p| p.attr("inst") == Some("false")).filter_map(|p| p.attr("name").map(String::from)).collect()
}

/// `WifiConfigStore.xml` → (SSID, security) in `cmd wifi list-networks` terms.
pub fn parse_wifi_store(root: &Elem) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for cfg in root.all("WifiConfiguration") {
        let s = |n: &str| cfg.children.iter().find(|c| c.attr("name") == Some(n)).map(|c| c.text.clone());
        let Some(key) = s("ConfigKey") else { continue };
        let ssid = s("SSID").unwrap_or_default().trim_matches('"').to_string();
        let sec = match key.rsplit('"').next().unwrap_or("") {
            "NONE" => "open",
            "WPA_PSK" => "wpa2-psk",
            "SAE" => "wpa3-sae",
            "OWE" => "owe",
            "WEP" => "wep",
            k if k.contains("EAP") || k.contains("SUITE_B") => "wpa2-eap",
            k => k,
        };
        out.push((ssid, sec.to_string()));
    }
    out
}

/// `bt_config.conf` → (own address, own name, bonded (address, name)).
pub fn parse_bt_config(text: &str) -> (Option<String>, Option<String>, Vec<(String, String)>) {
    let (mut addr, mut name, mut bonded) = (None, None, Vec::new());
    let mut section = String::new();
    let (mut dev_name, mut linked) = (String::new(), false);
    let flush = |section: &str, dev_name: &str, linked: bool, bonded: &mut Vec<(String, String)>| {
        if linked && section.matches(':').count() == 5 {
            bonded.push((section.to_uppercase(), dev_name.to_string()));
        }
    };
    for l in text.lines().map(str::trim) {
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            flush(&section, &dev_name, linked, &mut bonded);
            section = s.to_string();
            dev_name.clear();
            linked = false;
            continue;
        }
        let Some((k, v)) = l.split_once('=').map(|(k, v)| (k.trim(), v.trim())) else { continue };
        match (section.as_str(), k) {
            ("Adapter", "Address") => addr = Some(v.to_uppercase()),
            ("Adapter", "Name") => name = Some(v.to_string()),
            (_, "Name") => dev_name = v.to_string(),
            (_, "LinkKey") | (_, "LE_KEY_PENC") => linked = true,
            _ => {}
        }
    }
    flush(&section, &dev_name, linked, &mut bonded);
    (addr, name, bonded)
}

/// Accounts from an `accounts*.db` (SQLite, opened from a temp copy so the
/// source is never touched, WAL applied).
fn sqlite_accounts(files: &BTreeMap<String, Vec<u8>>, db: &str) -> Vec<(String, String)> {
    let Some(main) = files.get(db) else { return Vec::new() };
    let Ok(dir) = tempfile::tempdir() else { return Vec::new() };
    let p = dir.path().join("a.db");
    if std::fs::write(&p, main).is_err() {
        return Vec::new();
    }
    for ext in ["-wal", "-shm", "-journal"] {
        if let Some(b) = files.get(&format!("{db}{ext}")) {
            let _ = std::fs::write(dir.path().join(format!("a.db{ext}")), b);
        }
    }
    let Ok(c) = rusqlite::Connection::open(&p) else { return Vec::new() };
    let Ok(mut st) = c.prepare("SELECT type, name FROM accounts") else { return Vec::new() };
    st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map(|it| it.flatten().collect()).unwrap_or_default()
}

/// Synthetic `ls -laR` text for `artifacts::parse_ls`.
fn ls_text(entries: &[Listed], base: &str, tz: Option<chrono_tz::Tz>) -> String {
    let mut by_dir: BTreeMap<String, Vec<&Listed>> = BTreeMap::new();
    for e in entries.iter().filter(|e| e.device_path.starts_with(base)) {
        let (d, _) = e.device_path.rsplit_once('/').unwrap_or((base, ""));
        by_dir.entry(d.to_string()).or_default().push(e);
    }
    let mut s = String::new();
    for (d, files) in by_dir {
        s.push_str(&format!("{d}:\n"));
        for f in files {
            let t = match f.mtime {
                Some(MTime::Epoch(e)) => local(e * 1000, tz),
                Some(MTime::Local(n)) => Some(n.format("%Y-%m-%d %H:%M:%S").to_string()),
                None => None,
            }
            .map(|t| t[..16].to_string())
            .unwrap_or_else(|| "1970-01-01 00:00".into());
            let name = f.device_path.rsplit('/').next().unwrap_or("");
            s.push_str(&format!("-rw-rw---- 1 u0 media_rw {} {t} {name}\n", f.size));
        }
        s.push('\n');
    }
    s
}

fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}

/// What else to copy besides the system state.
#[derive(Clone, Copy, Default)]
pub struct Options {
    /// Communication databases (only under a legal mandate).
    pub comms: bool,
    /// Shared storage (`data/media/0`).
    pub storage: bool,
}

/// Stream `r` into `dst`, returning (sha256, bytes).
fn copy_stream(r: &mut dyn Read, dst: &Path) -> Result<(String, usize), String> {
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    let mut f = std::fs::File::create(dst).map_err(|e| format!("{}: {e}", dst.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0usize;
    loop {
        let k = r.read(&mut buf).map_err(|e| format!("{}: {e}", dst.display()))?;
        if k == 0 {
            break;
        }
        h.update(&buf[..k]);
        std::io::Write::write_all(&mut f, &buf[..k]).map_err(|e| e.to_string())?;
        n += k;
    }
    Ok((format!("{:x}", h.finalize()), n))
}

pub struct Summary {
    pub root_prefix: String,
    pub packages: usize,
    pub third_party: usize,
    pub apks: usize,
    pub users: usize,
    pub produced: Vec<String>,
    pub missing: Vec<&'static str>,
}

/// Import `src` into the case directory `out`.
pub fn import(src: &Path, out: &Path, case_meta: Value, opts: Options) -> Result<Summary, String> {
    let started = chrono::Utc::now().to_rfc3339();
    let prefix = find_root(src)?;
    let dev = out.join("device");
    let staging = out.join(".apk_staging");
    for d in [&dev, &staging] {
        std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }

    // ---- One pass: small files in memory, APKs staged, listings recorded.
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut apks: Vec<(String, PathBuf)> = Vec::new();
    let mut listed: Vec<Listed> = Vec::new();
    let mut inputs: Vec<Value> = Vec::new();
    // Extra copies (communications, storage), relative to `out`, for the manifest.
    let mut copied: Vec<String> = Vec::new();
    walk(src, &mut |rel, size, mt, r| {
        let Some(rel) = rel.strip_prefix(prefix.as_str()) else { return Ok(()) };
        for (dir, base) in LISTED {
            if let Some(rest) = rel.strip_prefix(dir) {
                listed.push(Listed { device_path: format!("{base}/{rest}"), size, mtime: mt });
            }
        }
        if wanted_small(rel) {
            let mut b = Vec::new();
            r.read_to_end(&mut b).map_err(|e| format!("{rel}: {e}"))?;
            inputs.push(json!({"file": format!("{prefix}{rel}"), "sha256": sha(&b), "bytes": b.len()}));
            files.insert(rel.to_string(), b);
        } else if is_apk(rel) {
            let dst = staging.join(format!("{}.apk", apks.len()));
            let (h, n) = copy_stream(r, &dst)?;
            inputs.push(json!({"file": format!("{prefix}{rel}"), "sha256": h, "bytes": n}));
            apks.push((format!("/{rel}"), dst));
        } else {
            let target = if opts.comms {
                crate::comms::db_name(rel)
                    .map(|(name, ext)| format!("comms/db/{name}{ext}"))
                    .or_else(|| rel.strip_prefix(crate::comms::MMS_PARTS_DIR).map(|f| format!("comms/mms_parts/{f}")))
                    .or_else(|| crate::appdata::target(rel, size))
            } else {
                None
            }
            .or_else(|| {
                let rest = rel.strip_prefix("data/media/0/")?;
                (opts.storage && !rest.starts_with("Android/data/") && !rest.starts_with("Android/obb/")).then(|| format!("storage/{rest}"))
            });
            if let Some(t) = target {
                let (h, n) = copy_stream(r, &out.join(&t))?;
                inputs.push(json!({"file": format!("{prefix}{rel}"), "sha256": h, "bytes": n}));
                copied.push(t);
            }
        }
        Ok(())
    })?;

    let xml = |rel: &str| files.get(rel).and_then(|b| abx::parse(b).ok());
    let text = |rel: &str| files.get(rel).map(|b| String::from_utf8_lossy(b).into_owned());
    let mut produced: Vec<String> = Vec::new();
    let mut missing: Vec<&'static str> = Vec::new();
    let write = |name: &str, body: String, produced: &mut Vec<String>| -> Result<(), String> {
        std::fs::write(dev.join(name), body).map_err(|e| format!("cannot write {name}: {e}"))?;
        produced.push(format!("device/{name}"));
        Ok(())
    };

    // ---- Properties (time zone first: every timestamp depends on it).
    let mut props: BTreeMap<String, String> = BTreeMap::new();
    for bp in ["system/build.prop", "system/system/build.prop", "vendor/build.prop", "product/etc/build.prop"] {
        for l in text(bp).unwrap_or_default().lines() {
            if let Some((k, v)) = l.split_once('=').filter(|_| !l.trim_start().starts_with('#')) {
                props.entry(k.trim().to_string()).or_insert_with(|| v.trim().to_string());
            }
        }
    }
    if let Some(b) = files.get("data/property/persistent_properties") {
        props.extend(parse_persistent_properties(b));
    }
    for (rel, b) in files.iter().filter(|(k, _)| k.starts_with("data/property/persist.")) {
        props.insert(rel.trim_start_matches("data/property/").to_string(), String::from_utf8_lossy(b).trim().to_string());
    }
    let tz: Option<chrono_tz::Tz> = props.get("persist.sys.timezone").and_then(|t| t.parse().ok());
    if tz.is_none() {
        missing.push("time zone (persist.sys.timezone): times are UTC");
    }
    if !props.is_empty() {
        write("getprop.txt", props.iter().map(|(k, v)| format!("[{k}]: [{v}]\n")).collect(), &mut produced)?;
    }

    // ---- Packages.
    let pkgs = xml("data/system/packages.xml").map(|r| parse_packages_xml(&r)).unwrap_or_default();
    if pkgs.is_empty() {
        return Err("data/system/packages.xml is missing or unreadable: nothing to analyze".into());
    }
    let users_xml = xml("data/system/users/userlist.xml");
    let user_ids: Vec<u32> = users_xml
        .as_ref()
        .map(|u| u.all("user").iter().filter_map(|e| e.attr("id")?.parse().ok()).collect())
        .filter(|v: &Vec<u32>| !v.is_empty())
        .unwrap_or_else(|| vec![0]);
    let absent = |u: u32| xml(&format!("data/system/users/{u}/package-restrictions.xml")).map(|r| not_installed(&r)).unwrap_or_default();
    let absent0 = absent(0);
    let apk_path = |p: &XPkg| if p.code_path.ends_with(".apk") { p.code_path.clone() } else { format!("{}/base.apk", p.code_path) };
    let line = |p: &XPkg| format!("package:{}={}  installer={}\n", apk_path(p), p.name, p.installer.as_deref().unwrap_or("null"));
    write("packages.txt", pkgs.iter().map(line).collect(), &mut produced)?;
    write("packages_3.txt", pkgs.iter().filter(|p| !p.system && !absent0.contains(&p.name)).map(|p| format!("package:{}\n", p.name)).collect(), &mut produced)?;
    write("packages_system.txt", pkgs.iter().filter(|p| p.system).map(|p| format!("package:{}\n", p.name)).collect(), &mut produced)?;
    write("packages_uid.txt", pkgs.iter().filter_map(|p| Some(format!("package:{} uid:{}\n", p.name, p.uid.as_ref()?))).collect(), &mut produced)?;

    // ---- Users.
    let mut users_txt = String::from("Users:\n");
    for u in &user_ids {
        let ux = xml(&format!("data/system/users/{u}.xml"));
        let e = ux.as_ref().and_then(|x| x.children.iter().find(|c| c.name == "user"));
        let name = e.and_then(|e| e.child("name")).map(|n| n.text.clone()).unwrap_or_default();
        let flags: u32 = e.and_then(|e| e.attr("flags")).and_then(|f| f.parse::<i64>().ok()).unwrap_or(0) as u32;
        users_txt.push_str(&format!("\tUserInfo{{{u}:{name}:{flags:x}}}\n"));
        if *u != 0 {
            let gone = absent(*u);
            write(&format!("packages_3_user{u}.txt"), pkgs.iter().filter(|p| !p.system && !gone.contains(&p.name)).map(|p| format!("package:{}\n", p.name)).collect(), &mut produced)?;
        }
    }
    write("users.txt", users_txt, &mut produced)?;

    // ---- Settings (main user; global and secure live there too).
    let mut bt_settings = String::new();
    let bt = text("data/misc/bluedroid/bt_config.conf").or_else(|| text("data/misc/bluetooth/bt_config.conf")).map(|t| parse_bt_config(&t));
    if let Some((Some(a), n, _)) = &bt {
        bt_settings.push_str(&format!("bluetooth_address={a}\n"));
        if let Some(n) = n {
            bt_settings.push_str(&format!("bluetooth_name={n}\n"));
        }
    }
    for ns in ["secure", "global", "system"] {
        match xml(&format!("data/system/users/0/settings_{ns}.xml")) {
            Some(r) => {
                let mut body: String = r.all("setting").iter().filter_map(|s| Some(format!("{}={}\n", s.attr("name")?, s.attr("value").unwrap_or("null")))).collect();
                if ns == "secure" && !body.contains("\nbluetooth_address=") {
                    body.push_str(&bt_settings);
                }
                write(&format!("settings_{ns}.txt"), body, &mut produced)?;
            }
            None => missing.push(match ns {
                "secure" => "settings_secure.xml",
                "global" => "settings_global.xml",
                _ => "settings_system.xml",
            }),
        }
    }

    // ---- Package manager log (first boot, uninstalls).
    if let Some(t) = text("data/system/uiderrors.txt") {
        write("package_messages.txt", format!("Package warning messages:\n{t}"), &mut produced)?;
    } else {
        missing.push("uiderrors.txt (install / uninstall history)");
    }

    // ---- Accounts.
    let mut acc: Vec<(String, String)> = sqlite_accounts(&files, "data/system_ce/0/accounts_ce.db");
    for (t, n) in sqlite_accounts(&files, "data/system_de/0/accounts_de.db").into_iter().chain(sqlite_accounts(&files, "data/system/users/0/accounts.db")) {
        if !acc.contains(&(t.clone(), n.clone())) {
            acc.push((t, n));
        }
    }
    if acc.is_empty() {
        missing.push("accounts (accounts_ce.db: credential-encrypted, needs an after-first-unlock extraction)");
    }
    write("accounts.txt", acc.iter().map(|(t, n)| format!("    Account {{name={n}, type={t}}}\n")).collect(), &mut produced)?;

    // ---- Device admins / owners.
    let mut dp = String::new();
    if let Some(o) = xml("data/system/device_owner_2.xml") {
        for (tag, label) in [("device-owner", "Device Owner:"), ("profile-owner", "Profile Owner:")] {
            for e in o.all(tag) {
                if let Some(c) = e.attr("component") {
                    dp.push_str(&format!("{label}\n    admin=ComponentInfo{{{c}}}\n"));
                }
            }
        }
    }
    for u in &user_ids {
        let rel = if *u == 0 { "data/system/device_policies.xml".to_string() } else { format!("data/system/users/{u}/device_policies.xml") };
        if let Some(p) = xml(&rel) {
            dp.push_str(&format!("  Enabled Device Admins (User {u}, provisioningState: 0):\n"));
            for a in p.all("admin") {
                if let Some(n) = a.attr("name") {
                    dp.push_str(&format!("    {n}:\n"));
                }
            }
        }
    }
    write("device_policy.txt", dp, &mut produced)?;

    // ---- Wi-Fi (SSID and security only: stored passwords are not copied).
    let wifi = xml("data/misc/apexdata/com.android.wifi/WifiConfigStore.xml").or_else(|| xml("data/misc/wifi/WifiConfigStore.xml"));
    match wifi {
        Some(w) => write(
            "wifi_networks.txt",
            std::iter::once("Network Id      SSID                         Security type\n".to_string())
                .chain(parse_wifi_store(&w).iter().enumerate().map(|(i, (s, k))| format!("{i}  {s}  {k}\n")))
                .collect(),
            &mut produced,
        )?,
        None => missing.push("WifiConfigStore.xml"),
    }

    // ---- Bluetooth bonded devices.
    if let Some((_, _, bonded)) = &bt {
        write("bluetooth.txt", std::iter::once("Bonded devices:\n".to_string()).chain(bonded.iter().map(|(a, n)| format!("  {a} {n}\n"))).collect(), &mut produced)?;
    }

    // ---- File listings.
    write("local_tmp.txt", ls_text(&listed, "/data/local/tmp", tz), &mut produced)?;
    write("sdcard_listing.txt", ls_text(&listed, "/storage/emulated/0", tz), &mut produced)?;

    // ---- Device identity.
    let p = |k: &str| props.get(k).cloned().unwrap_or_default();
    let ident = json!({
        "model": p("ro.product.model"),
        "manufacturer": p("ro.product.manufacturer"),
        "serial": p("ro.serialno"),
        "android_release": p("ro.build.version.release"),
        "sdk": p("ro.build.version.sdk"),
        "security_patch": p("ro.build.version.security_patch"),
        "build_fingerprint": p("ro.build.fingerprint"),
    });
    write("identifiers.json", serde_json::to_string_pretty(&ident).unwrap_or_default(), &mut produced)?;

    // ---- Apps: APKs by code path, plus install times for the timeline.
    let third: Vec<&XPkg> = pkgs.iter().filter(|p| !p.system).collect();
    let mut apk_count = 0;
    for x in &third {
        let dir = out.join("apps").join(&x.name);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let mut info = format!("Package [{}]\n", x.name);
        if let Some(v) = &x.version {
            info.push_str(&format!("    versionCode={v}\n"));
        }
        if let Some(t) = x.first_install_ms.and_then(|m| local(m, tz)) {
            info.push_str(&format!("    firstInstallTime={t}\n"));
        }
        if let Some(t) = x.last_update_ms.and_then(|m| local(m, tz)) {
            info.push_str(&format!("    lastUpdateTime={t}\n"));
        }
        if let Some(i) = &x.installer {
            info.push_str(&format!("    installerPackageName={i}\n"));
        }
        std::fs::write(dir.join("dumpsys_package.txt"), info).map_err(|e| e.to_string())?;
        produced.push(format!("apps/{}/dumpsys_package.txt", x.name));
        let cp = format!("{}/", x.code_path.trim_end_matches('/'));
        for (device_path, staged) in apks.iter().filter(|(d, _)| d.starts_with(&cp)) {
            let name = device_path.rsplit('/').next().unwrap_or("base.apk");
            std::fs::rename(staged, dir.join(name)).or_else(|_| std::fs::copy(staged, dir.join(name)).map(|_| ())).map_err(|e| e.to_string())?;
            produced.push(format!("apps/{}/{name}", x.name));
            apk_count += 1;
        }
    }
    let _ = std::fs::remove_dir_all(&staging);
    if opts.comms && !copied.iter().any(|c| c.starts_with("comms/db/")) {
        missing.push("communication databases (app data: needs an after-first-unlock extraction)");
    }
    produced.extend(copied);

    // ---- Evidence: hash of every source file read, and of every file produced.
    let produced_paths: Vec<PathBuf> = produced.iter().map(|p| out.join(p)).collect();
    let mut meta = case_meta;
    if let Value::Object(m) = &mut meta {
        m.insert("source".into(), json!(src.display().to_string()));
        m.insert("extraction_root".into(), json!(prefix));
    }
    crate::evidence::write_import_evidence(out, &src.display().to_string(), &started, inputs, &produced_paths, meta)?;

    Ok(Summary {
        root_prefix: prefix,
        packages: pkgs.len(),
        third_party: third.len(),
        apks: apk_count,
        users: user_ids.len(),
        produced,
        missing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_props() {
        // { 1: { 1: "persist.sys.timezone", 2: "Europe/Paris" } }
        let mut rec = vec![0x0a, 20];
        rec.extend(b"persist.sys.timezone");
        rec.extend([0x12, 12]);
        rec.extend(b"Europe/Paris");
        let mut b = vec![0x0a, rec.len() as u8];
        b.extend(rec);
        assert_eq!(parse_persistent_properties(&b), vec![("persist.sys.timezone".into(), "Europe/Paris".into())]);
    }

    #[test]
    fn packages_and_restrictions() {
        let x = abx::parse(br#"<packages><package name="com.spy" codePath="/data/app/~~a==/com.spy-b==" publicFlags="0" it="18d0a1b2c3d" ut="18d0a1b2c3e" version="12" userId="10200" installer="com.android.packageinstaller"/><package name="com.android.settings" codePath="/system/priv-app/Settings" publicFlags="-1" userId="1000"/></packages>"#).unwrap();
        let p = parse_packages_xml(&x);
        assert_eq!(p.len(), 2);
        assert!(!p[0].system && p[1].system);
        assert_eq!(p[0].first_install_ms, Some(0x18d0a1b2c3d));
        assert_eq!(local(0x18d0a1b2c3d, Some(chrono_tz::Europe::Paris)).unwrap(), "2024-01-14 23:32:49");
        let r = abx::parse(br#"<package-restrictions><pkg name="com.spy" inst="false"/><pkg name="com.ok"/></package-restrictions>"#).unwrap();
        assert_eq!(not_installed(&r), ["com.spy".to_string()].into_iter().collect());
    }

    #[test]
    fn wifi_and_bt() {
        let w = abx::parse(br#"<WifiConfigStoreData><NetworkList><Network><WifiConfiguration><string name="ConfigKey">"Home"WPA_PSK</string><string name="SSID">"Home"</string><string name="PreSharedKey">"secret"</string></WifiConfiguration></Network><Network><WifiConfiguration><string name="ConfigKey">"Cafe"NONE</string><string name="SSID">"Cafe"</string></WifiConfiguration></Network></NetworkList></WifiConfigStoreData>"#).unwrap();
        assert_eq!(parse_wifi_store(&w), vec![("Home".into(), "wpa2-psk".into()), ("Cafe".into(), "open".into())]);
        let (a, n, b) = parse_bt_config("[Adapter]\nAddress = 60:6e:e8:b7:eb:9b\nName = Phone\n[aa:bb:cc:dd:ee:ff]\nName = AirTag\nLinkKey = 0011\n[11:22:33:44:55:66]\nName = Seen only\n");
        assert_eq!((a.as_deref(), n.as_deref()), (Some("60:6E:E8:B7:EB:9B"), Some("Phone")));
        assert_eq!(b, vec![("AA:BB:CC:DD:EE:FF".into(), "AirTag".into())]);
    }
}
