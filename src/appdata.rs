//! App private data, **only under a legal mandate**, from a full file-system
//! extraction (`import --mandate`) or, for WhatsApp backups, shared storage:
//! Signal (SQLCipher), WhatsApp `.crypt14` / `.crypt15` backups, Google Maps,
//! Messenger, Instagram, Snapchat, Gboard, Gmail and crypto wallets.
//!
//! Files land in `<case>/comms/app/<package>/…` (same layout as `data/data/`).
//! App schemas change often: every reader checks tables / columns first and
//! marks heuristic sources as such.

use crate::comms::{self, rows, vi, vs, Comm, Dbx};
use crate::sqlite_carve::Val;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// App-data paths copied under mandate (`data/data/` form). A trailing `/` is a directory.
pub const APP_PATHS: &[&str] = &[
    "data/data/org.thoughtcrime.securesms/databases/",
    "data/data/org.thoughtcrime.securesms/shared_prefs/",
    "data/data/com.whatsapp/files/key",
    "data/data/com.whatsapp.w4b/files/key",
    // End-to-end backups: the 64-digit root key, kept by the app on the phone.
    "data/data/com.whatsapp/files/encrypted_backup.key",
    "data/data/com.whatsapp.w4b/files/encrypted_backup.key",
    "data/data/com.google.android.apps.maps/databases/",
    "data/data/com.facebook.orca/databases/",
    "data/data/com.instagram.android/databases/",
    "data/data/com.snapchat.android/databases/",
    "data/data/com.google.android.inputmethod.latin/databases/",
    "data/data/com.google.android.gm/databases/",
];

/// WhatsApp backup folders on shared storage (extraction form, then live form).
pub const WA_BACKUP_DIRS: &[&str] = &[
    "data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/",
    "data/media/0/WhatsApp/Databases/",
    "data/media/0/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases/",
];
pub const WA_BACKUP_LIVE: &[&str] = &[
    "/sdcard/Android/media/com.whatsapp/WhatsApp/Databases",
    "/sdcard/WhatsApp/Databases",
    "/sdcard/Android/media/com.whatsapp.w4b/WhatsApp Business/Databases",
];

/// Signal backup file name: `signal-YYYY-MM-DD-HH-MM-SS.backup`.
pub fn is_signal_backup(name: &str) -> bool {
    name.starts_with("signal-") && name.ends_with(".backup") && !name.contains(char::is_whitespace) && !name.contains('/')
}

/// Where Signal backups go in a case.
pub const SIGNAL_BACKUPS: &str = "comms/app/org.thoughtcrime.securesms/backups";

pub fn is_wa_backup(name: &str) -> bool {
    name.starts_with("msgstore") && !name.contains(char::is_whitespace) && !name.contains('/') && (name.ends_with(".crypt14") || name.ends_with(".crypt15"))
}

/// Crypto wallets and exchanges: (package, name).
pub const WALLETS: &[(&str, &str)] = &[
    ("com.wallet.crypto.trustapp", "Trust Wallet"),
    ("io.metamask", "MetaMask"),
    ("org.toshi", "Coinbase Wallet"),
    ("com.coinbase.android", "Coinbase"),
    ("exodusmovement.exodus", "Exodus"),
    ("com.binance.dev", "Binance"),
    ("de.schildbach.wallet", "Bitcoin Wallet"),
    ("org.electrum.electrum", "Electrum"),
    ("io.bluewallet.bluewallet", "BlueWallet"),
    ("io.atomicwallet", "Atomic Wallet"),
    ("com.ledger.live", "Ledger Live"),
    ("app.phantom", "Phantom"),
    ("com.kraken.trade", "Kraken"),
    ("co.mona.android", "Crypto.com"),
    ("com.bybit.app", "Bybit"),
    ("com.okinc.okex.gp", "OKX"),
    ("com.samourai.wallet", "Samourai"),
    ("com.mycelium.wallet", "Mycelium"),
    ("com.paymium.mobile", "Paymium"),
];

/// Apps whose operator holds data worth a legal request: (package, category, operator).
pub const OF_INTEREST: &[(&str, &str, &str)] = &[
    ("com.ubercab", "ride-hailing", "Uber"),
    ("ee.mtakso.client", "ride-hailing", "Bolt"),
    ("com.heetch", "ride-hailing", "Heetch"),
    ("taxi.android.client", "ride-hailing", "FreeNow"),
    ("com.comuto", "carpooling", "BlaBlaCar"),
    ("com.ubercab.eats", "delivery", "Uber Eats"),
    ("com.deliveroo.orderapp", "delivery", "Deliveroo"),
    ("org.thoughtcrime.securesms", "encrypted messaging", "Signal"),
    ("org.telegram.messenger", "messaging", "Telegram"),
    ("ch.threema.app", "encrypted messaging", "Threema"),
    ("network.loki.messenger", "encrypted messaging", "Session"),
    ("io.olvid.messenger", "encrypted messaging", "Olvid"),
    ("com.wire", "encrypted messaging", "Wire"),
    ("im.vector.app", "encrypted messaging", "Element (Matrix)"),
    ("org.briarproject.briar.android", "encrypted messaging", "Briar"),
    ("chat.simplex.app", "encrypted messaging", "SimpleX"),
    ("com.snapchat.android", "messaging", "Snapchat"),
    ("com.facebook.orca", "messaging", "Messenger (Meta)"),
    ("com.instagram.android", "social", "Instagram (Meta)"),
    ("com.zhiliaoapp.musically", "social", "TikTok"),
    ("com.paypal.android.p2pmobile", "payment", "PayPal"),
    ("com.lydia", "payment", "Lydia / Sumeria"),
    ("com.revolut.revolut", "payment", "Revolut"),
    ("com.airbnb.android", "lodging", "Airbnb"),
    ("com.leboncoin", "marketplace", "leboncoin"),
    ("com.vinted", "marketplace", "Vinted"),
];

/// Apps of interest installed: (package, category, operator), wallets included.
pub fn apps_of_interest<'a>(installed: impl Iterator<Item = &'a String>) -> Vec<(String, &'static str, &'static str)> {
    let mut out: Vec<_> = installed
        .filter_map(|p| {
            OF_INTEREST.iter().find(|(q, _, _)| q == p).map(|(_, c, o)| (p.clone(), *c, *o)).or_else(|| WALLETS.iter().find(|(q, _)| q == p).map(|(_, n)| (p.clone(), "crypto", *n)))
        })
        .collect();
    out.sort();
    out
}

/// Where an extraction file goes under mandate (relative to the case), if wanted.
pub fn target(rel: &str, size: u64) -> Option<String> {
    let r = rel.replacen("data/user/0/", "data/data/", 1);
    if let Some(name) = WA_BACKUP_DIRS.iter().find_map(|d| r.strip_prefix(d)).filter(|n| is_wa_backup(n)) {
        let pkg = if r.contains("w4b") { "com.whatsapp.w4b" } else { "com.whatsapp" };
        return Some(format!("comms/app/{pkg}/backups/{name}"));
    }
    if let Some(name) = r.strip_prefix("data/media/0/").and_then(|x| x.rsplit('/').next()).filter(|n| is_signal_backup(n)) {
        return Some(format!("{SIGNAL_BACKUPS}/{name}"));
    }
    let rest = r.strip_prefix("data/data/")?;
    let wanted = APP_PATHS.iter().any(|p| if p.ends_with('/') { r.starts_with(p) } else { r == *p })
        // Wallet apps: their settings, databases and files (addresses), size-capped.
        || (WALLETS.iter().any(|(p, _)| rest.starts_with(&format!("{p}/"))) && size <= 20 << 20 && ["shared_prefs/", "databases/", "files/"].iter().any(|d| rest.split_once('/').is_some_and(|(_, x)| x.starts_with(d))));
    wanted.then(|| format!("comms/app/{rest}"))
}

// ---------------------------------------------------------------- protobuf helpers

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

/// Length-delimited fields of a protobuf message; `None` unless it parses fully.
fn pb_bytes(b: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i)?;
        if key >> 3 == 0 {
            return None;
        }
        match key & 7 {
            0 => {
                varint(b, &mut i)?;
            }
            1 => i += 8,
            5 => i += 4,
            2 => {
                let n = varint(b, &mut i)? as usize;
                out.push(b.get(i..i.checked_add(n)?)?);
                i += n;
            }
            _ => return None,
        }
    }
    (i == b.len()).then_some(out)
}

fn printable(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| !c.is_control() || c == '\n') && s.chars().any(char::is_alphanumeric)
}

/// Every printable string in a protobuf, depth-first.
// ponytail: schema-less walk; app protos are undocumented and change often.
pub fn pb_strings(b: &[u8]) -> Vec<String> {
    fn go(b: &[u8], out: &mut Vec<String>, depth: u8) {
        if depth > 12 {
            return;
        }
        for f in pb_bytes(b).unwrap_or_default() {
            match std::str::from_utf8(f) {
                Ok(s) if printable(s) => out.push(s.to_string()),
                _ => go(f, out, depth + 1),
            }
        }
    }
    let mut out = Vec::new();
    go(b, &mut out, 0);
    out
}

/// 16-byte fields of a protobuf (candidate IVs), depth-first.
fn pb_16(b: &[u8], out: &mut Vec<Vec<u8>>) {
    for f in pb_bytes(b).unwrap_or_default() {
        if f.len() == 16 {
            out.push(f.to_vec());
        } else {
            pb_16(f, out);
        }
    }
}

// ---------------------------------------------------------------- WhatsApp backups

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

fn hmac256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// `.crypt15` encryption key from the 64-digit end-to-end backup key.
pub fn wa_e2e_key(root: &[u8]) -> [u8; 32] {
    let prk = hmac256(&[0u8; 32], root);
    hmac256(&prk, b"backup encryption\x01")
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    (s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())).then(|| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
}

/// Candidate keys: the `files/key` file (last 32 bytes) and/or a hex key
/// (64-digit E2E backup key, or a raw 32-byte key).
pub fn wa_keys(key_file: Option<&[u8]>, user: Option<&str>) -> Vec<[u8; 32]> {
    let mut out = Vec::new();
    if let Some(k) = key_file.filter(|k| k.len() >= 32) {
        out.push(k[k.len() - 32..].try_into().unwrap());
    }
    if let Some(b) = user.and_then(hex).filter(|b| b.len() == 32) {
        out.push(wa_e2e_key(&b));
        out.push(b.try_into().unwrap());
    }
    out
}

/// Decrypt a `.crypt14` / `.crypt15` backup into SQLite bytes.
/// Layout: [proto size varint][0x01 feature flag?][prefix protobuf with the IV][AES-256-GCM data][tag][md5?].
pub fn wa_decrypt(file: &[u8], keys: &[[u8; 32]]) -> Option<Vec<u8>> {
    use aes_gcm::aead::consts::U16;
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    type Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U16>;
    // The prefix size is a varint, sometimes followed by a 0x01 feature flag.
    let mut i = 0;
    let size = varint(file, &mut i)? as usize;
    for start in [i, i + 1] {
        let Some(proto) = file.get(start..start + size) else { continue };
        let body = &file[start + size..];
        let mut ivs = Vec::new();
        pb_16(proto, &mut ivs);
        for k in keys {
            let gcm = Gcm::new(k.into());
            for iv in &ivs {
                // With and without the trailing MD5 checksum.
                for trail in [32usize, 16] {
                    if body.len() < trail {
                        continue;
                    }
                    let mut buf = body[..body.len() - trail].to_vec();
                    let tag = &body[body.len() - trail..body.len() - trail + 16];
                    if gcm.decrypt_in_place_detached(iv.as_slice().into(), b"", &mut buf, tag.into()).is_ok() {
                        let mut db = Vec::new();
                        let plain = if std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&buf[..]), &mut db).is_ok() { db } else { buf };
                        return plain.starts_with(b"SQLite format 3\0").then_some(plain);
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------- Signal

/// Signal's database secret when stored in clear (older versions). Newer
/// versions encrypt it with an Android Keystore key: pass it with `--signal-key`.
fn signal_secret(app: &Path) -> Option<String> {
    let b = std::fs::read(app.join("org.thoughtcrime.securesms/shared_prefs/org.thoughtcrime.securesms_preferences.xml")).ok()?;
    let root = crate::abx::parse(&b).ok()?;
    root.all("string").into_iter().find(|e| e.attr("name") == Some("pref_database_unencrypted_secret")).map(|e| e.text.trim().to_string()).filter(|s| !s.is_empty())
}

/// Decrypt a SQLCipher database (Signal settings first) into a plain copy.
// ponytail: no deleted-record recovery: freed pages stay encrypted.
pub fn sqlcipher_open(dir: &Path, name: &str, secret: &str) -> Option<Dbx> {
    let tmp = tempfile::tempdir().ok()?;
    std::fs::copy(dir.join(name), tmp.path().join("x.db")).ok()?;
    let _ = std::fs::copy(dir.join(format!("{name}-wal")), tmp.path().join("x.db-wal"));
    let plain = tmp.path().join("plain.db");
    for cfg in [&["PRAGMA cipher_page_size = 4096", "PRAGMA kdf_iter = 1"][..], &["PRAGMA cipher_compatibility = 3", "PRAGMA kdf_iter = 1"], &["PRAGMA cipher_compatibility = 3"], &[]] {
        let Ok(c) = rusqlite::Connection::open(tmp.path().join("x.db")) else { continue };
        if c.pragma_update(None, "key", secret).is_err() || cfg.iter().any(|s| c.execute_batch(s).is_err()) {
            continue;
        }
        if c.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).is_err() {
            continue;
        }
        let _ = std::fs::remove_file(&plain);
        let ok = c.execute(&format!("ATTACH DATABASE '{}' AS plaintext KEY ''", plain.display()), []).is_ok()
            && c.query_row("SELECT sqlcipher_export('plaintext')", [], |_| Ok(())).is_ok()
            && c.execute("DETACH DATABASE plaintext", []).is_ok();
        if ok {
            return comms::open(tmp.path(), "plain.db");
        }
    }
    None
}

fn pick(m: &BTreeMap<String, Val>, keys: &[&str]) -> String {
    keys.iter().map(|k| vs(m, k)).find(|s| !s.is_empty()).unwrap_or_default()
}

fn signal(db: &Dbx) -> Vec<Comm> {
    let recips: BTreeMap<i64, String> = rows(db, "SELECT * FROM recipient")
        .iter()
        .map(|m| {
            let name = pick(m, &["system_joined_name", "system_display_name", "profile_joined_name", "signal_profile_name", "system_given_name"]);
            let id = pick(m, &["e164", "phone", "aci", "uuid", "group_id"]);
            let label = match (id.is_empty(), name.is_empty()) {
                (false, false) => format!("{id} ({name})"),
                (true, _) => name,
                _ => id,
            };
            (vi(m, "_id"), label)
        })
        .collect();
    let threads: BTreeMap<i64, i64> = rows(db, "SELECT * FROM thread").iter().map(|m| (vi(m, "_id"), m.get("recipient_id").or(m.get("recipient_ids")).and_then(|v| v.int().or_else(|| v.text()?.split(',').next()?.trim().parse().ok())).unwrap_or(0))).collect();
    let mut att: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    for t in ["attachment", "part"] {
        for m in rows(db, &format!("SELECT * FROM {t}")) {
            let mid = m.get("message_id").or(m.get("mms_id")).or(m.get("mid")).and_then(Val::int).unwrap_or(0);
            att.entry(mid).or_default().push(format!("{} ({})", pick(&m, &["file_name", "data_file", "_data"]), pick(&m, &["content_type", "ct"])));
        }
    }
    let mut out = Vec::new();
    for t in ["message", "sms", "mms"] {
        if !db.has(t) {
            continue;
        }
        for m in rows(db, &format!("SELECT * FROM {t}")) {
            let ty = m.get("type").or(m.get("msg_box")).and_then(Val::int).unwrap_or(0);
            let base = ty & 0x1f;
            let (direction, call) = match base {
                21..=26 => ("out", None),
                2 | 11 => ("out", Some(if base == 11 { "video call" } else { "audio call" })),
                1 | 10 => ("in", Some(if base == 10 { "video call" } else { "audio call" })),
                3 | 8 => ("missed", Some(if base == 8 { "video call" } else { "audio call" })),
                _ => ("in", None),
            };
            let conv = recips.get(threads.get(&vi(&m, "thread_id")).unwrap_or(&0)).cloned().unwrap_or_default();
            let from = m.get("from_recipient_id").and_then(Val::int).and_then(|r| recips.get(&r)).cloned().unwrap_or_default();
            let peer = if direction == "in" && !from.is_empty() && from != conv { format!("{from} in {conv}") } else if conv.is_empty() { from } else { conv };
            let time = [vi(&m, "date_sent"), vi(&m, "date"), vi(&m, "date_received")].into_iter().find(|t| *t > 0).unwrap_or(0);
            out.push(Comm {
                time_ms: time,
                kind: "signal",
                direction: direction.into(),
                peer,
                text: call.map(String::from).unwrap_or_else(|| vs(&m, "body")),
                extra: att.get(&vi(&m, "_id")).map(|a| a.join("; ")).unwrap_or_default(),
                source: "signal.db (decrypted)".into(),
                recovered: false,
            });
        }
    }
    out
}

// ---------------------------------------------------------------- Google Maps

/// Integer coordinates are E6 or E7 depending on the table; tell by latitude.
// ponytail: an E7 latitude under 9° reads as E6; fine outside the tropics.
fn coords(lat: Option<&Val>, lon: Option<&Val>) -> Option<(f64, f64)> {
    let f = |v: &Val| match v {
        Val::Real(x) => Some((*x, true)),
        Val::Int(x) => Some((*x as f64, false)),
        _ => None,
    };
    let ((la, real), (lo, _)) = (f(lat?)?, f(lon?)?);
    let div = if real { 1.0 } else if la.abs() > 90e6 { 1e7 } else { 1e6 };
    let (la, lo) = (la / div, lo / div);
    (la.abs() <= 90.0 && lo.abs() <= 180.0 && (la, lo) != (0.0, 0.0)).then_some((la, lo))
}

fn location(time_ms: i64, place: String, address: String, ll: (f64, f64), source: &str) -> Comm {
    Comm { time_ms, kind: "location", direction: String::new(), peer: place, text: address, extra: format!("{:.6},{:.6}", ll.0, ll.1), source: source.into(), recovered: false }
}

fn maps(dir: &Path) -> Vec<Comm> {
    let mut out = Vec::new();
    if let Some(d) = comms::open(dir, "da_destination_history").filter(|d| d.has("destination_history")) {
        for m in rows(&d, "SELECT * FROM destination_history") {
            if let Some(ll) = coords(m.get("dest_lat"), m.get("dest_lng")) {
                out.push(location(to_ms(vi(&m, "time")), vs(&m, "dest_title"), vs(&m, "dest_address"), ll, "Google Maps navigation"));
            }
        }
    }
    if let Some(d) = comms::open(dir, "gmm_myplaces.db").filter(|d| d.has("sync_item")) {
        for m in rows(&d, "SELECT * FROM sync_item") {
            let Some(ll) = coords(m.get("latitude"), m.get("longitude")) else { continue };
            let s = match m.get("sync_item") {
                Some(Val::Blob(b)) => pb_strings(b),
                _ => Vec::new(),
            };
            let s: Vec<String> = s.into_iter().filter(|x| x.len() > 2 && x.contains(' ')).take(2).collect();
            out.push(location(to_ms(vi(&m, "timestamp")), s.first().cloned().unwrap_or_default(), s.get(1).cloned().unwrap_or_default(), ll, "Google Maps saved place"));
        }
    }
    out
}

// ---------------------------------------------------------------- Meta, Snapchat

/// Seconds / ms / µs / ns since 1970 → ms.
fn to_ms(t: i64) -> i64 {
    match t {
        t if t > 100_000_000_000_000_000 => t / 1_000_000,
        t if t > 100_000_000_000_000 => t / 1000,
        t if t > 100_000_000_000 => t,
        t => t * 1000,
    }
}

/// Messenger / Instagram "msys" databases (`msys_database_<own id>`).
fn msys(db: &Dbx, own: &str, app: &'static str, source: &str) -> Vec<Comm> {
    let (cols, _) = db.cols("messages");
    if !cols.iter().any(|c| c == "text") {
        return Vec::new();
    }
    let contacts: BTreeMap<String, String> = rows(db, "SELECT * FROM contacts").iter().map(|m| (val_str(m.get("id")), pick(m, &["name", "first_name", "username"]))).collect();
    let threads: BTreeMap<String, String> = rows(db, "SELECT * FROM threads").iter().map(|m| (val_str(m.get("thread_key")), pick(m, &["thread_name", "name"]))).collect();
    let f = |m: &BTreeMap<String, Val>, rec: bool| {
        let sender = val_str(m.get("sender_id"));
        let name = contacts.get(&sender).filter(|n| !n.is_empty()).map(|n| format!("{sender} ({n})")).unwrap_or(sender.clone());
        let thread = threads.get(&val_str(m.get("thread_key"))).cloned().unwrap_or_default();
        Comm {
            time_ms: to_ms(vi(m, "timestamp_ms")),
            kind: app,
            direction: if sender == own { "out".into() } else { "in".into() },
            peer: match (sender == own, thread.is_empty()) {
                (true, true) => format!("thread {}", val_str(m.get("thread_key"))),
                (true, false) => thread,
                (false, true) => name,
                (false, false) => format!("{name} in {thread}"),
            },
            text: vs(m, "text"),
            extra: String::new(),
            source: source.into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM messages").iter().map(|m| f(m, false)).collect();
    out.extend(db.deleted("messages", |m| vi(m, "timestamp_ms") > 1_000_000_000_000 && m.get("text").and_then(Val::text).is_some()).iter().map(|m| f(m, true)));
    out
}

fn val_str(v: Option<&Val>) -> String {
    match v {
        Some(Val::Int(i)) => i.to_string(),
        Some(Val::Text(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Messenger's older `threads_db2`: sender is a JSON object.
fn threads_db2(db: &Dbx) -> Vec<Comm> {
    if !db.has("messages") {
        return Vec::new();
    }
    let threads: BTreeMap<String, String> = rows(db, "SELECT thread_key, name FROM threads").iter().map(|m| (vs(m, "thread_key"), vs(m, "name"))).collect();
    let f = |m: &BTreeMap<String, Val>, rec: bool| {
        let s: serde_json::Value = serde_json::from_str(&vs(m, "sender")).unwrap_or_default();
        let who = format!("{} ({})", s["user_key"].as_str().unwrap_or(""), s["name"].as_str().unwrap_or(""));
        let thread = threads.get(&vs(m, "thread_key")).cloned().unwrap_or_default();
        Comm {
            time_ms: vi(m, "timestamp_ms"),
            kind: "messenger",
            direction: String::new(),
            peer: if thread.is_empty() { who } else { format!("{who} in {thread}") },
            text: vs(m, "text"),
            extra: String::new(),
            source: "threads_db2".into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM messages WHERE text IS NOT NULL").iter().map(|m| f(m, false)).collect();
    out.extend(db.deleted("messages", |m| vi(m, "timestamp_ms") > 1_000_000_000_000 && m.get("text").and_then(Val::text).is_some()).iter().map(|m| f(m, true)));
    out
}

/// Instagram `direct.db`: user names come from the threads' JSON.
fn instagram(db: &Dbx) -> Vec<Comm> {
    if !db.has("messages") {
        return Vec::new();
    }
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut viewer = String::new();
    fn walk(v: &serde_json::Value, names: &mut BTreeMap<String, String>, viewer: &mut String) {
        match v {
            serde_json::Value::Object(o) => {
                if let Some(u) = o.get("username").and_then(|u| u.as_str()) {
                    if let Some(id) = ["pk", "id", "pk_id"].iter().find_map(|k| o.get(*k)).map(|x| x.as_str().map(String::from).unwrap_or(x.to_string())) {
                        names.insert(id, u.to_string());
                    }
                }
                if let Some(x) = o.get("viewer_id") {
                    *viewer = x.as_str().map(String::from).unwrap_or(x.to_string());
                }
                o.values().for_each(|x| walk(x, names, viewer));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, names, viewer)),
            _ => {}
        }
    }
    for m in rows(db, "SELECT * FROM threads") {
        for c in ["thread_info", "recipients"] {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&vs(&m, c)) {
                walk(&v, &mut names, &mut viewer);
            }
        }
    }
    let f = |m: &BTreeMap<String, Val>, rec: bool| {
        let user = val_str(m.get("user_id"));
        let msg: serde_json::Value = serde_json::from_str(&vs(m, "message")).unwrap_or_default();
        let text = Some(vs(m, "text")).filter(|t| !t.is_empty()).or_else(|| msg["text"].as_str().map(String::from)).unwrap_or_default();
        Comm {
            time_ms: to_ms(vi(m, "timestamp")),
            kind: "instagram",
            direction: if !viewer.is_empty() && user == viewer { "out".into() } else { "in".into() },
            peer: if !viewer.is_empty() && user == viewer {
                names.iter().filter(|(id, _)| **id != viewer).map(|(id, n)| format!("{id} (@{n})")).collect::<Vec<_>>().join(", ")
            } else {
                names.get(&user).map(|n| format!("{user} (@{n})")).unwrap_or(user)
            },
            text,
            extra: format!("thread {} {}", val_str(m.get("thread_id")), vs(m, "message_type")).trim().to_string(),
            source: "direct.db".into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM messages").iter().map(|m| f(m, false)).collect();
    out.extend(db.deleted("messages", |m| vi(m, "timestamp") > 1_000_000_000 && (m.get("text").and_then(Val::text).is_some() || m.get("message").and_then(Val::text).is_some())).iter().map(|m| f(m, true)));
    out
}

/// Snapchat `arroyo.db`: message bodies are protobuf; text is the longest string.
fn snapchat(db: &Dbx, friends: &BTreeMap<String, String>) -> Vec<Comm> {
    if !db.has("conversation_message") {
        return Vec::new();
    }
    let own = rows(db, "SELECT key, value FROM required_values").iter().find(|m| vs(m, "key") == "USERID").map(|m| vs(m, "value")).unwrap_or_default();
    let is_id = |s: &str| s.len() >= 32 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    let f = |m: &BTreeMap<String, Val>, rec: bool| {
        let sender = val_str(m.get("sender_id"));
        let text = match m.get("message_content") {
            Some(Val::Blob(b)) => pb_strings(b).into_iter().filter(|s| !is_id(s)).max_by_key(|s| s.len()).unwrap_or_default(),
            _ => String::new(),
        };
        Comm {
            time_ms: to_ms(vi(m, "creation_timestamp")),
            kind: "snapchat",
            direction: if !own.is_empty() && sender == own { "out".into() } else { "in".into() },
            peer: friends.get(&sender).map(|n| format!("{sender} ({n})")).unwrap_or(sender),
            text,
            extra: format!("conversation {} · content type {}", val_str(m.get("client_conversation_id")), vi(m, "content_type")),
            source: "arroyo.db (text heuristic)".into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM conversation_message").iter().map(|m| f(m, false)).collect();
    out.extend(db.deleted("conversation_message", |m| vi(m, "creation_timestamp") > 1_000_000_000_000 && matches!(m.get("message_content"), Some(Val::Blob(_)))).iter().map(|m| f(m, true)));
    out
}

// ---------------------------------------------------------------- Gboard, Gmail, wallets

fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Main database files of a folder (skips -wal / -journal / -shm).
fn dbs(dir: &Path, pred: impl Fn(&str) -> bool) -> Vec<String> {
    files_in(dir)
        .iter()
        .filter_map(|p| p.file_name()?.to_str().map(String::from))
        .filter(|n| !n.ends_with("-wal") && !n.ends_with("-journal") && !n.ends_with("-shm") && pred(n))
        .collect()
}

fn gboard(dir: &Path) -> Vec<Comm> {
    let mut out = Vec::new();
    if let Some(d) = comms::open(dir, "gboard_clipboard.db") {
        for m in rows(&d, "SELECT * FROM clips") {
            out.push(Comm { time_ms: to_ms(vi(&m, "timestamp")), kind: "clipboard", direction: String::new(), peer: String::new(), text: vs(&m, "text"), extra: String::new(), source: "gboard_clipboard.db".into(), recovered: false });
        }
    }
    for name in dbs(dir, |n| n.starts_with("trainingcache")) {
        let Some(d) = comms::open(dir, &name) else { continue };
        let tables: Vec<String> = rows(&d, "SELECT name FROM sqlite_master WHERE type='table'").iter().map(|m| vs(m, "name")).collect();
        for t in tables {
            let (cols, _) = d.cols(&t);
            let Some(blob) = cols.iter().find(|c| c.contains("payload")) else { continue };
            let tcol = cols.iter().find(|c| c.contains("timestamp")).cloned().unwrap_or_default();
            for m in rows(&d, &format!("SELECT * FROM \"{t}\"")) {
                let Some(Val::Blob(b)) = m.get(blob.as_str()) else { continue };
                let mut seen = HashSet::new();
                let words: Vec<String> = pb_strings(b).into_iter().filter(|s| seen.insert(s.clone())).collect();
                if !words.is_empty() {
                    out.push(Comm { time_ms: to_ms(vi(&m, &tcol)), kind: "keyboard", direction: String::new(), peer: String::new(), text: words.join(" "), extra: String::new(), source: format!("{name} (typed text, heuristic)"), recovered: false });
                }
            }
        }
    }
    out
}

fn gmail(dir: &Path) -> Vec<Comm> {
    let mut out = Vec::new();
    for name in dbs(dir, |n| n.starts_with("mailstore.") && n.ends_with(".db")) {
        let Some(d) = comms::open(dir, &name) else { continue };
        for m in rows(&d, "SELECT * FROM messages") {
            out.push(Comm {
                time_ms: [vi(&m, "dateSentMs"), vi(&m, "dateReceivedMs")].into_iter().max().unwrap_or(0),
                kind: "email",
                direction: String::new(),
                peer: format!("{} → {}", vs(&m, "fromAddress"), vs(&m, "toAddresses")),
                text: [vs(&m, "subject"), vs(&m, "snippet")].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" — "),
                extra: String::new(),
                source: name.clone(),
                recovered: false,
            });
        }
    }
    for name in dbs(dir, |n| n.starts_with("bigTopDataDB")) {
        let Some(d) = comms::open(dir, &name) else { continue };
        let (cols, _) = d.cols("item_messages");
        let Some(blob) = cols.iter().find(|c| c.contains("proto")) else { continue };
        for m in rows(&d, "SELECT * FROM item_messages") {
            let Some(Val::Blob(b)) = m.get(blob.as_str()) else { continue };
            let mut raw = Vec::new();
            let b = if std::io::Read::read_to_end(&mut flate2::read::ZlibDecoder::new(&b[..]), &mut raw).is_ok() { raw } else { b.clone() };
            let s = pb_strings(&b);
            let (mails, other): (Vec<String>, Vec<String>) = s.into_iter().partition(|x| x.contains('@') && !x.contains(' '));
            let mut seen = HashSet::new();
            let mails: Vec<String> = mails.into_iter().filter(|x| seen.insert(x.clone())).collect();
            out.push(Comm {
                time_ms: to_ms(cols.iter().find(|c| c.contains("timestamp")).map(|c| vi(&m, c)).unwrap_or(0)),
                kind: "email",
                direction: String::new(),
                peer: mails.join(", "),
                text: other.into_iter().filter(|x| x.len() > 3 && x.contains(' ')).take(2).collect::<Vec<_>>().join(" — "),
                extra: String::new(),
                source: format!("{name} (heuristic)"),
                recovered: false,
            });
        }
    }
    out
}

fn wallets(app: &Path) -> Vec<Comm> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (pkg, name) in WALLETS {
        for p in files_in(&app.join(pkg)) {
            let Ok(b) = std::fs::read(&p) else { continue };
            let text = String::from_utf8_lossy(&b);
            for (kind, v) in crate::search::entities(&text, false) {
                if matches!(kind, "bitcoin" | "ethereum") && seen.insert(v.clone()) {
                    let rel = p.strip_prefix(app).unwrap_or(&p).to_string_lossy().into_owned();
                    out.push(Comm { time_ms: 0, kind: "wallet", direction: String::new(), peer: v, text: format!("{name} ({kind})"), extra: rel, source: "wallet app data".into(), recovered: false });
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------- entry point

/// Keys an examiner supplies (from the lab extraction or the user).
#[derive(Default, Clone)]
pub struct Keys {
    /// Signal database secret (hex), when not stored in clear.
    pub signal: Option<String>,
    /// WhatsApp 64-digit end-to-end backup key (hex) or raw 32-byte key.
    pub whatsapp: Option<String>,
    /// Signal backup passphrase (30 digits, shown when backups are turned on).
    pub signal_passphrase: Option<String>,
}

/// Decrypt every Signal `.backup` of the case: (file name, database, decoded).
fn signal_backups(app: &Path, pass: Option<&str>, notes: &mut Vec<String>) -> Vec<(String, Dbx, crate::signal_backup::Decoded)> {
    let dir = app.join("org.thoughtcrime.securesms/backups");
    let mut out = Vec::new();
    for n in dbs(&dir, is_signal_backup) {
        let Some(pass) = pass else {
            notes.push(format!("Signal backup {n}: needs its 30-digit passphrase (`apex comms --signal-passphrase`)"));
            continue;
        };
        let d = match std::fs::read(dir.join(&n)).map_err(|e| e.to_string()).and_then(|b| crate::signal_backup::decrypt(&b, pass)) {
            Ok(d) => d,
            Err(e) => {
                notes.push(format!("Signal backup {n}: {e}"));
                continue;
            }
        };
        let Ok(tmp) = tempfile::tempdir() else { continue };
        match crate::signal_backup::to_sqlite(&d, &tmp.path().join("s.db")) {
            Ok(failed) if failed > 0 => notes.push(format!("Signal backup {n}: {failed} SQL statement(s) not replayed (internal or full-text tables)")),
            Ok(_) => {}
            Err(e) => {
                notes.push(format!("Signal backup {n}: {e}"));
                continue;
            }
        }
        if let Some(db) = comms::open(tmp.path(), "s.db") {
            out.push((n, db, d));
        }
    }
    out
}

/// Write the files carried by Signal backups (attachments, avatars, stickers) into `dir`.
pub fn export_signal_files(case_root: &Path, pass: Option<&str>, dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut written = Vec::new();
    for (n, _, d) in signal_backups(&case_root.join("comms/app"), pass, &mut Vec::new()) {
        let base = dir.join("signal_files").join(n.trim_end_matches(".backup"));
        for f in &d.files {
            let p = base.join(f.kind).join(format!("{}.{}", f.id.replace(['/', '\\'], "_"), crate::signal_backup::ext(&f.data)));
            std::fs::create_dir_all(p.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(&p, &f.data).map_err(|e| format!("{}: {e}", p.display()))?;
            written.push(p);
        }
    }
    Ok(written)
}

/// App-data records in `<case>/comms/app/`. `live_wa` (from msgstore.db)
/// marks backup messages missing from it as recovered (deleted since).
pub fn load(comms_dir: &Path, keys: &Keys, live_wa: &[Comm], wa_names: &BTreeMap<String, String>) -> (Vec<Comm>, Vec<String>) {
    let app = comms_dir.join("app");
    let mut out = Vec::new();
    let mut notes = Vec::new();
    if !app.is_dir() {
        return (out, notes);
    }
    let sig = app.join("org.thoughtcrime.securesms/databases");
    let mut live_sig: Vec<Comm> = Vec::new();
    if sig.join("signal.db").exists() {
        match keys.signal.clone().or_else(|| signal_secret(&app)).and_then(|k| sqlcipher_open(&sig, "signal.db", &k)) {
            Some(d) => live_sig = signal(&d),
            None => notes.push("Signal: database encrypted with a Keystore-protected secret; pass it with `apex comms --signal-key <hex>`".into()),
        }
    }
    {
        let live: HashSet<(i64, String)> = live_sig.iter().map(|c| (c.time_ms, c.text.clone())).collect();
        let mut seen = HashSet::new();
        for (n, db, _) in signal_backups(&app, keys.signal_passphrase.as_deref(), &mut notes) {
            for mut c in signal(&db) {
                if !seen.insert((c.time_ms, c.text.clone(), c.peer.clone())) || live.contains(&(c.time_ms, c.text.clone())) {
                    continue;
                }
                c.recovered = !live_sig.is_empty();
                c.source = format!("Signal backup {n}");
                out.push(c);
            }
        }
    }
    out.extend(live_sig);
    for pkg in ["com.whatsapp", "com.whatsapp.w4b"] {
        let bk = app.join(pkg).join("backups");
        let names = dbs(&bk, is_wa_backup);
        if names.is_empty() {
            continue;
        }
        let key_file = std::fs::read(app.join(pkg).join("files/key")).ok();
        let mut keys = wa_keys(key_file.as_deref(), keys.whatsapp.as_deref());
        // encrypted_backup.key: Java-serialized 32-byte root key (last 32 bytes).
        if let Some(r) = std::fs::read(app.join(pkg).join("files/encrypted_backup.key")).ok().filter(|r| r.len() >= 32) {
            keys.push(wa_e2e_key(&r[r.len() - 32..]));
        }
        let live: HashSet<(i64, String)> = live_wa.iter().map(|c| (c.time_ms, c.text.clone())).collect();
        let mut seen = HashSet::new();
        for n in names {
            let Some(plain) = std::fs::read(bk.join(&n)).ok().and_then(|f| wa_decrypt(&f, &keys)) else {
                notes.push(format!("WhatsApp backup {n}: no working key (needs files/key or files/encrypted_backup.key from an extraction, or the 64-digit key: `--wa-key`)"));
                continue;
            };
            let Ok(tmp) = tempfile::tempdir() else { continue };
            if std::fs::write(tmp.path().join("m.db"), plain).is_err() {
                continue;
            }
            let Some(d) = comms::open(tmp.path(), "m.db") else { continue };
            for mut c in comms::whatsapp(&d, wa_names) {
                if !seen.insert((c.time_ms, c.text.clone(), c.peer.clone())) || (!live_wa.is_empty() && live.contains(&(c.time_ms, c.text.clone()))) {
                    continue;
                }
                c.recovered = c.recovered || !live_wa.is_empty();
                c.source = format!("backup {n}");
                out.push(c);
            }
        }
    }
    out.extend(maps(&app.join("com.google.android.apps.maps/databases")));
    for (pkg, kind) in [("com.facebook.orca", "messenger"), ("com.instagram.android", "instagram")] {
        let dir = app.join(pkg).join("databases");
        for n in dbs(&dir, |n| n.starts_with("msys_database_")) {
            let own = n.trim_start_matches("msys_database_").trim_end_matches(".db").to_string();
            if let Some(d) = comms::open(&dir, &n) {
                out.extend(msys(&d, &own, kind, &n));
            }
        }
    }
    if let Some(d) = comms::open(&app.join("com.facebook.orca/databases"), "threads_db2") {
        out.extend(threads_db2(&d));
    }
    if let Some(d) = comms::open(&app.join("com.instagram.android/databases"), "direct.db") {
        out.extend(instagram(&d));
    }
    let snap = app.join("com.snapchat.android/databases");
    let friends: BTreeMap<String, String> = comms::open(&snap, "main.db")
        .map(|d| rows(&d, "SELECT * FROM Friend").iter().map(|m| (pick(m, &["userId", "user_id"]), [pick(m, &["displayName", "display_name"]), pick(m, &["username"])].into_iter().filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" @"))).collect())
        .unwrap_or_default();
    if let Some(d) = comms::open(&snap, "arroyo.db") {
        out.extend(snapchat(&d, &friends));
    }
    out.extend(gboard(&app.join("com.google.android.inputmethod.latin/databases")));
    out.extend(gmail(&app.join("com.google.android.gm/databases")));
    out.extend(wallets(&app));
    (out, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb_field(n: u8, b: &[u8]) -> Vec<u8> {
        let mut v = vec![(n << 3) | 2, b.len() as u8];
        v.extend(b);
        v
    }

    #[test]
    fn targets() {
        assert_eq!(target("data/user/0/org.thoughtcrime.securesms/databases/signal.db", 1).as_deref(), Some("comms/app/org.thoughtcrime.securesms/databases/signal.db"));
        assert_eq!(target("data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore-2026-01-01.1.db.crypt15", 1).as_deref(), Some("comms/app/com.whatsapp/backups/msgstore-2026-01-01.1.db.crypt15"));
        assert_eq!(target("data/data/com.wallet.crypto.trustapp/shared_prefs/a.xml", 10).as_deref(), Some("comms/app/com.wallet.crypto.trustapp/shared_prefs/a.xml"));
        assert_eq!(target("data/data/com.wallet.crypto.trustapp/cache/x", 10), None);
        assert_eq!(target("data/data/com.whatsapp/files/other", 10), None);
        assert!(target("data/user/0/com.whatsapp/files/encrypted_backup.key", 59).is_some());
        assert_eq!(target("data/media/0/Signal/Backups/signal-2026-11-07-10-00-00.backup", 9).as_deref(), Some("comms/app/org.thoughtcrime.securesms/backups/signal-2026-11-07-10-00-00.backup"));
    }

    #[test]
    fn protobuf_strings() {
        let inner = [pb_field(1, b"salut on se voit a 20h"), pb_field(2, &[0xff, 0xfe])].concat();
        let msg = [vec![0x08, 0x01], pb_field(3, &inner)].concat();
        assert_eq!(pb_strings(&msg), vec!["salut on se voit a 20h".to_string()]);
    }

    #[test]
    fn crypt15_roundtrip() {
        use aes_gcm::aead::consts::U16;
        use aes_gcm::aead::{AeadInPlace, KeyInit};
        type Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes256, U16>;
        let root = [7u8; 32];
        let key = wa_e2e_key(&root);
        let iv = [9u8; 16];
        let mut db = b"SQLite format 3\0".to_vec();
        db.extend([0u8; 100]);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, &db).unwrap();
        let mut buf = z.finish().unwrap();
        let tag = Gcm::new((&key).into()).encrypt_in_place_detached((&iv).into(), b"", &mut buf).unwrap();
        let proto = [vec![0x08, 0x01], pb_field(3, &pb_field(1, &iv))].concat();
        let mut file = vec![proto.len() as u8, 1];
        file.extend(&proto);
        file.extend(&buf);
        file.extend(tag);
        file.extend([0u8; 16]); // md5
        let hexkey: String = root.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(wa_decrypt(&file, &wa_keys(None, Some(&hexkey))).unwrap(), db);
        assert!(wa_decrypt(&file, &wa_keys(Some(&[1u8; 158]), None)).is_none());
    }

    #[test]
    fn signal_sqlcipher() {
        let d = tempfile::tempdir().unwrap();
        let c = rusqlite::Connection::open(d.path().join("signal.db")).unwrap();
        c.pragma_update(None, "key", "00ff").unwrap();
        c.execute_batch(
            "PRAGMA cipher_page_size = 4096; PRAGMA kdf_iter = 1;
             CREATE TABLE recipient(_id INTEGER PRIMARY KEY, e164 TEXT, system_joined_name TEXT);
             CREATE TABLE thread(_id INTEGER PRIMARY KEY, recipient_id INTEGER);
             CREATE TABLE message(_id INTEGER PRIMARY KEY, date_sent INTEGER, type INTEGER, body TEXT, thread_id INTEGER, from_recipient_id INTEGER);
             INSERT INTO recipient VALUES (2, '+33612345678', 'Dédé');
             INSERT INTO thread VALUES (1, 2);
             INSERT INTO message VALUES (1, 1700000000000, 10485780, 'le colis est arrivé', 1, 2);
             INSERT INTO message VALUES (2, 1700000060000, 10485783, 'ok j arrive', 1, 1);",
        )
        .unwrap();
        drop(c);
        assert!(sqlcipher_open(d.path(), "signal.db", "bad").is_none());
        let db = sqlcipher_open(d.path(), "signal.db", "00ff").unwrap();
        let m = signal(&db);
        assert_eq!(m.len(), 2);
        assert_eq!((m[0].direction.as_str(), m[0].peer.as_str(), m[0].text.as_str()), ("in", "+33612345678 (Dédé)", "le colis est arrivé"));
        assert_eq!(m[1].direction, "out");
    }

    #[test]
    fn coordinates() {
        assert_eq!(coords(Some(&Val::Int(48_858_370)), Some(&Val::Int(2_294_481))), Some((48.85837, 2.294481)));
        assert_eq!(coords(Some(&Val::Int(488_583_700)), Some(&Val::Int(22_944_810))), Some((48.85837, 2.294481)));
        assert_eq!(coords(Some(&Val::Real(48.8)), Some(&Val::Real(2.3))), Some((48.8, 2.3)));
        assert_eq!(to_ms(1_700_000_000), 1_700_000_000_000);
        assert_eq!(to_ms(1_700_000_000_000_000), 1_700_000_000_000);
    }
}
