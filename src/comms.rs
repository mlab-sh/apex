//! Communications, **only under a legal mandate** (`--mandate <reference>`):
//! SMS, MMS (text + attachments), call log, contacts, WhatsApp, Telegram,
//! Chrome history and downloads.
//!
//! Sources, all under `<case>/comms/`:
//! - live (`device acquire --mandate`): `content query` of the SMS / MMS /
//!   call-log providers (readable by the shell user without root; contacts
//!   usually are not), MMS attachments via `content read`;
//! - extraction (`import --mandate`): the app databases themselves, copied
//!   with their WAL, so deleted rows are recovered too (`sqlite_carve`).
//!
//! Everything is normalized into one list of `Comm` rows (CSV / JSON export,
//! timeline). Parsers are best-effort across Android / app versions.

use crate::case::{Case, Event};
use crate::sqlite_carve::{self, Val};
use serde_json::json;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub struct Comm {
    /// Epoch milliseconds (0 when unknown, e.g. contacts).
    pub time_ms: i64,
    /// sms, mms, call, whatsapp, telegram, web, download, contact.
    pub kind: &'static str,
    /// in, out, missed, rejected, blocked, voicemail, draft… or "".
    pub direction: String,
    pub peer: String,
    pub text: String,
    /// Duration, attachment, page title…
    pub extra: String,
    pub source: String,
    /// From a deleted record (WAL / freelist) or a contact flagged deleted.
    pub recovered: bool,
}

// ---------------------------------------------------------------- live acquisition

pub const SMS_COLS: &str = "_id:thread_id:address:date:date_sent:type:read:body";
pub const MMS_COLS: &str = "_id:thread_id:date:msg_box:read:sub";
pub const PART_COLS: &str = "_id:mid:ct:text:name:cl";
pub const CALL_COLS: &str = "_id:number:date:duration:type:name:geocoded_location";
pub const CONTACT_COLS: &str = "display_name:data1";
pub const CAL_COLS: &str = "_id:title:dtstart:dtend:eventLocation:description:organizer:deleted";

/// Shell commands for a live mandate acquisition: (file, command).
pub fn live_commands() -> Vec<(&'static str, String)> {
    vec![
        ("sms.txt", format!("content query --uri content://sms --projection {SMS_COLS}")),
        ("mms.txt", format!("content query --uri content://mms --projection {MMS_COLS}")),
        ("mms_part.txt", format!("content query --uri content://mms/part --projection {PART_COLS}")),
        (
            "mms_addr.txt",
            "content query --uri content://mms --projection _id | sed -n 's/.*_id=\\([0-9]*\\).*/\\1/p' | while read id; do echo \"## $id\"; content query --uri content://mms/$id/addr --projection address:type; done".into(),
        ),
        ("calls.txt", format!("content query --uri content://call_log/calls --projection {CALL_COLS}")),
        ("contacts.txt", format!("content query --uri content://com.android.contacts/data/phones --projection {CONTACT_COLS}")),
        ("calendar.txt", format!("content query --uri content://com.android.calendar/events --projection {CAL_COLS}")),
    ]
}

/// `content query` output → rows as key → value, using the projection order to
/// split values that contain ", " or newlines.
pub fn parse_content_query(text: &str, cols: &str) -> Vec<BTreeMap<String, String>> {
    let keys: Vec<&str> = cols.split(':').collect();
    let mut rows: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Row: ") {
            rows.push(rest.split_once(' ').map(|(_, r)| r).unwrap_or("").to_string());
        } else if let Some(last) = rows.last_mut() {
            last.push('\n');
            last.push_str(line);
        }
    }
    rows.into_iter()
        .map(|r| {
            let mut m = BTreeMap::new();
            let mut pos = 0;
            for (i, k) in keys.iter().enumerate() {
                let start_pat = format!("{k}=");
                let Some(s) = r[pos..].find(&start_pat).map(|x| pos + x + start_pat.len()) else { continue };
                let end = keys[i + 1..].iter().find_map(|n| r[s..].find(&format!(", {n}=")).map(|x| s + x)).unwrap_or(r.len());
                let v = r[s..end].to_string();
                if v != "NULL" {
                    m.insert(k.to_string(), v);
                }
                pos = end;
            }
            m
        })
        .collect()
}

/// Part ids of MMS attachments (not text, not SMIL) from `mms_part.txt`.
pub fn attachment_parts(text: &str) -> Vec<(String, String)> {
    parse_content_query(text, PART_COLS)
        .into_iter()
        .filter(|r| r.get("ct").is_some_and(|c| c != "text/plain" && c != "application/smil"))
        .filter_map(|r| Some((r.get("_id")?.clone(), part_name(&r))))
        .collect()
}

/// File name an attachment is saved under in `comms/mms_parts/`: `<id>_<name>`.
fn part_name(r: &BTreeMap<String, String>) -> String {
    let id = r.get("_id").cloned().unwrap_or_default();
    r.get("name").or(r.get("cl")).cloned().unwrap_or_else(|| format!("part{id}")).replace(['/', '\\'], "_")
}

fn sms_dir(t: i64) -> &'static str {
    match t {
        1 => "in",
        2 => "out",
        3 => "draft",
        4 => "outbox",
        5 => "failed",
        6 => "queued",
        _ => "",
    }
}

fn call_dir(t: i64) -> &'static str {
    match t {
        1 => "in",
        2 => "out",
        3 => "missed",
        4 => "voicemail",
        5 => "rejected",
        6 => "blocked",
        7 => "answered elsewhere",
        _ => "",
    }
}

/// Google's public holiday calendars, subscribed by default: not the phone owner's events.
fn public_calendar(organizer: &str) -> bool {
    organizer.contains("#holiday@group.v.calendar.google.com")
}

fn calendar_row(start: i64, title: &str, place: &str, desc: &str, organizer: &str, deleted: bool, source: &str) -> Comm {
    Comm {
        time_ms: start,
        kind: "calendar",
        direction: String::new(),
        peer: organizer.to_string(),
        text: [title, desc].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" — "),
        extra: place.to_string(),
        source: source.into(),
        recovered: deleted,
    }
}

fn live(dir: &Path) -> Vec<Comm> {
    let rd = |f: &str| std::fs::read_to_string(dir.join(f)).unwrap_or_default();
    let mut out = Vec::new();
    let n = |m: &BTreeMap<String, String>, k: &str| m.get(k).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
    let s = |m: &BTreeMap<String, String>, k: &str| m.get(k).cloned().unwrap_or_default();
    for r in parse_content_query(&rd("sms.txt"), SMS_COLS) {
        out.push(Comm { time_ms: n(&r, "date"), kind: "sms", direction: sms_dir(n(&r, "type")).into(), peer: s(&r, "address"), text: s(&r, "body"), extra: String::new(), source: "content://sms".into(), recovered: false });
    }
    // MMS: text parts and addresses by message id.
    let parts = parse_content_query(&rd("mms_part.txt"), PART_COLS);
    let mut addr: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    let mut cur = String::new();
    for l in rd("mms_addr.txt").lines() {
        if let Some(id) = l.strip_prefix("## ") {
            cur = id.trim().to_string();
        } else if l.starts_with("Row: ") {
            let r = parse_content_query(l, "address:type").pop().unwrap_or_default();
            addr.entry(cur.clone()).or_default().push((s(&r, "address"), s(&r, "type")));
        }
    }
    for r in parse_content_query(&rd("mms.txt"), MMS_COLS) {
        let id = s(&r, "_id");
        let out_box = n(&r, "msg_box") == 2;
        let text: Vec<String> = parts.iter().filter(|p| p.get("mid") == Some(&id) && p.get("ct").map(String::as_str) == Some("text/plain")).filter_map(|p| p.get("text").cloned()).collect();
        let files: Vec<String> = parts.iter().filter(|p| p.get("mid") == Some(&id) && p.get("ct").is_some_and(|c| c != "text/plain" && c != "application/smil")).map(|p| format!("comms/mms_parts/{}_{} ({})", s(p, "_id"), part_name(p), s(p, "ct"))).collect();
        // 137 = from, 151 = to.
        let want = if out_box { "151" } else { "137" };
        let peer = addr.get(&id).into_iter().flatten().filter(|(_, t)| t == want).map(|(a, _)| a.clone()).collect::<Vec<_>>().join(", ");
        out.push(Comm { time_ms: n(&r, "date") * 1000, kind: "mms", direction: if out_box { "out".into() } else { "in".into() }, peer, text: text.join("\n"), extra: files.join("; "), source: "content://mms".into(), recovered: false });
    }
    for r in parse_content_query(&rd("calls.txt"), CALL_COLS) {
        let name = s(&r, "name");
        out.push(Comm {
            time_ms: n(&r, "date"),
            kind: "call",
            direction: call_dir(n(&r, "type")).into(),
            peer: if name.is_empty() { s(&r, "number") } else { format!("{} ({name})", s(&r, "number")) },
            text: String::new(),
            extra: format!("{}s{}", n(&r, "duration"), r.get("geocoded_location").map(|g| format!(", {g}")).unwrap_or_default()),
            source: "content://call_log".into(),
            recovered: false,
        });
    }
    for r in parse_content_query(&rd("calendar.txt"), CAL_COLS).into_iter().filter(|r| !public_calendar(&s(r, "organizer"))) {
        out.push(calendar_row(n(&r, "dtstart"), &s(&r, "title"), &s(&r, "eventLocation"), &s(&r, "description"), &s(&r, "organizer"), n(&r, "deleted") == 1, "content://com.android.calendar"));
    }
    for r in parse_content_query(&rd("contacts.txt"), CONTACT_COLS) {
        out.push(Comm { time_ms: 0, kind: "contact", direction: String::new(), peer: s(&r, "data1"), text: s(&r, "display_name"), extra: String::new(), source: "content://com.android.contacts".into(), recovered: false });
    }
    out
}

// ---------------------------------------------------------------- databases (extractions)

/// Database files an `import --mandate` copies: (path in the extraction, name in comms/db/).
pub const DATABASES: &[(&str, &str)] = &[
    ("data/user_de/0/com.android.providers.telephony/databases/mmssms.db", "mmssms.db"),
    ("data/data/com.android.providers.telephony/databases/mmssms.db", "mmssms.db"),
    ("data/user_de/0/com.android.providers.contacts/databases/calllog.db", "calllog.db"),
    ("data/data/com.android.providers.contacts/databases/contacts2.db", "contacts2.db"),
    ("data/data/com.whatsapp/databases/msgstore.db", "msgstore.db"),
    ("data/data/com.whatsapp/databases/wa.db", "wa.db"),
    ("data/data/org.telegram.messenger/files/cache4.db", "cache4.db"),
    ("data/data/org.telegram.messenger.web/files/cache4.db", "cache4.db"),
    ("data/data/com.android.chrome/app_chrome/Default/History", "chrome_history.db"),
    ("data/data/com.android.providers.calendar/databases/calendar.db", "calendar.db"),
];

/// MMS attachment files in an extraction.
pub const MMS_PARTS_DIR: &str = "data/user_de/0/com.android.providers.telephony/app_parts/";

/// `data/user/0/x` is `data/data/x`.
pub fn db_name(rel: &str) -> Option<(&'static str, String)> {
    let r = rel.replacen("data/user/0/", "data/data/", 1);
    for (p, name) in DATABASES {
        for ext in ["", "-wal", "-journal"] {
            if r == format!("{p}{ext}") {
                return Some((name, ext.to_string()));
            }
        }
    }
    None
}

/// An opened copy of a database + its live rowids and carved records.
pub struct Dbx {
    conn: rusqlite::Connection,
    main: Vec<u8>,
    wal: Option<Vec<u8>>,
    _tmp: tempfile::TempDir,
}

pub fn open(dir: &Path, name: &str) -> Option<Dbx> {
    let main = std::fs::read(dir.join(name)).ok()?;
    let wal = std::fs::read(dir.join(format!("{name}-wal"))).ok();
    // Work on a temp copy: opening applies the WAL, which must not touch the evidence.
    let tmp = tempfile::tempdir().ok()?;
    std::fs::write(tmp.path().join("x.db"), &main).ok()?;
    if let Some(w) = &wal {
        std::fs::write(tmp.path().join("x.db-wal"), w).ok()?;
    }
    let conn = rusqlite::Connection::open(tmp.path().join("x.db")).ok()?;
    Some(Dbx { conn, main, wal, _tmp: tmp })
}

impl Dbx {
    pub fn has(&self, table: &str) -> bool {
        self.conn.query_row("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1", [table], |_| Ok(())).is_ok()
    }

    /// Column names, and the INTEGER PRIMARY KEY column (stored as NULL in records).
    pub fn cols(&self, table: &str) -> (Vec<String>, Option<usize>) {
        let mut st = match self.conn.prepare(&format!("PRAGMA table_info({table})")) {
            Ok(s) => s,
            Err(_) => return (Vec::new(), None),
        };
        let rows: Vec<(String, String, i64)> = st.query_map([], |r| Ok((r.get(1)?, r.get(2)?, r.get(5)?))).map(|it| it.flatten().collect()).unwrap_or_default();
        let ipk = rows.iter().position(|(_, t, pk)| *pk == 1 && t.eq_ignore_ascii_case("INTEGER"));
        (rows.into_iter().map(|r| r.0).collect(), ipk)
    }

    /// Deleted rows of `table`: carved records with the table's column count
    /// whose rowid is gone, as column → value.
    pub fn deleted(&self, table: &str, check: impl Fn(&BTreeMap<String, Val>) -> bool) -> Vec<BTreeMap<String, Val>> {
        let (cols, ipk) = self.cols(table);
        if cols.is_empty() {
            return Vec::new();
        }
        let live: HashSet<i64> = self
            .conn
            .prepare(&format!("SELECT rowid FROM {table}"))
            .and_then(|mut s| s.query_map([], |r| r.get(0)).map(|it| it.flatten().collect()))
            .unwrap_or_default();
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for c in sqlite_carve::carve(&self.main, self.wal.as_deref()) {
            // Columns added later (ALTER TABLE) are missing from older records.
            if c.values.len() > cols.len() || c.values.len() + 3 < cols.len() || live.contains(&c.rowid) || !seen.insert(c.rowid) {
                continue;
            }
            let mut m: BTreeMap<String, Val> = cols.iter().cloned().zip(c.values).collect();
            if let Some(i) = ipk {
                m.insert(cols[i].clone(), Val::Int(c.rowid));
            }
            if check(&m) {
                out.push(m);
            } else {
                seen.remove(&c.rowid);
            }
        }
        out
    }
}

pub fn vi(m: &BTreeMap<String, Val>, k: &str) -> i64 {
    m.get(k).and_then(Val::int).unwrap_or(0)
}
pub fn vs(m: &BTreeMap<String, Val>, k: &str) -> String {
    m.get(k).and_then(|v| v.text().map(String::from)).unwrap_or_default()
}

/// Rows of a query as column → value.
pub fn rows(db: &Dbx, sql: &str) -> Vec<BTreeMap<String, Val>> {
    let Ok(mut st) = db.conn.prepare(sql) else { return Vec::new() };
    let names: Vec<String> = st.column_names().iter().map(|s| s.to_string()).collect();
    st.query_map([], |r| {
        let mut m = BTreeMap::new();
        for (i, n) in names.iter().enumerate() {
            let v = match r.get_ref(i)? {
                rusqlite::types::ValueRef::Null => Val::Null,
                rusqlite::types::ValueRef::Integer(x) => Val::Int(x),
                rusqlite::types::ValueRef::Real(x) => Val::Real(x),
                rusqlite::types::ValueRef::Text(t) => Val::Text(String::from_utf8_lossy(t).into_owned()),
                rusqlite::types::ValueRef::Blob(b) => Val::Blob(b.to_vec()),
            };
            m.insert(n.clone(), v);
        }
        Ok(m)
    })
    .map(|it| it.flatten().collect())
    .unwrap_or_default()
}

fn mmssms(db: &Dbx) -> Vec<Comm> {
    let mut out = Vec::new();
    let sms = |m: &BTreeMap<String, Val>, rec: bool| Comm {
        time_ms: vi(m, "date"),
        kind: "sms",
        direction: sms_dir(vi(m, "type")).into(),
        peer: vs(m, "address"),
        text: vs(m, "body"),
        extra: String::new(),
        source: "mmssms.db".into(),
        recovered: rec,
    };
    out.extend(rows(db, "SELECT * FROM sms").iter().map(|m| sms(m, false)));
    out.extend(db.deleted("sms", |m| vi(m, "date") > 1_000_000_000_000 && (m.get("body").and_then(Val::text).is_some() || m.get("address").and_then(Val::text).is_some())).iter().map(|m| sms(m, true)));
    if db.has("pdu") {
        let parts = rows(db, "SELECT mid, ct, text, _data, name FROM part");
        let addr = rows(db, "SELECT msg_id, address, type FROM addr");
        for m in rows(db, "SELECT _id, date, msg_box FROM pdu") {
            let id = vi(&m, "_id");
            let ob = vi(&m, "msg_box") == 2;
            let want = if ob { 151 } else { 137 };
            let mine = |p: &&BTreeMap<String, Val>| vi(p, "mid") == id;
            out.push(Comm {
                time_ms: vi(&m, "date") * 1000,
                kind: "mms",
                direction: if ob { "out".into() } else { "in".into() },
                peer: addr.iter().filter(|a| vi(a, "msg_id") == id && vi(a, "type") == want).map(|a| vs(a, "address")).collect::<Vec<_>>().join(", "),
                text: parts.iter().filter(mine).filter(|p| vs(p, "ct") == "text/plain").map(|p| vs(p, "text")).collect::<Vec<_>>().join("\n"),
                extra: parts.iter().filter(mine).filter(|p| !matches!(vs(p, "ct").as_str(), "text/plain" | "application/smil")).map(|p| format!("{} ({})", vs(p, "_data").rsplit('/').next().unwrap_or(""), vs(p, "ct"))).collect::<Vec<_>>().join("; "),
                source: "mmssms.db".into(),
                recovered: false,
            });
        }
    }
    out
}

fn calls(db: &Dbx, name: &str) -> Vec<Comm> {
    if !db.has("calls") {
        return Vec::new();
    }
    let c = |m: &BTreeMap<String, Val>, rec: bool| {
        let n = vs(m, "name");
        Comm {
            time_ms: vi(m, "date"),
            kind: "call",
            direction: call_dir(vi(m, "type")).into(),
            peer: if n.is_empty() { vs(m, "number") } else { format!("{} ({n})", vs(m, "number")) },
            text: String::new(),
            extra: format!("{}s", vi(m, "duration")),
            source: name.into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM calls").iter().map(|m| c(m, false)).collect();
    out.extend(db.deleted("calls", |m| vi(m, "date") > 1_000_000_000_000 && m.get("number").and_then(Val::text).is_some()).iter().map(|m| c(m, true)));
    out
}

fn contacts(db: &Dbx) -> Vec<Comm> {
    rows(
        db,
        "SELECT r.display_name AS name, d.data1 AS value, mt.mimetype AS mt, r.deleted AS deleted FROM data d \
         JOIN raw_contacts r ON d.raw_contact_id = r._id JOIN mimetypes mt ON d.mimetype_id = mt._id \
         WHERE mt.mimetype IN ('vnd.android.cursor.item/phone_v2', 'vnd.android.cursor.item/email_v2')",
    )
    .iter()
    .map(|m| Comm {
        time_ms: 0,
        kind: "contact",
        direction: String::new(),
        peer: vs(m, "value"),
        text: vs(m, "name"),
        extra: if vs(m, "mt").ends_with("email_v2") { "email".into() } else { "phone".into() },
        source: "contacts2.db".into(),
        recovered: vi(m, "deleted") == 1,
    })
    .collect()
}

pub fn whatsapp(db: &Dbx, names: &BTreeMap<String, String>) -> Vec<Comm> {
    let label = |jid: &str| match names.get(jid) {
        Some(n) if !n.is_empty() => format!("{jid} ({n})"),
        _ => jid.to_string(),
    };
    let mut out = Vec::new();
    if db.has("message") && db.has("jid") {
        let jids: BTreeMap<i64, String> = rows(db, "SELECT _id, raw_string FROM jid").iter().map(|m| (vi(m, "_id"), vs(m, "raw_string"))).collect();
        let chats: BTreeMap<i64, (i64, String)> = rows(db, "SELECT _id, jid_row_id, subject FROM chat").iter().map(|m| (vi(m, "_id"), (vi(m, "jid_row_id"), vs(m, "subject")))).collect();
        let media: BTreeMap<i64, String> = if db.has("message_media") { rows(db, "SELECT message_row_id, file_path, mime_type FROM message_media").iter().map(|m| (vi(m, "message_row_id"), format!("{} ({})", vs(m, "file_path"), vs(m, "mime_type")))).collect() } else { BTreeMap::new() };
        let w = |m: &BTreeMap<String, Val>, rec: bool| {
            let (jid_row, subject) = chats.get(&vi(m, "chat_row_id")).cloned().unwrap_or_default();
            let chat = jids.get(&jid_row).cloned().unwrap_or_default();
            let sender = jids.get(&vi(m, "sender_jid_row_id")).cloned();
            let peer = match (subject.is_empty(), sender) {
                (false, Some(s)) => format!("{} in group {subject}", label(&s)),
                (false, None) => format!("group {subject}"),
                _ => label(&chat),
            };
            Comm {
                time_ms: vi(m, "timestamp"),
                kind: "whatsapp",
                direction: if vi(m, "from_me") == 1 { "out".into() } else { "in".into() },
                peer,
                text: vs(m, "text_data"),
                extra: media.get(&vi(m, "_id")).cloned().unwrap_or_default(),
                source: "msgstore.db".into(),
                recovered: rec,
            }
        };
        out.extend(rows(db, "SELECT * FROM message WHERE timestamp > 0").iter().map(|m| w(m, false)));
        out.extend(db.deleted("message", |m| vi(m, "timestamp") > 1_000_000_000_000 && m.get("text_data").and_then(Val::text).is_some()).iter().map(|m| w(m, true)));
    } else if db.has("messages") {
        // Legacy schema (before 2022).
        let w = |m: &BTreeMap<String, Val>, rec: bool| Comm {
            time_ms: vi(m, "timestamp"),
            kind: "whatsapp",
            direction: if vi(m, "key_from_me") == 1 { "out".into() } else { "in".into() },
            peer: label(&vs(m, "key_remote_jid")),
            text: vs(m, "data"),
            extra: vs(m, "media_name"),
            source: "msgstore.db".into(),
            recovered: rec,
        };
        out.extend(rows(db, "SELECT * FROM messages WHERE timestamp > 0").iter().map(|m| w(m, false)));
        out.extend(db.deleted("messages", |m| vi(m, "timestamp") > 1_000_000_000_000 && m.get("data").and_then(Val::text).is_some()).iter().map(|m| w(m, true)));
    }
    out
}

/// TL string at `i`: (text, next offset).
fn tl_string(b: &[u8], i: usize) -> Option<String> {
    let (len, start) = match *b.get(i)? {
        254 => (*b.get(i + 1)? as usize | (*b.get(i + 2)? as usize) << 8 | (*b.get(i + 3)? as usize) << 16, i + 4),
        255 => return None,
        n => (n as usize, i + 1),
    };
    std::str::from_utf8(b.get(start..start + len)?).ok().map(String::from)
}

/// Text of a TL `message`: in every layer, the `message` string directly
/// follows the `date` field, which the row also stores; fall back to the
/// longest printable string.
pub fn tl_message(b: &[u8], date: i64) -> String {
    let d = (date as i32).to_le_bytes();
    let mut i = 0;
    while let Some(p) = b.get(i..).and_then(|r| r.windows(4).position(|w| w == d)) {
        let at = i + p + 4;
        if let Some(s) = tl_string(b, at).filter(|s| s.is_empty() || s.chars().all(|c| !c.is_control() || c == '\n')) {
            return s;
        }
        i = at;
    }
    tl_text(b)
}

/// Longest printable TL-serialized string in a Telegram message blob.
// ponytail: heuristic fallback when the date anchor is not found.
pub fn tl_text(b: &[u8]) -> String {
    let mut best = String::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let (len, start) = if b[i] < 254 { (b[i] as usize, i + 1) } else if b[i] == 254 && i + 4 <= b.len() { (b[i + 1] as usize | (b[i + 2] as usize) << 8 | (b[i + 3] as usize) << 16, i + 4) } else { (0, i + 1) };
        if len > best.len() {
            if let Some(Ok(s)) = b.get(start..start + len).map(std::str::from_utf8) {
                if s.chars().all(|c| !c.is_control() || c == '\n') && s.chars().any(char::is_alphanumeric) {
                    best = s.to_string();
                }
            }
        }
        i += 4;
    }
    best
}

fn telegram(db: &Dbx) -> Vec<Comm> {
    if !db.has("messages_v2") {
        return Vec::new();
    }
    let users: BTreeMap<i64, String> = rows(db, "SELECT uid, name FROM users").iter().map(|m| (vi(m, "uid"), vs(m, "name").replace(";;;", " @"))).collect();
    let chats: BTreeMap<i64, String> = if db.has("chats") { rows(db, "SELECT uid, name FROM chats").iter().map(|m| (vi(m, "uid"), vs(m, "name"))).collect() } else { BTreeMap::new() };
    let t = |m: &BTreeMap<String, Val>, rec: bool| {
        let uid = vi(m, "uid");
        let peer = if uid > 0 { users.get(&uid).cloned().map(|n| format!("{uid} ({n})")).unwrap_or(uid.to_string()) } else { chats.get(&-uid).cloned().map(|n| format!("chat {n}")).unwrap_or(uid.to_string()) };
        Comm {
            time_ms: vi(m, "date") * 1000,
            kind: "telegram",
            direction: if vi(m, "out") == 1 { "out".into() } else { "in".into() },
            peer,
            text: match m.get("data") {
                Some(Val::Blob(b)) => tl_message(b, vi(m, "date")),
                _ => String::new(),
            },
            extra: String::new(),
            source: "cache4.db".into(),
            recovered: rec,
        }
    };
    let mut out: Vec<Comm> = rows(db, "SELECT * FROM messages_v2").iter().map(|m| t(m, false)).collect();
    out.extend(db.deleted("messages_v2", |m| vi(m, "date") > 1_000_000_000 && matches!(m.get("data"), Some(Val::Blob(_)))).iter().map(|m| t(m, true)));
    out
}

fn chrome(db: &Dbx) -> Vec<Comm> {
    // WebKit time: microseconds since 1601-01-01.
    let ms = |t: i64| t / 1000 - 11_644_473_600_000;
    let mut out: Vec<Comm> = rows(db, "SELECT v.visit_time AS t, u.url AS url, u.title AS title FROM visits v JOIN urls u ON v.url = u.id")
        .iter()
        .map(|m| Comm { time_ms: ms(vi(m, "t")), kind: "web", direction: String::new(), peer: vs(m, "url"), text: vs(m, "title"), extra: String::new(), source: "Chrome History".into(), recovered: false })
        .collect();
    if db.has("downloads") {
        out.extend(rows(db, "SELECT start_time AS t, target_path AS p, tab_url AS u FROM downloads").iter().map(|m| Comm {
            time_ms: ms(vi(m, "t")),
            kind: "download",
            direction: String::new(),
            peer: vs(m, "u"),
            text: vs(m, "p"),
            extra: String::new(),
            source: "Chrome History".into(),
            recovered: false,
        }));
    }
    out
}

/// Every communication record in the case, sorted by time.
pub fn load(case: &Case) -> Vec<Comm> {
    load_with(case, &crate::appdata::Keys::default()).0
}

/// Same, with examiner-supplied keys; also returns notes on what could not be read.
pub fn load_with(case: &Case, keys: &crate::appdata::Keys) -> (Vec<Comm>, Vec<String>) {
    let dir = case.root.join("comms");
    if !dir.is_dir() {
        return (Vec::new(), Vec::new());
    }
    let mut out = live(&dir);
    let db = dir.join("db");
    if let Some(d) = open(&db, "mmssms.db") {
        out.extend(mmssms(&d));
    }
    if let Some(d) = open(&db, "calllog.db") {
        out.extend(calls(&d, "calllog.db"));
    }
    if let Some(d) = open(&db, "contacts2.db") {
        // Older Android keeps the call log in contacts2.db.
        if !db.join("calllog.db").exists() {
            out.extend(calls(&d, "contacts2.db"));
        }
        out.extend(contacts(&d));
    }
    let names: BTreeMap<String, String> = open(&db, "wa.db").map(|d| rows(&d, "SELECT jid, display_name FROM wa_contacts").iter().map(|m| (vs(m, "jid"), vs(m, "display_name"))).collect()).unwrap_or_default();
    let live_wa: Vec<Comm> = open(&db, "msgstore.db").map(|d| whatsapp(&d, &names)).unwrap_or_default();
    let (app, notes) = crate::appdata::load(&dir, keys, &live_wa, &names);
    out.extend(live_wa);
    out.extend(app);
    if let Some(d) = open(&db, "cache4.db") {
        out.extend(telegram(&d));
    }
    if let Some(d) = open(&db, "chrome_history.db") {
        out.extend(chrome(&d));
    }
    if let Some(d) = open(&db, "calendar.db") {
        out.extend(rows(&d, "SELECT dtstart, title, eventLocation, description, organizer, deleted FROM Events").iter().filter(|m| !public_calendar(&vs(m, "organizer"))).map(|m| {
            calendar_row(vi(m, "dtstart"), &vs(m, "title"), &vs(m, "eventLocation"), &vs(m, "description"), &vs(m, "organizer"), vi(m, "deleted") == 1, "calendar.db")
        }));
    }
    // Contacts the shell could not read, from the APEX agent (under mandate).
    if !out.iter().any(|c| c.kind == "contact") {
        if let Some(v) = crate::agent::load(&case.root) {
            for x in v["sections"]["contacts"].as_array().into_iter().flatten() {
                let mt = x["mimetype"].as_str().unwrap_or("");
                let kind = if mt.ends_with("phone_v2") { "phone" } else if mt.ends_with("email_v2") { "email" } else { continue };
                out.push(Comm {
                    time_ms: 0,
                    kind: "contact",
                    direction: String::new(),
                    peer: x["data1"].as_str().unwrap_or("").to_string(),
                    text: x["display_name"].as_str().unwrap_or("").to_string(),
                    extra: kind.into(),
                    source: "contacts (APEX agent)".into(),
                    recovered: false,
                });
            }
        }
    }
    name_peers(&mut out);
    out.sort_by(|a, b| a.time_ms.cmp(&b.time_ms).then(a.kind.cmp(b.kind)));
    (out, notes)
}

/// Last 9 digits: matches +33 6 12 34 56 78, 0612345678 and 33612345678@s.whatsapp.net.
fn number_key(s: &str) -> Option<String> {
    let d: String = s.split('@').next().unwrap_or(s).chars().filter(char::is_ascii_digit).collect();
    (d.len() >= 9).then(|| d[d.len() - 9..].to_string())
}

/// Add the contact name to bare numbers ("+33612345678" → "+33612345678 (Dédé)").
fn name_peers(items: &mut [Comm]) {
    let names: BTreeMap<String, String> = items
        .iter()
        .filter(|c| c.kind == "contact" && !c.text.is_empty())
        .filter_map(|c| Some((number_key(&c.peer)?, c.text.clone())))
        .collect();
    if names.is_empty() {
        return;
    }
    for c in items.iter_mut().filter(|c| c.kind != "contact" && !c.peer.contains('(')) {
        if let Some(n) = number_key(&c.peer).and_then(|k| names.get(&k)) {
            c.peer = format!("{} ({n})", c.peer);
        }
    }
}

pub fn events(case: &Case) -> Vec<Event> {
    load(case)
        .into_iter()
        .filter(|c| c.time_ms > 0)
        .filter_map(|c| {
            let rec = if c.recovered { " [recovered deleted record]" } else { "" };
            let body = if c.text.is_empty() { c.extra.clone() } else { c.text.replace('\n', " ") };
            Some(Event {
                local: case.local_from_epoch_ms(c.time_ms)?,
                desc: format!("comms:{}{}", c.kind, if c.recovered { ":recovered" } else { "" }),
                source: c.source.clone(),
                package: String::new(),
                message: format!("{} {} {}: {}{rec}", c.kind, c.direction, c.peer, body).replace("  ", " "),
            })
        })
        .collect()
}

fn csv(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

/// comms.csv + comms.json in `dir`.
pub fn export(case: &Case, items: &[Comm], dir: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let when = |c: &Comm| if c.time_ms > 0 { case.local_from_epoch_ms(c.time_ms).map(|t| case.iso(&t)).unwrap_or_default() } else { String::new() };
    let mut s = String::from("time,kind,direction,peer,text,extra,source,recovered\n");
    for c in items {
        s.push_str(&format!("{},{},{},{},{},{},{},{}\n", csv(&when(c)), c.kind, c.direction, csv(&c.peer), csv(&c.text), csv(&c.extra), csv(&c.source), c.recovered));
    }
    let j: Vec<_> = items.iter().map(|c| json!({"time": when(c), "kind": c.kind, "direction": c.direction, "peer": c.peer, "text": c.text, "extra": c.extra, "source": c.source, "recovered": c.recovered})).collect();
    let mut files = vec![(dir.join("comms.csv"), s), (dir.join("comms.json"), serde_json::to_string_pretty(&j).unwrap_or_default())];
    let x = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    let pins: String = items
        .iter()
        .filter(|c| c.kind == "location")
        .filter_map(|c| {
            let (la, lo) = c.extra.split_once(',')?;
            Some(format!("<Placemark><name>{}</name><description>{} — {} ({})</description><Point><coordinates>{lo},{la}</coordinates></Point></Placemark>\n", x(&c.peer), x(&when(c)), x(&c.text), x(&c.source)))
        })
        .collect();
    if !pins.is_empty() {
        files.push((dir.join("locations.kml"), format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document>\n{pins}</Document></kml>\n")));
    }
    let mut out = Vec::new();
    let db = dir.join("comms.db");
    write_db(case, items, &db).map_err(|e| format!("{}: {e}", db.display()))?;
    out.push(db);
    for (p, b) in files {
        std::fs::write(&p, b).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(p);
    }
    Ok(out)
}

/// `comms.db`: one table to query with SQL (`SELECT … FROM comms WHERE …`).
fn write_db(case: &Case, items: &[Comm], path: &Path) -> rusqlite::Result<()> {
    let _ = std::fs::remove_file(path);
    let c = rusqlite::Connection::open(path)?;
    c.execute_batch(
        "CREATE TABLE comms(
           id INTEGER PRIMARY KEY,
           time TEXT,              -- phone local time, ISO 8601 with UTC offset
           time_ms INTEGER,        -- epoch milliseconds (0 = unknown)
           kind TEXT,              -- sms, mms, call, contact, calendar, whatsapp, signal, telegram, messenger, instagram, snapchat, email, web, download, location, clipboard, keyboard, wallet
           direction TEXT,         -- in, out, missed, … or ''
           peer TEXT,
           text TEXT,
           extra TEXT,             -- duration, attachment, coordinates 'lat,lon', …
           source TEXT,            -- database or file it comes from
           recovered INTEGER       -- 1 = deleted record recovered
         );
         CREATE INDEX comms_time ON comms(time_ms);
         CREATE INDEX comms_kind ON comms(kind);
         CREATE INDEX comms_peer ON comms(peer);
         BEGIN;",
    )?;
    {
        let mut st = c.prepare("INSERT INTO comms(time, time_ms, kind, direction, peer, text, extra, source, recovered) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")?;
        for x in items {
            let when = if x.time_ms > 0 { case.local_from_epoch_ms(x.time_ms).map(|t| case.iso(&t)) } else { None };
            st.execute(rusqlite::params![when, x.time_ms, x.kind, x.direction, x.peer, x.text, x.extra, x.source, x.recovered as i64])?;
        }
    }
    c.execute_batch("COMMIT")
}

/// Counts per kind (and recovered) for reports.
pub fn counts(items: &[Comm]) -> BTreeMap<String, (usize, usize)> {
    let mut m: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for c in items {
        let e = m.entry(c.kind.to_string()).or_default();
        e.0 += 1;
        if c.recovered {
            e.1 += 1;
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_query_rows() {
        let t = "Row: 0 _id=39, thread_id=45, address=+33600000000, date=1793971203325, date_sent=0, type=1, read=0, body=Salut, ça va, body=ok?\nseconde ligne\nRow: 1 _id=40, thread_id=45, address=NULL, date=1, date_sent=0, type=2, read=1, body=\n";
        let r = parse_content_query(t, SMS_COLS);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0]["body"], "Salut, ça va, body=ok?\nseconde ligne");
        assert_eq!(r[0]["address"], "+33600000000");
        assert!(!r[1].contains_key("address"));
    }

    #[test]
    fn peers_get_contact_names() {
        let c = |kind: &'static str, peer: &str, text: &str| Comm { time_ms: 0, kind, direction: String::new(), peer: peer.into(), text: text.into(), extra: String::new(), source: String::new(), recovered: false };
        let mut v = vec![c("contact", "06 12 34 56 78", "Dédé"), c("sms", "+33612345678", "salut"), c("call", "+33699999999", ""), c("whatsapp", "33612345678@s.whatsapp.net (Dédé W)", "")];
        name_peers(&mut v);
        assert_eq!(v[1].peer, "+33612345678 (Dédé)");
        assert_eq!(v[2].peer, "+33699999999");
        assert_eq!(v[3].peer, "33612345678@s.whatsapp.net (Dédé W)");
    }

    #[test]
    fn telegram_text() {
        // constructor, flags, then a TL string "hello world" (len 11, padded).
        let mut b = vec![0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0];
        b.push(11);
        b.extend(b"hello world");
        assert_eq!(tl_text(&b), "hello world");
        // message: flags, id, peer…, date (0x65000000), then the text.
        let date: i64 = 0x6500_0000;
        let mut m = vec![0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 5, 0, 0, 0, 2, 0, 0, 0];
        m.extend((date as i32).to_le_bytes());
        m.push(9);
        m.extend(b"rdv 22h ?");
        m.extend([0, 0]);
        m.push(30);
        m.extend(b"a much longer unrelated string");
        assert_eq!(tl_message(&m, date), "rdv 22h ?");
    }

    #[test]
    fn databases_with_recovery() {
        let d = tempfile::tempdir().unwrap();
        let db = d.path().join("mmssms.db");
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
             CREATE TABLE sms(_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, type INTEGER, body TEXT);
             INSERT INTO sms(thread_id,address,date,type,body) VALUES (1,'+33600000001',1700000000000,1,'rdv 20h');
             INSERT INTO sms(thread_id,address,date,type,body) VALUES (1,'+33600000001',1700000060000,2,'efface ce message');
             DELETE FROM sms WHERE _id=2;",
        )
        .unwrap();
        // Copy while the connection still holds the WAL (as an extraction would).
        let x = open(d.path(), "mmssms.db").unwrap();
        let rows = mmssms(&x);
        drop(c);
        assert_eq!(rows.len(), 2, "{rows:?}");
        let gone = rows.iter().find(|r| r.recovered).unwrap();
        assert_eq!((gone.text.as_str(), gone.direction.as_str()), ("efface ce message", "out"));
    }
}
