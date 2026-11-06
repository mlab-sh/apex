//! Deleted-record recovery from SQLite databases (read-only, from bytes).
//!
//! A deleted row usually survives for a while in two places:
//! - the **WAL** (`-wal` file): every frame is a full page image, including
//!   older versions of pages written before the delete;
//! - **freelist pages** of the main file: pages released by a delete keep
//!   their content until reused (unless `secure_delete` is on).
//!
//! Both are parsed as table b-tree leaf pages (0x0D); records whose rowid is
//! no longer in the live table are returned as recovered. Unallocated space
//! and freeblocks *inside* live pages are not carved (partial headers).

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Val {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl Val {
    pub fn int(&self) -> Option<i64> {
        match self {
            Val::Int(i) => Some(*i),
            _ => None,
        }
    }
    pub fn text(&self) -> Option<&str> {
        match self {
            Val::Text(t) => Some(t),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Carved {
    pub rowid: i64,
    pub values: Vec<Val>,
    /// `wal` or `freelist`.
    pub origin: &'static str,
}

fn varint(b: &[u8], i: &mut usize) -> Option<i64> {
    let mut v: u64 = 0;
    for k in 0..9 {
        let x = *b.get(*i)?;
        *i += 1;
        if k == 8 {
            return Some(((v << 8) | x as u64) as i64);
        }
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            return Some(v as i64);
        }
    }
    None
}

fn be(b: &[u8]) -> i64 {
    let mut v: i64 = if b.first().is_some_and(|x| x & 0x80 != 0) { -1 } else { 0 };
    for x in b {
        v = (v << 8) | *x as i64;
    }
    v
}

/// Parse a record (header + body) into values.
pub fn record(p: &[u8]) -> Option<Vec<Val>> {
    let mut i = 0;
    let hlen = varint(p, &mut i)? as usize;
    if hlen < 2 || hlen > p.len() {
        return None;
    }
    let mut types = Vec::new();
    while i < hlen {
        types.push(varint(p, &mut i)?);
    }
    let mut j = hlen;
    let mut out = Vec::with_capacity(types.len());
    for t in types {
        let (n, v) = match t {
            0 => (0, Val::Null),
            1..=6 => {
                let n = [0, 1, 2, 3, 4, 6, 8][t as usize];
                (n, Val::Int(be(p.get(j..j + n)?)))
            }
            7 => (8, Val::Real(f64::from_bits(u64::from_be_bytes(p.get(j..j + 8)?.try_into().ok()?)))),
            8 => (0, Val::Int(0)),
            9 => (0, Val::Int(1)),
            10 | 11 => return None,
            t if t % 2 == 0 => {
                let n = ((t - 12) / 2) as usize;
                (n, Val::Blob(p.get(j..j + n)?.to_vec()))
            }
            t => {
                let n = ((t - 13) / 2) as usize;
                (n, Val::Text(std::str::from_utf8(p.get(j..j + n)?).ok()?.to_string()))
            }
        };
        j += n;
        out.push(v);
    }
    Some(out)
}

struct Db<'a> {
    main: &'a [u8],
    ps: usize,
    usable: usize,
    /// Latest WAL image per page number.
    wal_latest: HashMap<u32, &'a [u8]>,
}

impl<'a> Db<'a> {
    fn page(&self, n: u32) -> Option<&'a [u8]> {
        if let Some(p) = self.wal_latest.get(&n) {
            return Some(p);
        }
        let s = (n as usize).checked_sub(1)? * self.ps;
        self.main.get(s..s + self.ps)
    }

    /// Cells of a table leaf page → (rowid, record values).
    fn leaf_cells(&self, page: &[u8], pno: u32) -> Vec<(i64, Vec<Val>)> {
        let h = if pno == 1 { 100 } else { 0 };
        if page.get(h) != Some(&0x0D) {
            return Vec::new();
        }
        let n = u16::from_be_bytes([page[h + 3], page[h + 4]]) as usize;
        let mut out = Vec::new();
        for c in 0..n {
            let Some(ptr) = page.get(h + 8 + 2 * c..h + 10 + 2 * c) else { break };
            let mut i = u16::from_be_bytes([ptr[0], ptr[1]]) as usize;
            let (Some(plen), Some(rowid)) = (varint(page, &mut i), varint(page, &mut i)) else { continue };
            let plen = plen as usize;
            let u = self.usable;
            let x = u - 35;
            let local = if plen <= x {
                plen
            } else {
                let m = ((u - 12) * 32 / 255) - 23;
                let k = m + (plen - m) % (u - 4);
                if k <= x { k } else { m }
            };
            let Some(head) = page.get(i..i + local) else { continue };
            let mut payload = head.to_vec();
            if local < plen {
                // Follow the overflow chain (latest page versions).
                let mut next = page.get(i + local..i + local + 4).map(|b| u32::from_be_bytes(b.try_into().unwrap())).unwrap_or(0);
                let mut guard = 0;
                while next != 0 && payload.len() < plen && guard < 10_000 {
                    let Some(op) = self.page(next) else { break };
                    let take = (plen - payload.len()).min(u - 4);
                    payload.extend_from_slice(op.get(4..4 + take).unwrap_or(&[]));
                    next = u32::from_be_bytes(op[..4].try_into().unwrap());
                    guard += 1;
                }
            }
            if let Some(v) = record(&payload) {
                out.push((rowid, v));
            }
        }
        out
    }
}

/// Every record found in WAL frames and freelist pages.
pub fn carve(main: &[u8], wal: Option<&[u8]>) -> Vec<Carved> {
    if main.len() < 100 || !main.starts_with(b"SQLite format 3\0") {
        return Vec::new();
    }
    let ps = match u16::from_be_bytes([main[16], main[17]]) {
        1 => 65536,
        p => p as usize,
    };
    let usable = ps - main[20] as usize;
    let mut frames: Vec<(u32, &[u8])> = Vec::new();
    if let Some(w) = wal.filter(|w| w.len() > 32 && (w[..4] == [0x37, 0x7f, 0x06, 0x82] || w[..4] == [0x37, 0x7f, 0x06, 0x83])) {
        let wps = u32::from_be_bytes(w[8..12].try_into().unwrap()) as usize;
        let salt = &w[16..24];
        let mut off = 32;
        while wps == ps && off + 24 + ps <= w.len() {
            let pno = u32::from_be_bytes(w[off..off + 4].try_into().unwrap());
            // Frames from an older WAL generation have other salts: still page images, keep them.
            let _same_gen = &w[off + 8..off + 16] == salt;
            frames.push((pno, &w[off + 24..off + 24 + ps]));
            off += 24 + ps;
        }
    }
    let db = Db { main, ps, usable, wal_latest: frames.iter().map(|(n, p)| (*n, *p)).collect() };

    let mut out = Vec::new();
    for (pno, page) in &frames {
        for (rowid, values) in db.leaf_cells(page, *pno) {
            out.push(Carved { rowid, values, origin: "wal" });
        }
    }
    // Freelist: trunk pages list leaf pages; both may hold old leaf content.
    let mut trunk = u32::from_be_bytes(main[32..36].try_into().unwrap());
    let mut guard = 0;
    while trunk != 0 && guard < 100_000 {
        guard += 1;
        let Some(t) = db.page(trunk) else { break };
        let mut pages = vec![trunk];
        let n = u32::from_be_bytes(t[4..8].try_into().unwrap()) as usize;
        for k in 0..n.min((ps - 8) / 4) {
            pages.push(u32::from_be_bytes(t[8 + 4 * k..12 + 4 * k].try_into().unwrap()));
        }
        for p in pages {
            if let Some(pg) = db.page(p) {
                for (rowid, values) in db.leaf_cells(pg, p) {
                    out.push(Carved { rowid, values, origin: "freelist" });
                }
            }
        }
        trunk = u32::from_be_bytes(t[..4].try_into().unwrap());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_deleted_rows() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("t.db");
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
             CREATE TABLE sms(_id INTEGER PRIMARY KEY, address TEXT, date INTEGER, body TEXT);
             INSERT INTO sms(address,date,body) VALUES ('+33600000001', 1700000000000, 'see you at 8');
             INSERT INTO sms(address,date,body) VALUES ('+33600000002', 1700000001000, 'delete this one');",
        )
        .unwrap();
        c.execute("DELETE FROM sms WHERE _id=2", []).unwrap();
        let main = std::fs::read(&p).unwrap();
        let wal = std::fs::read(d.path().join("t.db-wal")).unwrap();
        let rows = carve(&main, Some(&wal));
        let gone: Vec<_> = rows.iter().filter(|r| r.rowid == 2).collect();
        assert!(!gone.is_empty(), "{rows:?}");
        assert_eq!(gone[0].values[3], Val::Text("delete this one".into()));
        assert_eq!(gone[0].values[1], Val::Text("+33600000002".into()));
        assert_eq!(gone[0].values[2], Val::Int(1700000001000));
        drop(c);
    }

    #[test]
    fn freelist_pages() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f.db");
        let c = rusqlite::Connection::open(&p).unwrap();
        c.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA secure_delete=OFF; CREATE TABLE m(_id INTEGER PRIMARY KEY, t TEXT);").unwrap();
        for i in 0..400 {
            c.execute("INSERT INTO m(t) VALUES (?1)", [format!("message number {i} with some padding text to fill pages")]).unwrap();
        }
        c.execute("DELETE FROM m WHERE _id > 100", []).unwrap();
        drop(c);
        let main = std::fs::read(&p).unwrap();
        let rows = carve(&main, None);
        assert!(rows.iter().any(|r| r.rowid == 350 && r.origin == "freelist" && r.values[1] == Val::Text("message number 349 with some padding text to fill pages".into())), "{} rows", rows.len());
    }
}
