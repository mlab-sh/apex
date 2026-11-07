//! Signal Android `.backup` files (Settings → Chats → Chat backups), decrypted
//! with the 30-digit passphrase Signal shows when backups are turned on.
//!
//! Format (Signal-Android `FullBackupExporter` / `BackupRecordInputStream`):
//! - a plaintext header frame: [u32 BE length][BackupFrame{header{iv, salt, version}}];
//! - key = SHA-512 loop (250 000 rounds) over the passphrase digits, salted once;
//!   HKDF-SHA256(key, "Backup Export") → 32-byte AES key + 32-byte HMAC key;
//! - each frame: [length][AES-256-CTR(frame)][HMAC-SHA256 truncated to 10 bytes];
//!   from version 1 the length itself is encrypted and MACed. The CTR IV is the
//!   header IV with its first 4 bytes replaced by a counter, +1 per frame;
//! - attachment, avatar and sticker frames are followed by their encrypted
//!   bytes, MACed over (IV ‖ ciphertext).
//!
//! The frames are SQL statements that rebuild the database, plus files.

use aes_gcm::aes::cipher::{BlockEncrypt, KeyInit};
use aes_gcm::aes::Aes256;
use hmac::Mac;
use sha2::{Digest, Sha512};

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

/// SQL parameter of a statement frame.
#[derive(Debug, Clone, PartialEq)]
pub enum Param {
    Text(String),
    Int(i64),
    Real(f64),
    Blob(Vec<u8>),
    Null,
}

/// A file carried by the backup.
#[derive(Debug, Clone)]
pub struct File {
    /// "attachment", "avatar", "sticker".
    pub kind: &'static str,
    /// Attachment: (row id, attachment id); avatar: recipient / name; sticker: row id.
    pub id: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Default)]
#[allow(dead_code)] // version: kept for diagnostics and tests
pub struct Decoded {
    pub version: u32,
    pub db_version: u64,
    pub statements: Vec<(String, Vec<Param>)>,
    pub files: Vec<File>,
    pub preferences: usize,
}

// ---------------------------------------------------------------- crypto

/// Backup key from the passphrase (digits only; spaces ignored).
pub fn backup_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let input: Vec<u8> = passphrase.chars().filter(|c| !c.is_whitespace()).collect::<String>().into_bytes();
    let mut hash = input.clone();
    let mut d = Sha512::new();
    d.update(salt);
    for _ in 0..250_000 {
        d.update(&hash);
        d.update(&input);
        hash = d.finalize_reset().to_vec();
    }
    hash[..32].try_into().unwrap()
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// HKDF-SHA256 with a zero salt, 64 bytes: (cipher key, MAC key).
pub fn derive(key: &[u8; 32], info: &[u8]) -> ([u8; 32], [u8; 32]) {
    let prk = hmac(&[0u8; 32], &[key]);
    let t1 = hmac(&prk, &[info, &[1]]);
    let t2 = hmac(&prk, &[&t1, info, &[2]]);
    (t1, t2)
}

/// AES-256-CTR with a 128-bit big-endian counter (Java's AES/CTR/NoPadding).
pub struct Ctr {
    aes: Aes256,
    block: [u8; 16],
    ks: [u8; 16],
    pos: usize,
}

impl Ctr {
    pub fn new(key: &[u8; 32], iv: &[u8; 16]) -> Self {
        Ctr { aes: Aes256::new(key.into()), block: *iv, ks: [0; 16], pos: 16 }
    }
    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data {
            if self.pos == 16 {
                let mut k = self.block.into();
                self.aes.encrypt_block(&mut k);
                self.ks = k.into();
                for i in (0..16).rev() {
                    self.block[i] = self.block[i].wrapping_add(1);
                    if self.block[i] != 0 {
                        break;
                    }
                }
                self.pos = 0;
            }
            *b ^= self.ks[self.pos];
            self.pos += 1;
        }
    }
}

// ---------------------------------------------------------------- protobuf

enum Wire<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed64([u8; 8]),
}

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

fn fields(b: &[u8]) -> Option<Vec<(u64, Wire<'_>)>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let key = varint(b, &mut i)?;
        let w = match key & 7 {
            0 => Wire::Varint(varint(b, &mut i)?),
            1 => {
                let v: [u8; 8] = b.get(i..i + 8)?.try_into().ok()?;
                i += 8;
                Wire::Fixed64(v)
            }
            2 => {
                let n = varint(b, &mut i)? as usize;
                let v = b.get(i..i.checked_add(n)?)?;
                i += n;
                Wire::Bytes(v)
            }
            5 => {
                i += 4;
                continue;
            }
            _ => return None,
        };
        out.push((key >> 3, w));
    }
    Some(out)
}

fn get_bytes<'a>(f: &'a [(u64, Wire<'a>)], n: u64) -> Option<&'a [u8]> {
    f.iter().find_map(|(k, w)| match w {
        Wire::Bytes(b) if *k == n => Some(*b),
        _ => None,
    })
}
fn get_int(f: &[(u64, Wire<'_>)], n: u64) -> Option<u64> {
    f.iter().find_map(|(k, w)| match w {
        Wire::Varint(v) if *k == n => Some(*v),
        _ => None,
    })
}

fn statement(b: &[u8]) -> Option<(String, Vec<Param>)> {
    let f = fields(b)?;
    let sql = String::from_utf8_lossy(get_bytes(&f, 1)?).into_owned();
    let mut params = Vec::new();
    for (k, w) in &f {
        let Wire::Bytes(p) = w else { continue };
        if *k != 2 {
            continue;
        }
        let pf = fields(p)?;
        let v = pf
            .iter()
            .find_map(|(k, w)| match (k, w) {
                (1, Wire::Bytes(s)) => Some(Param::Text(String::from_utf8_lossy(s).into_owned())),
                (2, Wire::Varint(v)) => Some(Param::Int(*v as i64)),
                (3, Wire::Fixed64(d)) => Some(Param::Real(f64::from_le_bytes(*d))),
                (4, Wire::Bytes(b)) => Some(Param::Blob(b.to_vec())),
                (5, _) => Some(Param::Null),
                _ => None,
            })
            .unwrap_or(Param::Null);
        params.push(v);
    }
    Some((sql, params))
}

// ---------------------------------------------------------------- reader

/// Decrypt a whole `.backup` file. A wrong passphrase fails on the first frame's MAC.
pub fn decrypt(file: &[u8], passphrase: &str) -> Result<Decoded, String> {
    let be = |b: &[u8]| u32::from_be_bytes(b.try_into().unwrap()) as usize;
    let hlen = be(file.get(0..4).ok_or("not a Signal backup")?);
    let hf = fields(file.get(4..4 + hlen).ok_or("not a Signal backup")?).ok_or("not a Signal backup")?;
    let header = fields(get_bytes(&hf, 1).ok_or("not a Signal backup (no header)")?).ok_or("not a Signal backup")?;
    let mut iv: [u8; 16] = get_bytes(&header, 1).and_then(|v| v.try_into().ok()).ok_or("not a Signal backup (no IV)")?;
    let salt = get_bytes(&header, 2).unwrap_or(&[]);
    let version = get_int(&header, 3).unwrap_or(0) as u32;
    let (ck, mk) = derive(&backup_key(passphrase, salt), b"Backup Export");
    let mut counter = u32::from_be_bytes(iv[0..4].try_into().unwrap());
    let mut out = Decoded { version, ..Default::default() };
    let mut pos = 4 + hlen;
    let mut first = true;
    let take = |pos: &mut usize, n: usize| -> Result<&[u8], String> {
        let s = file.get(*pos..*pos + n).ok_or("truncated backup")?;
        *pos += n;
        Ok(s)
    };
    while pos < file.len() {
        let len_raw = take(&mut pos, 4)?.to_vec();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&mk).unwrap();
        // Version 1+: one CTR stream per frame, starting with the encrypted length.
        let mut ctr = None;
        let flen = if version >= 1 {
            mac.update(&len_raw);
            iv[0..4].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            let mut c = Ctr::new(&ck, &iv);
            let mut l = len_raw.clone();
            c.apply(&mut l);
            ctr = Some(c);
            be(&l)
        } else {
            be(&len_raw)
        };
        if flen < 10 || flen > file.len() {
            return Err(if first { "wrong passphrase".into() } else { "corrupt frame length".into() });
        }
        let frame = take(&mut pos, flen)?;
        let (ct, theirs) = frame.split_at(flen - 10);
        mac.update(ct);
        if mac.finalize().into_bytes()[..10] != *theirs {
            return Err(if first { "wrong passphrase".into() } else { "frame MAC mismatch (corrupt backup)".into() });
        }
        first = false;
        let mut ctr = ctr.unwrap_or_else(|| {
            iv[0..4].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            Ctr::new(&ck, &iv)
        });
        let mut pt = ct.to_vec();
        ctr.apply(&mut pt);
        let f = fields(&pt).ok_or("undecodable frame")?;
        // Frame kinds with trailing file data: (field, kind, length field, id).
        let mut file_len: Option<(&'static str, usize, String)> = None;
        for (k, w) in &f {
            let Wire::Bytes(b) = w else {
                if *k == 6 {
                    return Ok(out); // end
                }
                continue;
            };
            let sub = fields(b).unwrap_or_default();
            match k {
                2 => out.statements.extend(statement(b)),
                3 | 9 => out.preferences += 1,
                5 => out.db_version = get_int(&sub, 1).unwrap_or(0),
                4 => file_len = Some(("attachment", get_int(&sub, 3).unwrap_or(0) as usize, format!("{}_{}", get_int(&sub, 1).unwrap_or(0), get_int(&sub, 2).unwrap_or(0)))),
                7 => {
                    let id = get_bytes(&sub, 3).or(get_bytes(&sub, 1)).map(|x| String::from_utf8_lossy(x).into_owned()).unwrap_or_default();
                    file_len = Some(("avatar", get_int(&sub, 2).unwrap_or(0) as usize, id));
                }
                8 => file_len = Some(("sticker", get_int(&sub, 2).unwrap_or(0) as usize, get_int(&sub, 1).unwrap_or(0).to_string())),
                _ => {}
            }
        }
        if let Some((kind, n, id)) = file_len {
            iv[0..4].copy_from_slice(&counter.to_be_bytes());
            counter = counter.wrapping_add(1);
            let mut ctr = Ctr::new(&ck, &iv);
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&mk).unwrap();
            mac.update(&iv);
            let data = take(&mut pos, n)?;
            mac.update(data);
            let theirs = take(&mut pos, 10)?;
            if mac.finalize().into_bytes()[..10] != *theirs {
                return Err(format!("{kind} {id}: MAC mismatch (corrupt backup)"));
            }
            let mut d = data.to_vec();
            ctr.apply(&mut d);
            out.files.push(File { kind, id, data: d });
        }
    }
    Ok(out)
}

/// Replay the SQL statements into a new SQLite database. Returns the number
/// of statements that failed (virtual / internal tables the bundled SQLite
/// does not have).
pub fn to_sqlite(d: &Decoded, path: &std::path::Path) -> Result<usize, String> {
    let c = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; BEGIN").map_err(|e| e.to_string())?;
    let mut failed = 0;
    for (sql, params) in &d.statements {
        if sql.starts_with("CREATE TABLE sqlite_") {
            continue;
        }
        let ps: Vec<rusqlite::types::Value> = params
            .iter()
            .map(|p| match p {
                Param::Text(s) => rusqlite::types::Value::Text(s.clone()),
                Param::Int(i) => rusqlite::types::Value::Integer(*i),
                Param::Real(f) => rusqlite::types::Value::Real(*f),
                Param::Blob(b) => rusqlite::types::Value::Blob(b.clone()),
                Param::Null => rusqlite::types::Value::Null,
            })
            .collect();
        if c.execute(sql, rusqlite::params_from_iter(ps)).is_err() {
            failed += 1;
        }
    }
    c.execute_batch("COMMIT").map_err(|e| e.to_string())?;
    Ok(failed)
}

/// File extension from magic bytes, for exported attachments.
pub fn ext(b: &[u8]) -> &'static str {
    match b {
        [0xff, 0xd8, 0xff, ..] => "jpg",
        [0x89, b'P', b'N', b'G', ..] => "png",
        [b'G', b'I', b'F', ..] => "gif",
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => "webp",
        [_, _, _, _, b'f', b't', b'y', b'p', ..] => "mp4",
        [b'%', b'P', b'D', b'F', ..] => "pdf",
        [b'O', b'g', b'g', b'S', ..] => "ogg",
        [b'P', b'K', 3, 4, ..] => "zip",
        _ => "bin",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pb(n: u64, b: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let mut put = |mut x: u64| loop {
            let byte = (x & 0x7f) as u8;
            x >>= 7;
            if x == 0 {
                v.push(byte);
                break;
            }
            v.push(byte | 0x80);
        };
        put((n << 3) | 2);
        put(b.len() as u64);
        v.extend(b);
        v
    }
    fn pv(n: u64, x: u64) -> Vec<u8> {
        let mut v = vec![(n << 3) as u8];
        let mut x = x;
        loop {
            let byte = (x & 0x7f) as u8;
            x >>= 7;
            if x == 0 {
                v.push(byte);
                break;
            }
            v.push(byte | 0x80);
        }
        v
    }

    /// Writer mirroring Signal's `BackupFrameOutputStream` (version 1), for the test.
    fn build(pass: &str, frames: &[Vec<u8>], attachment: Option<(usize, &[u8])>) -> Vec<u8> {
        let iv = [0x11u8; 16];
        let salt = [0x22u8; 32];
        let (ck, mk) = derive(&backup_key(pass, &salt), b"Backup Export");
        let header = pb(1, &[pb(1, &iv), pb(2, &salt), pv(3, 1)].concat());
        let mut out = (header.len() as u32).to_be_bytes().to_vec();
        out.extend(&header);
        let mut counter = u32::from_be_bytes(iv[0..4].try_into().unwrap());
        let mut ivm = iv;
        for (i, f) in frames.iter().enumerate() {
            ivm[0..4].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
            let mut ctr = Ctr::new(&ck, &ivm);
            let mut len = ((f.len() + 10) as u32).to_be_bytes();
            ctr.apply(&mut len);
            let mut ct = f.clone();
            ctr.apply(&mut ct);
            let mac = hmac(&mk, &[&len, &ct]);
            out.extend(len);
            out.extend(&ct);
            out.extend(&mac[..10]);
            if let Some((at, data)) = attachment.filter(|(at, _)| *at == i) {
                let _ = at;
                ivm[0..4].copy_from_slice(&counter.to_be_bytes());
                counter += 1;
                let mut ctr = Ctr::new(&ck, &ivm);
                let mut d = data.to_vec();
                ctr.apply(&mut d);
                let mac = hmac(&mk, &[&ivm, &d]);
                out.extend(&d);
                out.extend(&mac[..10]);
            }
        }
        out
    }

    #[test]
    fn decrypt_and_replay() {
        let pass = "123451234512345123451234512345";
        let stmt = |sql: &str, params: Vec<Vec<u8>>| pb(2, &[pb(1, sql.as_bytes()), params.into_iter().map(|p| pb(2, &p)).collect::<Vec<_>>().concat()].concat());
        let frames = vec![
            pb(5, &pv(1, 200)),
            stmt("CREATE TABLE message (_id INTEGER PRIMARY KEY, date_sent INTEGER, type INTEGER, body TEXT, thread_id INTEGER)", vec![]),
            stmt("INSERT INTO message VALUES (?, ?, ?, ?, ?)", vec![pv(2, 1), pv(2, 1_700_000_000_000), pv(2, 10485780), pb(1, "rdv gare 22h".as_bytes()), pv(2, 1)]),
            pb(4, &[pv(1, 7), pv(2, 9), pv(3, 4)].concat()),
            pv(6, 1),
        ];
        let file = build(pass, &frames, Some((3, &[0xff, 0xd8, 0xff, 0xe0])));
        assert_eq!(decrypt(&file, "000000000000000000000000000000").unwrap_err(), "wrong passphrase");
        let d = decrypt(&file, "12345 12345 12345 12345 12345 12345").unwrap();
        assert_eq!((d.version, d.db_version, d.statements.len()), (1, 200, 2));
        assert_eq!(d.files.len(), 1);
        assert_eq!((d.files[0].id.as_str(), ext(&d.files[0].data)), ("7_9", "jpg"));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.db");
        assert_eq!(to_sqlite(&d, &p).unwrap(), 0);
        let c = rusqlite::Connection::open(&p).unwrap();
        let body: String = c.query_row("SELECT body FROM message", [], |r| r.get(0)).unwrap();
        assert_eq!(body, "rdv gare 22h");
    }
}
