//! `adb backup` without an adb server: `bu backup -all -noapk` run on the phone
//! into `/data/local/tmp`, confirmed by the examiner on the phone's screen,
//! pulled, then removed.
//!
//! Only apps that allow backup are included (most apps targeting Android 12+
//! opt out), so this complements, not replaces, a lab extraction. The `.ab`
//! (header + zlib + tar) is unpacked into `<case>/backup/`; under a mandate, the
//! communication databases found there go to `comms/db/` like an extraction's.

use std::io::Read;
use std::path::{Path, PathBuf};

const REMOTE: &str = "/data/local/tmp/apex_backup.ab";

/// Run the backup on the phone and pull it to `<out>/device/backup.ab`.
pub fn run(phone: &mut crate::device::Phone, out: &Path) -> Result<PathBuf, String> {
    phone.run(&format!("rm -f {REMOTE}; (bu backup -all -noapk > {REMOTE} 2>/dev/null &)"))?;
    eprintln!("\x1b[33m  On the phone: unlock it, tap \"Back up my data\" and leave the password EMPTY (an encrypted backup cannot be read).\x1b[0m");
    let started = std::time::Instant::now();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let running = phone.run("pidof bu").map(|o| !o.trim().is_empty()).unwrap_or(false);
        if !running {
            break;
        }
        if started.elapsed().as_secs() > 900 {
            let _ = phone.run("kill $(pidof bu)");
            return Err("backup not confirmed or not finished after 15 min".into());
        }
    }
    let local = out.join("device/backup.ab");
    let res = phone.pull(REMOTE, &local);
    let _ = phone.run(&format!("rm -f {REMOTE}"));
    res?;
    if std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0) < 24 {
        return Err("empty backup (refused on the phone, or no app allows backup)".into());
    }
    Ok(local)
}

/// Backup tar path `apps/<pkg>/<domain>/<rest>` → app data path in an
/// extraction (`data/data/<pkg>/…`), so `comms::db_name` can recognise it.
pub fn data_path(tar_path: &str) -> Option<String> {
    let rest = tar_path.strip_prefix("apps/")?;
    let (pkg, rest) = rest.split_once('/')?;
    let (domain, file) = rest.split_once('/').unwrap_or((rest, ""));
    let dir = match domain {
        "db" => "databases",
        "f" => "files",
        "sp" => "shared_prefs",
        "c" => "cache",
        "r" => "",
        _ => return None,
    };
    Some(if dir.is_empty() { format!("data/data/{pkg}/{file}") } else { format!("data/data/{pkg}/{dir}/{file}") })
}

/// Unpack `ab` into `<out>/backup/`; with `mandate`, copy communication
/// databases to `<out>/comms/db/`. Returns every file written (relative to `out`).
pub fn extract(ab: &Path, out: &Path, mandate: bool) -> Result<Vec<String>, String> {
    let f = std::fs::File::open(ab).map_err(|e| format!("{}: {e}", ab.display()))?;
    let mut r = std::io::BufReader::new(f);
    let mut header = Vec::new();
    // Four text lines: magic, version, compressed, encryption.
    for _ in 0..4 {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            r.read_exact(&mut b).map_err(|_| "not an Android backup")?;
            if b[0] == b'\n' {
                break;
            }
            line.push(b[0]);
        }
        header.push(String::from_utf8_lossy(&line).into_owned());
    }
    if header[0] != "ANDROID BACKUP" {
        return Err("not an Android backup".into());
    }
    if header[3] != "none" {
        return Err("the backup is password-protected: redo it with an empty password".into());
    }
    let body: Box<dyn Read> = if header[2] == "1" { Box::new(flate2::read::ZlibDecoder::new(r)) } else { Box::new(r) };
    let mut tar = tar::Archive::new(body);
    let mut written = Vec::new();
    for e in tar.entries().map_err(|e| e.to_string())? {
        let mut e = e.map_err(|e| e.to_string())?;
        if !e.header().entry_type().is_file() {
            continue;
        }
        let p = e.path().map_err(|e| e.to_string())?.to_string_lossy().into_owned();
        if p.contains("..") {
            continue;
        }
        let mut data = Vec::new();
        e.read_to_end(&mut data).map_err(|e| e.to_string())?;
        let rel = format!("backup/{p}");
        let dst = out.join(&rel);
        std::fs::create_dir_all(dst.parent().unwrap()).map_err(|e| e.to_string())?;
        std::fs::write(&dst, &data).map_err(|e| e.to_string())?;
        written.push(rel);
        if mandate {
            if let Some((name, ext)) = data_path(&p).and_then(|d| crate::comms::db_name(&d)) {
                let rel = format!("comms/db/{name}{ext}");
                std::fs::create_dir_all(out.join("comms/db")).map_err(|e| e.to_string())?;
                std::fs::write(out.join(&rel), &data).map_err(|e| e.to_string())?;
                written.push(rel);
            } else if let Some(rel) = data_path(&p).and_then(|d| crate::appdata::target(&d, data.len() as u64)) {
                std::fs::create_dir_all(out.join(&rel).parent().unwrap()).map_err(|e| e.to_string())?;
                std::fs::write(out.join(&rel), &data).map_err(|e| e.to_string())?;
                written.push(rel);
            }
        }
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        assert_eq!(data_path("apps/com.whatsapp/db/msgstore.db").as_deref(), Some("data/data/com.whatsapp/databases/msgstore.db"));
        assert_eq!(data_path("apps/org.telegram.messenger/f/cache4.db").as_deref(), Some("data/data/org.telegram.messenger/files/cache4.db"));
        assert_eq!(data_path("apps/x/_manifest"), None);
    }

    #[test]
    fn unpack_ab() {
        let d = tempfile::tempdir().unwrap();
        // tar with one database and one file
        let mut t = tar::Builder::new(Vec::new());
        for (p, body) in [("apps/com.whatsapp/db/msgstore.db", &b"SQLite format 3\0x"[..]), ("apps/com.x/f/notes.txt", &b"hello"[..])] {
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o600);
            h.set_cksum();
            t.append_data(&mut h, p, body).unwrap();
        }
        let tarb = t.into_inner().unwrap();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, &tarb).unwrap();
        let mut ab = b"ANDROID BACKUP\n5\n1\nnone\n".to_vec();
        ab.extend(z.finish().unwrap());
        let abp = d.path().join("b.ab");
        std::fs::write(&abp, ab).unwrap();
        let w = extract(&abp, d.path(), true).unwrap();
        assert!(w.contains(&"backup/apps/com.x/f/notes.txt".to_string()));
        assert!(w.contains(&"comms/db/msgstore.db".to_string()));
        assert_eq!(std::fs::read(d.path().join("backup/apps/com.x/f/notes.txt")).unwrap(), b"hello");
        // Without a mandate, no comms copy.
        let d2 = tempfile::tempdir().unwrap();
        assert!(!extract(&abp, d2.path(), false).unwrap().iter().any(|p| p.starts_with("comms/")));
        // Encrypted backups are refused with a clear message.
        std::fs::write(&abp, b"ANDROID BACKUP\n5\n1\nAES-256\nxxxx").unwrap();
        assert!(extract(&abp, d.path(), false).unwrap_err().contains("password"));
    }
}
