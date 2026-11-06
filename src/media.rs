//! Shared storage (photos, videos, downloads, messaging media):
//! - pulled from the phone by `device acquire --storage`, or copied from an
//!   extraction by `import --storage`, into `<case>/storage/`;
//! - inventoried with SHA-256 / SHA-1 / MD5, EXIF (date, make, model, GPS) and
//!   MP4 / MOV location atoms;
//! - matched against hash sets: *known* files (NSRL) to set aside, *alert* sets
//!   (Project VIC / CAID VICS JSON, plain lists) through the IOC engine;
//! - exported as CSV, KML and GeoJSON, and fed to the timeline.

use crate::case::{Case, Event};
use crate::ioc::{IocSet, Kind};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

/// App-private or cache trees of shared storage that are not user media.
fn skipped(rel: &str) -> bool {
    rel.starts_with("Android/data/") || rel.starts_with("Android/obb/") || rel.contains("/.thumbnails/") || rel.starts_with(".")
}

/// Pull every file of shared storage listed in `device/sdcard_listing.txt`
/// into `<out>/storage/` (each pull hashed in the audit log).
pub fn pull_storage(phone: &mut crate::device::Phone, out: &Path) -> (usize, u64, usize) {
    let listing = std::fs::read_to_string(out.join("device/sdcard_listing.txt")).unwrap_or_default();
    let base = "/storage/emulated/0";
    let files: Vec<_> = crate::artifacts::parse_ls(&listing, base)
        .into_iter()
        .filter(|f| f.path.strip_prefix(&format!("{base}/")).is_some_and(|r| !skipped(r)))
        .collect();
    let total: u64 = files.iter().map(|f| f.size).sum();
    println!("\x1b[2m  shared storage: {} file(s), {:.1} MB…\x1b[0m", files.len(), total as f64 / 1_048_576.0);
    let (mut ok, mut failed) = (0, 0);
    for f in &files {
        let rel = &f.path[base.len() + 1..];
        let dst = out.join("storage").join(rel);
        if let Some(p) = dst.parent() {
            let _ = std::fs::create_dir_all(p);
        }
        match phone.pull(&f.path, &dst) {
            Ok(()) => ok += 1,
            Err(_) => failed += 1,
        }
    }
    (ok, total, failed)
}

// ---------------------------------------------------------------- hash sets

/// Hashes from a hash-set file, with a label per hash:
/// VICS JSON (Project VIC, CAID: `MD5` / `SHA1` / `SHA256` + `Category`),
/// NSRL (legacy `NSRLFile.txt` CSV or RDSv3 SQLite), or any text with one
/// hex hash per line (32 = MD5, 40 = SHA-1, 64 = SHA-256).
pub fn load_hashset(path: &Path) -> Result<Vec<(Kind, String, String)>, String> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    let kind_of = |h: &str| match h.len() {
        32 => Some(Kind::Md5),
        40 => Some(Kind::Sha1),
        64 => Some(Kind::Sha256),
        _ => None,
    };
    if bytes.starts_with(b"SQLite format 3\0") {
        let c = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| e.to_string())?;
        // ponytail: whole RDSv3 FILE table in memory; a full NSRL set needs per-hash queries instead.
        let mut st = c.prepare("SELECT sha256, sha1, md5 FROM FILE").map_err(|e| format!("{name}: not an NSRL RDSv3 database ({e})"))?;
        let rows = st.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?))).map_err(|e| e.to_string())?;
        for (a, b, c) in rows.flatten() {
            for h in [a, b, c].into_iter().flatten() {
                if let Some(k) = kind_of(&h) {
                    out.push((k, h.to_lowercase(), name.clone()));
                }
            }
        }
        return Ok(out);
    }
    let text = String::from_utf8_lossy(&bytes);
    if text.trim_start().starts_with('{') || text.trim_start().starts_with('[') {
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("{name}: {e}"))?;
        fn walk(v: &Value, name: &str, out: &mut Vec<(Kind, String, String)>) {
            match v {
                Value::Object(m) => {
                    let cat = m.iter().find(|(k, _)| k.eq_ignore_ascii_case("category")).map(|(_, c)| c.to_string().trim_matches('"').to_string());
                    let label = match cat {
                        Some(c) => format!("{name} (category {c})"),
                        None => name.to_string(),
                    };
                    for (k, x) in m {
                        let kind = match k.to_ascii_uppercase().as_str() {
                            "MD5" => Some(Kind::Md5),
                            "SHA1" | "SHA-1" => Some(Kind::Sha1),
                            "SHA256" | "SHA-256" => Some(Kind::Sha256),
                            _ => None,
                        };
                        match (kind, x.as_str()) {
                            (Some(kd), Some(h)) if !h.is_empty() => out.push((kd, h.to_lowercase(), label.clone())),
                            _ => walk(x, name, out),
                        }
                    }
                }
                Value::Array(a) => a.iter().for_each(|x| walk(x, name, out)),
                _ => {}
            }
        }
        walk(&v, &name, &mut out);
        return Ok(out);
    }
    for line in text.lines() {
        for tok in line.split([',', '"', '\t', ' ', ';']) {
            if tok.chars().all(|c| c.is_ascii_hexdigit()) {
                if let Some(k) = kind_of(tok) {
                    out.push((k, tok.to_lowercase(), name.clone()));
                }
            }
        }
    }
    Ok(out)
}

/// Load alert hash sets into the IOC set: a match becomes an `IOC_MATCH` finding.
pub fn load_alert_hashsets(iocs: &mut IocSet, files: &[PathBuf]) -> Result<(), String> {
    for f in files {
        let hs = load_hashset(f)?;
        eprintln!("\x1b[2mLoaded {} hash(es) from {}\x1b[0m", hs.len(), f.display());
        for (k, h, label) in &hs {
            iocs.insert(*k, h, &format!("hash set: {label}"));
        }
        iocs.sources.push((f.display().to_string(), hs.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------- metadata

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Meta {
    /// Device-local `YYYY-MM-DD HH:MM:SS` (EXIF DateTimeOriginal / MP4 creation).
    pub taken: Option<String>,
    pub make: Option<String>,
    pub model: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

fn exif_meta(path: &Path) -> Meta {
    let mut m = Meta::default();
    let Ok(f) = std::fs::File::open(path) else { return m };
    let Ok(ex) = exif::Reader::new().read_from_container(&mut std::io::BufReader::new(f)) else { return m };
    let s = |t: exif::Tag| ex.get_field(t, exif::In::PRIMARY).map(|f| f.display_value().to_string().trim_matches('"').trim().to_string()).filter(|s| !s.is_empty());
    m.make = s(exif::Tag::Make);
    m.model = s(exif::Tag::Model);
    m.taken = ex
        .get_field(exif::Tag::DateTimeOriginal, exif::In::PRIMARY)
        .or_else(|| ex.get_field(exif::Tag::DateTime, exif::In::PRIMARY))
        .and_then(|f| match &f.value {
            exif::Value::Ascii(v) => v.first().and_then(|b| exif::DateTime::from_ascii(b).ok()),
            _ => None,
        })
        .map(|d| format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", d.year, d.month, d.day, d.hour, d.minute, d.second));
    let deg = |t: exif::Tag, r: exif::Tag, neg: &str| -> Option<f64> {
        let f = ex.get_field(t, exif::In::PRIMARY)?;
        let exif::Value::Rational(v) = &f.value else { return None };
        if v.len() < 3 {
            return None;
        }
        let d = v[0].to_f64() + v[1].to_f64() / 60.0 + v[2].to_f64() / 3600.0;
        let sign = if s(r).is_some_and(|x| x.starts_with(neg)) { -1.0 } else { 1.0 };
        Some(d * sign)
    };
    m.lat = deg(exif::Tag::GPSLatitude, exif::Tag::GPSLatitudeRef, "S");
    m.lon = deg(exif::Tag::GPSLongitude, exif::Tag::GPSLongitudeRef, "W");
    // 0,0 is "no fix" written by some cameras.
    if m.lat == Some(0.0) && m.lon == Some(0.0) {
        m.lat = None;
        m.lon = None;
    }
    m
}

/// ISO 6709 location in an MP4 / MOV / 3GP (`©xyz` atom, e.g. `+48.8566+002.3522/`).
pub fn mp4_location(bytes: &[u8]) -> Option<(f64, f64)> {
    let i = bytes.windows(4).position(|w| w == b"\xa9xyz")?;
    // '©xyz', then u16 length and u16 language, then the string.
    let s: String = bytes.get(i + 8..)?.iter().take(40).map(|&b| b as char).take_while(|c| "+-.0123456789".contains(*c)).collect();
    let starts: Vec<usize> = s.char_indices().filter(|(_, c)| *c == '+' || *c == '-').map(|(i, _)| i).chain([s.len()]).collect();
    let part = |k: usize| s.get(*starts.get(k)?..*starts.get(k + 1)?)?.parse::<f64>().ok();
    Some((part(0)?, part(1)?))
}

pub fn file_meta(path: &Path) -> Meta {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" | "heic" | "heif" | "png" | "webp" | "tif" | "tiff" | "dng" => exif_meta(path),
        "mp4" | "mov" | "3gp" | "m4v" => {
            let mut m = Meta::default();
            // Location atoms sit in `moov`, at the start or the end of the file.
            if let Ok(mut f) = std::fs::File::open(path) {
                let len = f.metadata().map(|x| x.len()).unwrap_or(0);
                let mut head = vec![0u8; (1 << 20).min(len as usize)];
                let _ = f.read_exact(&mut head);
                let mut tail = Vec::new();
                if len > (2 << 20) {
                    use std::io::Seek;
                    let _ = f.seek(std::io::SeekFrom::End(-(1 << 20)));
                    let _ = f.read_to_end(&mut tail);
                }
                if let Some((la, lo)) = mp4_location(&head).or_else(|| mp4_location(&tail)) {
                    m.lat = Some(la);
                    m.lon = Some(lo);
                }
            }
            m
        }
        _ => Meta::default(),
    }
}

pub fn storage_files(case: &Case) -> Vec<PathBuf> {
    let root = case.root.join("storage");
    walkdir::WalkDir::new(&root).into_iter().flatten().filter(|e| e.file_type().is_file()).map(|e| e.into_path()).collect()
}

/// Timeline events: when each photo / video was taken, and where.
pub fn events(case: &Case) -> Vec<Event> {
    let files = storage_files(case);
    let metas = crate::par_map(&files, |p| file_meta(p));
    files
        .iter()
        .zip(metas)
        .filter_map(|(p, m)| {
            let rel = p.strip_prefix(&case.root).unwrap_or(p).to_string_lossy().into_owned();
            let at = match (m.lat, m.lon) {
                (Some(a), Some(o)) => format!(" at {a:.6},{o:.6}"),
                _ => String::new(),
            };
            let cam = [m.make.as_deref(), m.model.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
            Some(Event {
                local: m.taken?,
                desc: if at.is_empty() { "media:taken".into() } else { "media:taken+gps".into() },
                source: "exif".into(),
                package: String::new(),
                message: format!("{rel} taken{at}{}", if cam.is_empty() { String::new() } else { format!(" ({cam})") }),
            })
        })
        .collect()
}

/// Full inventory row.
pub struct Item {
    pub rel: String,
    pub size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub meta: Meta,
    pub known: bool,
    pub alert: Option<String>,
}

pub fn inventory(case: &Case, known: &HashSet<String>, alert: &IocSet) -> Vec<Item> {
    let files = storage_files(case);
    crate::par_map(&files, |p| {
        let [sha256, sha1, md5] = crate::ioc::file_hashes(p)?;
        let size = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let alert = [(Kind::Sha256, &sha256), (Kind::Sha1, &sha1), (Kind::Md5, &md5)].iter().find_map(|(k, h)| alert.get(*k, h).cloned());
        Some(Item {
            rel: p.strip_prefix(case.root.join("storage")).unwrap_or(p).to_string_lossy().into_owned(),
            size,
            known: known.contains(&sha256) || known.contains(&sha1) || known.contains(&md5),
            sha256,
            sha1,
            md5,
            meta: file_meta(p),
            alert,
        })
    })
    .into_iter()
    .flatten()
    .collect()
}

fn csv(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

fn xml_esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// media.csv, locations.kml, locations.geojson into `dir`.
pub fn export(case: &Case, items: &[Item], dir: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut c = String::from("path,size,sha256,sha1,md5,taken,make,model,latitude,longitude,known,alert\n");
    for i in items {
        let o = |v: Option<f64>| v.map(|x| format!("{x:.6}")).unwrap_or_default();
        c.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{}\n",
            csv(&i.rel),
            i.size,
            i.sha256,
            i.sha1,
            i.md5,
            csv(&i.meta.taken.as_deref().map(|t| case.iso(t)).unwrap_or_default()),
            csv(i.meta.make.as_deref().unwrap_or("")),
            csv(i.meta.model.as_deref().unwrap_or("")),
            o(i.meta.lat),
            o(i.meta.lon),
            i.known,
            csv(i.alert.as_deref().unwrap_or(""))
        ));
    }
    let located: Vec<&Item> = items.iter().filter(|i| i.meta.lat.is_some() && i.meta.lon.is_some()).collect();
    let mut k = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\"><Document><name>APEX media locations</name>\n");
    let mut features = Vec::new();
    for i in &located {
        let (la, lo) = (i.meta.lat.unwrap(), i.meta.lon.unwrap());
        let when = i.meta.taken.as_deref().map(|t| case.iso(t)).unwrap_or_default();
        k.push_str(&format!(
            "<Placemark><name>{}</name>{}<description>sha256 {}</description><Point><coordinates>{lo:.6},{la:.6}</coordinates></Point></Placemark>\n",
            xml_esc(&i.rel),
            if when.is_empty() { String::new() } else { format!("<TimeStamp><when>{when}</when></TimeStamp>") },
            i.sha256
        ));
        features.push(json!({"type": "Feature", "geometry": {"type": "Point", "coordinates": [lo, la]}, "properties": {"path": i.rel, "taken": when, "sha256": i.sha256}}));
    }
    k.push_str("</Document></kml>\n");
    let files = [
        (dir.join("media.csv"), c),
        (dir.join("locations.kml"), k),
        (dir.join("locations.geojson"), serde_json::to_string_pretty(&json!({"type": "FeatureCollection", "features": features})).unwrap_or_default()),
    ];
    let mut out = Vec::new();
    for (p, body) in files {
        std::fs::write(&p, body).map_err(|e| format!("{}: {e}", p.display()))?;
        out.push(p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp4_xyz() {
        let mut b = vec![0u8; 100];
        b.extend(b"\x00\x00\x00\x1e\xa9xyz\x00\x12\x15\xc7+48.8566+002.3522/");
        assert_eq!(mp4_location(&b), Some((48.8566, 2.3522)));
        let mut c = vec![0u8; 10];
        c.extend(b"\x00\x00\x00\x1e\xa9xyz\x00\x12\x15\xc7-33.8688+151.2093+012.000/");
        assert_eq!(mp4_location(&c), Some((-33.8688, 151.2093)));
    }

    #[test]
    fn hashsets() {
        let d = tempfile::tempdir().unwrap();
        let v = d.path().join("vics.json");
        std::fs::write(&v, r#"{"value":[{"Media":[{"MD5":"D41D8CD98F00B204E9800998ECF8427E","SHA1":"","Category":1}]}]}"#).unwrap();
        let h = load_hashset(&v).unwrap();
        assert_eq!(h, vec![(Kind::Md5, "d41d8cd98f00b204e9800998ecf8427e".into(), "vics.json (category 1)".into())]);
        let n = d.path().join("NSRLFile.txt");
        std::fs::write(&n, "\"SHA-1\",\"MD5\",\"CRC32\",\"FileName\"\n\"0000004DA6391F7F5D2F7FCCF36CEBDA60C6EA02\",\"0E53C14A3E48D94FF596A2824307B492\",\"AA6A7B16\",\"x.gif\"\n").unwrap();
        assert_eq!(load_hashset(&n).unwrap().len(), 2);
    }
}
