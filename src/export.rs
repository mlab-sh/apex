//! `apex export`: a case laid out like a file-system extraction
//! (`data/media/0/…`, `data/app/…`, `data/data/<pkg>/…`), for tools that read
//! extractions (ALEAPP, lab suites). Real copies, never hard links: a tool
//! opening an exported database read-write must not touch the evidence. On
//! APFS / btrfs / XFS the copy is a copy-on-write clone (instant, no extra
//! space). Every file's SHA-256 is checked against the source and listed in
//! `export_manifest.json`.

use crate::case::Case;
use serde_json::json;
use std::path::{Path, PathBuf};

pub struct Summary {
    pub files: usize,
    pub bytes: u64,
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir).into_iter().flatten().filter(|e| e.file_type().is_file()).map(|e| e.into_path()).collect()
}

/// Extraction path for a file of the case (relative to the case root), if any.
pub fn target(rel: &str) -> Option<String> {
    let (top, rest) = rel.split_once('/')?;
    match top {
        "storage" => Some(format!("data/media/0/{rest}")),
        "apps" => {
            let (pkg, file) = rest.split_once('/')?;
            file.ends_with(".apk").then(|| format!("data/app/~~apex==/{pkg}-apex==/{file}"))
        }
        "comms" => {
            if let Some(r) = rest.strip_prefix("app/") {
                let (pkg, inner) = r.split_once('/')?;
                if let Some(f) = inner.strip_prefix("backups/") {
                    return Some(if f.starts_with("signal-") {
                        format!("data/media/0/Signal/Backups/{f}")
                    } else if pkg.ends_with("w4b") {
                        format!("data/media/0/Android/media/{pkg}/WhatsApp Business/Databases/{f}")
                    } else {
                        format!("data/media/0/Android/media/{pkg}/WhatsApp/Databases/{f}")
                    });
                }
                return Some(format!("data/data/{pkg}/{inner}"));
            }
            if let Some(f) = rest.strip_prefix("mms_parts/") {
                return Some(format!("{}{f}", crate::comms::MMS_PARTS_DIR));
            }
            let f = rest.strip_prefix("db/")?;
            let (base, ext) = ["-wal", "-journal"].iter().find_map(|e| f.strip_suffix(e).map(|b| (b, *e))).unwrap_or((f, ""));
            crate::comms::DATABASES.iter().find(|(_, n)| *n == base).map(|(p, _)| format!("{p}{ext}"))
        }
        "backup" => crate::backup::data_path(rest),
        _ => None,
    }
}

fn place(src: &Path, dst: &Path) -> Result<(), String> {
    if let Some(p) = dst.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    if !dst.exists() {
        std::fs::copy(src, dst).map_err(|e| format!("{} → {}: {e}", src.display(), dst.display()))?;
    }
    Ok(())
}

pub fn export(case: &Case, out: &Path) -> Result<Summary, String> {
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut list = Vec::new();
    let mut s = Summary { files: 0, bytes: 0 };
    for src in walk(&case.root) {
        let rel = src.strip_prefix(&case.root).unwrap_or(&src).to_string_lossy().replace('\\', "/");
        // Case metadata (manifest, device dumps, agent output) goes under apex/, unchanged.
        let dest = target(&rel).unwrap_or_else(|| format!("apex/{rel}"));
        let dst = out.join(&dest);
        place(&src, &dst)?;
        let (a, b) = (crate::scanner::compute_hash(&src).unwrap_or_default(), crate::scanner::compute_hash(&dst).unwrap_or_default());
        if a != b {
            return Err(format!("{dest}: hash differs from the case file after copy"));
        }
        let n = std::fs::metadata(&dst).map(|m| m.len()).unwrap_or(0);
        s.files += 1;
        s.bytes += n;
        list.push(json!({"source": rel, "path": dest, "sha256": a, "bytes": n}));
    }
    let manifest = json!({
        "tool": format!("APEX {}", env!("CARGO_PKG_VERSION")),
        "exported_utc": chrono::Utc::now().to_rfc3339(),
        "case": case.root.display().to_string(),
        "note": "Logical acquisition laid out as a file-system extraction. Only what the case holds is here: no system databases or app private data unless the case was imported from a lab extraction.",
        "files": list,
    });
    std::fs::write(out.join("export_manifest.json"), serde_json::to_string_pretty(&manifest).unwrap_or_default()).map_err(|e| e.to_string())?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        assert_eq!(target("storage/DCIM/Camera/a.jpg").as_deref(), Some("data/media/0/DCIM/Camera/a.jpg"));
        assert_eq!(target("apps/com.x/base.apk").as_deref(), Some("data/app/~~apex==/com.x-apex==/base.apk"));
        assert_eq!(target("apps/com.x/dumpsys_package.txt"), None);
        assert_eq!(target("comms/db/msgstore.db-wal").as_deref(), Some("data/data/com.whatsapp/databases/msgstore.db-wal"));
        assert_eq!(target("comms/app/com.whatsapp/backups/msgstore.db.crypt15").as_deref(), Some("data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/msgstore.db.crypt15"));
        assert_eq!(target("comms/app/org.thoughtcrime.securesms/databases/signal.db").as_deref(), Some("data/data/org.thoughtcrime.securesms/databases/signal.db"));
        assert_eq!(target("backup/apps/com.y/db/x.db").as_deref(), Some("data/data/com.y/databases/x.db"));
        assert_eq!(target("device/getprop.txt"), None);
    }
}
