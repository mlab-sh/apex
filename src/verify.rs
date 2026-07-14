//! Re-verify a forensic evidence bundle: recompute hashes and confirm nothing
//! changed since acquisition.
//!
//! Checks (a) the manifest's own SHA-256 against the detached
//! `manifest.json.sha256`, and (b) every file present in the bundle against the
//! hashes recorded in the manifest (reports, artifacts, inputs, audit log).
//! Matching is by hash, so it survives the bundle being moved or renamed.

use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct VerifyReport {
    pub manifest_ok: Option<bool>,
    pub matched: Vec<String>,
    pub unlisted: Vec<String>,
    pub missing: Vec<String>,
    /// Recorded inputs that live outside the bundle (an offline run's source
    /// extraction) — reported for information, not required to be present.
    pub external: usize,
}

impl VerifyReport {
    /// A bundle passes when the manifest self-hash is valid (or absent) and no
    /// recorded artifact is missing. Unlisted extra files are warnings only.
    pub fn passed(&self) -> bool {
        self.manifest_ok != Some(false) && self.missing.is_empty()
    }
}

/// Pure comparison of recorded `(label, hash)` pairs against present
/// `(name, hash)` pairs. `external` hashes are known-but-not-required (offline
/// source inputs): a present file matching one is not flagged, but an absent
/// external is not reported missing. Returns (matched, unlisted, missing).
fn classify(
    recorded: &[(String, String)],
    external: &[(String, String)],
    present: &[(String, String)],
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let present_hashes: HashSet<&str> = present.iter().map(|(_, h)| h.as_str()).collect();
    let mut known_hashes: HashSet<&str> = recorded.iter().map(|(_, h)| h.as_str()).collect();
    known_hashes.extend(external.iter().map(|(_, h)| h.as_str()));

    let mut matched = Vec::new();
    let mut unlisted = Vec::new();
    for (name, h) in present {
        if known_hashes.contains(h.as_str()) {
            matched.push(name.clone());
        } else {
            unlisted.push(name.clone());
        }
    }
    let mut missing = Vec::new();
    for (label, h) in recorded {
        if !present_hashes.contains(h.as_str()) {
            let short = &h[..8.min(h.len())];
            missing.push(format!("{label} ({short}…)"));
        }
    }
    (matched, unlisted, missing)
}

/// Extract `(label, sha256)` pairs from a manifest array whose objects carry a
/// `sha256` plus one of `file`/`action`/`package` as a label.
fn gather(arr: Option<&Value>, out: &mut Vec<(String, String)>) {
    let Some(Value::Array(items)) = arr else { return };
    for it in items {
        let Some(h) = it.get("sha256").and_then(|v| v.as_str()) else { continue };
        let label = it
            .get("file")
            .or_else(|| it.get("action"))
            .or_else(|| it.get("package"))
            .and_then(|v| v.as_str())
            .unwrap_or("(artifact)");
        out.push((label.to_string(), h.to_string()));
    }
}

/// Verify the bundle at `path` (a directory, or a path to its `manifest.json`).
pub fn verify_bundle(path: &Path) -> Result<VerifyReport, String> {
    let (dir, manifest_path) = if path.is_dir() {
        (path.to_path_buf(), path.join("manifest.json"))
    } else {
        (
            path.parent().unwrap_or(Path::new(".")).to_path_buf(),
            path.to_path_buf(),
        )
    };

    let manifest_bytes = std::fs::read(&manifest_path)
        .map_err(|e| format!("cannot read manifest {}: {e}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("manifest is not valid JSON: {e}"))?;

    // (a) Manifest self-hash against the detached .sha256, if present.
    let manifest_sha = crate::scanner::compute_hash(&manifest_path).ok();
    let sha_file = dir.join("manifest.json.sha256");
    let manifest_ok = match (std::fs::read_to_string(&sha_file).ok(), manifest_sha.as_ref()) {
        (Some(recorded), Some(actual)) => {
            let recorded = recorded.split_whitespace().next().unwrap_or("").to_string();
            Some(recorded.eq_ignore_ascii_case(actual))
        }
        _ => None,
    };

    // (b) Recorded artifact hashes that must be present in the bundle.
    let mut recorded: Vec<(String, String)> = Vec::new();
    gather(manifest.get("reports"), &mut recorded);
    gather(manifest.get("artifacts"), &mut recorded);
    // Offline `inputs` reference the source extraction, not the bundle.
    let mut external: Vec<(String, String)> = Vec::new();
    gather(manifest.get("inputs"), &mut external);
    if let Some(al) = manifest.get("audit_log") {
        if let (Some(f), Some(h)) = (
            al.get("file").and_then(|v| v.as_str()),
            al.get("sha256").and_then(|v| v.as_str()),
        ) {
            recorded.push((f.to_string(), h.to_string()));
        }
    }

    // Present files in the bundle (excluding the manifest + its detached hash).
    let mut present: Vec<(String, String)> = Vec::new();
    for e in walkdir::WalkDir::new(&dir).into_iter().filter_map(|e| e.ok()) {
        if !e.file_type().is_file() {
            continue;
        }
        let p = e.path();
        let name = p.strip_prefix(&dir).unwrap_or(p).to_string_lossy().into_owned();
        if name == "manifest.json" || name == "manifest.json.sha256" {
            continue;
        }
        if let Ok(h) = crate::scanner::compute_hash(p) {
            present.push((name, h));
        }
    }

    let (matched, unlisted, missing) = classify(&recorded, &external, &present);
    Ok(VerifyReport {
        manifest_ok,
        matched,
        unlisted,
        missing,
        external: external.len(),
    })
}

/// Convenience for callers that only have a directory.
#[allow(dead_code)]
pub fn verify_dir(dir: PathBuf) -> Result<VerifyReport, String> {
    verify_bundle(&dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_by_hash() {
        let recorded = vec![
            ("a.apk".into(), "hash_a".into()),
            ("b.txt".into(), "hash_b".into()),
        ];
        let present = vec![
            ("apps/a.apk".into(), "hash_a".into()),
            ("extra.log".into(), "hash_x".into()),
        ];
        let (matched, unlisted, missing) = classify(&recorded, &[], &present);
        assert_eq!(matched, vec!["apps/a.apk"]);
        assert_eq!(unlisted, vec!["extra.log"]);
        assert_eq!(missing.len(), 1); // b.txt absent
        assert!(missing[0].starts_with("b.txt"));
    }

    #[test]
    fn classify_all_present_no_missing() {
        let recorded = vec![("r".into(), "h1".into())];
        let present = vec![("report.json".into(), "h1".into())];
        let (matched, unlisted, missing) = classify(&recorded, &[], &present);
        assert_eq!(matched.len(), 1);
        assert!(unlisted.is_empty());
        assert!(missing.is_empty());
    }

    #[test]
    fn classify_external_not_missing_not_unlisted() {
        // An offline input source file is external: absent from the bundle but
        // must not count as missing; if present, it counts as matched.
        let recorded: Vec<(String, String)> = vec![];
        let external = vec![("src/app.apk".into(), "h_ext".into())];
        let present = vec![("app.apk".into(), "h_ext".into())];
        let (matched, unlisted, missing) = classify(&recorded, &external, &present);
        assert_eq!(matched.len(), 1);
        assert!(unlisted.is_empty());
        assert!(missing.is_empty());
    }
}
