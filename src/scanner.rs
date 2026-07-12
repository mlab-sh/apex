//! Static analysis orchestrator: hashing, extraction, and analyzer dispatch.

use crate::analyzers::get_analyzers;
use crate::models::{AppType, Finding, ScanResult};
use crate::xml;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub fn detect_app_type(path: &Path) -> Option<AppType> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())?;
    match ext.as_str() {
        "apk" => Some(AppType::Apk),
        "aab" => Some(AppType::Aab),
        "xapk" => Some(AppType::Xapk),
        "ipa" => Some(AppType::Ipa),
        _ => None,
    }
}

pub const VALID_EXTENSIONS: [&str; 4] = [".apk", ".aab", ".xapk", ".ipa"];

pub fn compute_hash(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Extract a zip package into `dest`, guarding against Zip Slip.
pub fn extract_package(path: &Path, dest: &Path) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let dest_canon = dest
        .canonicalize()
        .map_err(|e| e.to_string())?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        let outpath = match entry.enclosed_name() {
            Some(p) => dest.join(p),
            None => return Err(format!("Zip Slip detected: {name}")),
        };
        // Extra guard mirroring the Python resolve() check.
        if name.contains("..") {
            let joined = dest.join(&name);
            let normalized = normalize(&joined);
            if !normalized.starts_with(&dest_canon) && !normalized.starts_with(dest) {
                return Err(format!("Zip Slip detected: {name}"));
            }
        }

        if entry.is_dir() {
            std::fs::create_dir_all(&outpath).ok();
        } else {
            if let Some(parent) = outpath.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let mut out = match std::fs::File::create(&outpath) {
                Ok(f) => f,
                Err(_) => continue,
            };
            std::io::copy(&mut entry, &mut out).ok();
        }
    }
    Ok(())
}

fn normalize(p: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn extract_app_info(extracted: &Path, app_type: AppType) -> Map<String, Value> {
    let mut info = Map::new();
    if !matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk) {
        return info;
    }
    let manifest = extracted.join("AndroidManifest.xml");
    if !manifest.exists() {
        return info;
    }
    let raw = match std::fs::read(&manifest) {
        Ok(r) => r,
        Err(_) => return info,
    };
    let root = match xml::parse_axml_or_xml(&raw) {
        Some(r) => r,
        None => return info,
    };

    info.insert("package".into(), json!(root.attr("package").unwrap_or("")));
    info.insert(
        "version_name".into(),
        json!(root.android("versionName").unwrap_or("")),
    );
    info.insert(
        "version_code".into(),
        json!(root.android("versionCode").unwrap_or("")),
    );
    if let Some(uses_sdk) = root.find("uses-sdk") {
        if let Some(v) = uses_sdk.android("minSdkVersion") {
            if !v.is_empty() {
                info.insert("min_sdk".into(), sdk_value(v));
            }
        }
        if let Some(v) = uses_sdk.android("targetSdkVersion") {
            if !v.is_empty() {
                info.insert("target_sdk".into(), sdk_value(v));
            }
        }
    }
    info
}

fn sdk_value(v: &str) -> Value {
    if v.chars().all(|c| c.is_ascii_digit()) {
        json!(v.parse::<i64>().unwrap_or(0))
    } else {
        json!(v)
    }
}

pub fn scan<F: FnMut(&Finding)>(path: &Path, mut on_finding: Option<F>) -> ScanResult {
    let start = Instant::now();
    let app_type = detect_app_type(path).expect("caller validated extension");
    let file_hash = compute_hash(path).unwrap_or_default();

    let mut findings: Vec<Finding> = Vec::new();
    let mut app_info = Map::new();

    let tmp = tempfile::Builder::new()
        .prefix("apex_")
        .tempdir()
        .expect("create temp dir");
    let extracted = tmp.path();

    if extract_package(path, extracted).is_ok() {
        app_info = extract_app_info(extracted, app_type);

        for analyzer in get_analyzers() {
            if !analyzer.can_analyze(app_type) {
                continue;
            }
            let results = analyzer.analyze(extracted, app_type, path);
            for f in results {
                if let Some(cb) = on_finding.as_mut() {
                    cb(&f);
                }
                findings.push(f);
            }
        }
    }

    ScanResult {
        file_path: path.to_string_lossy().into_owned(),
        file_hash,
        app_type,
        app_info,
        findings,
        scan_duration: start.elapsed().as_secs_f64(),
    }
}
