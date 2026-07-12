//! JSON export (`--json`).

use crate::models::ScanResult;
use std::path::{Path, PathBuf};

pub fn export_json(result: &ScanResult, output_path: Option<&Path>) -> std::io::Result<PathBuf> {
    let data = result.to_json();
    let json_str = serde_json::to_string_pretty(&data).unwrap_or_default();

    let out_path: PathBuf = match output_path {
        Some(p) => p.to_path_buf(),
        None => {
            let stem = Path::new(&result.file_path)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("report");
            PathBuf::from(format!("{stem}_report.json"))
        }
    };
    std::fs::write(&out_path, json_str)?;
    Ok(out_path)
}
