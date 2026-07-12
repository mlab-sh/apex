//! Android platform deep checks — StrictMode, broadcast ordering, zip slip,
//! backup agent, signature bypass.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx, rx_flags};
use std::path::Path;

use Severity::*;

pub struct AndroidPlatformDeepAnalyzer;

impl Analyzer for AndroidPlatformDeepAnalyzer {
    fn name(&self) -> &'static str {
        "Android Platform Deep Checks"
    }
    fn category(&self) -> &'static str {
        "platform"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let paths = find_files_by_ext(extracted, &["java", "kt", "smali"]);
        let files: Vec<(String, String)> = paths
            .iter()
            .filter_map(|p| read_text(p).map(|c| (rel(p, extracted), c)))
            .collect();

        let mut findings = Vec::new();
        findings.extend(check_strictmode(&files));
        findings.extend(check_broadcast_ordering(&files));
        findings.extend(check_zip_slip(&files));
        findings.extend(check_backup_agent(extracted));
        findings.extend(check_signature_bypass(&files));
        findings
    }
}

fn check_strictmode(files: &[(String, String)]) -> Vec<Finding> {
    let patterns = [
        (r#"StrictMode\.setThreadPolicy\s*\(\s*StrictMode\.ThreadPolicy\.LAX"#, "StrictMode set to LAX (all violations allowed)"),
        (r#"StrictMode\.ThreadPolicy\.Builder\(\)\.permitAll\(\)"#, "StrictMode ThreadPolicy permits all (disk/network on main thread)"),
        (r#"StrictMode\.VmPolicy\.Builder\(\)\.permitAll\(\)"#, "StrictMode VmPolicy permits all"),
        (r#"NetworkOnMainThreadException"#, "Potential NetworkOnMainThread (StrictMode violation indicator)"),
    ];
    let compiled: Vec<_> = patterns.iter().map(|(p, d)| (rx(p), *d)).collect();
    let mut findings = Vec::new();
    for (rel_path, content) in files {
        for (re, desc) in &compiled {
            if let Ok(Some(m)) = re.find(content) {
                let line = line_of(content, m.start());
                let short: String = desc.chars().take(50).collect();
                findings.push(
                    Finding::new(
                        "PLAT_STRICTMODE",
                        format!("StrictMode issue: {short}"),
                        format!("{desc} in {rel_path}:{line}. StrictMode violations can cause ANRs and poor UX."),
                        Low,
                        "platform",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .masvs("MASVS-CODE"),
                );
                break;
            }
        }
    }
    findings
}

fn check_broadcast_ordering(files: &[(String, String)]) -> Vec<Finding> {
    let re = rx(r#"sendOrderedBroadcast\s*\("#);
    let mut findings = Vec::new();
    for (rel_path, content) in files {
        if let Ok(Some(m)) = re.find(content) {
            let line = line_of(content, m.start());
            let end = (m.start() + 200).min(content.len());
            let context = &content[m.start()..end];
            let before_paren = context.split(')').next().unwrap_or("");
            if before_paren.contains("null") {
                findings.push(
                    Finding::new(
                        "PLAT_ORDERED_BROADCAST",
                        "Ordered broadcast without result receiver",
                        format!(
                            "sendOrderedBroadcast() in {rel_path}:{line} with null result receiver. A higher-priority receiver can abort or modify the broadcast."
                        ),
                        Medium,
                        "platform",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .cwe("CWE-927")
                    .masvs("MASVS-PLATFORM"),
                );
            }
        }
    }
    findings
}

fn check_zip_slip(files: &[(String, String)]) -> Vec<Finding> {
    let zip_re = rx(r#"(ZipInputStream|ZipEntry|\.getName\(\).*new\s+File|ZipFile\s*\()"#);
    let valid_re = rx_flags(
        r#"(\.contains\s*\(\s*["']\.\.["']|canonical|normalize|startsWith|Zip\s*Slip|traversal)"#,
        true,
        false,
        false,
    );
    let mut findings = Vec::new();
    for (rel_path, content) in files {
        let m = match zip_re.find(content) {
            Ok(Some(m)) => m,
            _ => continue,
        };
        let has_validation = valid_re.is_match(content).unwrap_or(false);
        if !has_validation {
            let line = line_of(content, m.start());
            findings.push(
                Finding::new(
                    "PLAT_ZIP_SLIP",
                    "Potential Zip Slip vulnerability",
                    format!(
                        "Zip extraction in {rel_path}:{line} without apparent path traversal validation. An attacker could craft a ZIP with '../' entries to write files outside the target directory."
                    ),
                    High,
                    "platform",
                )
                .file_path(rel_path.clone())
                .line(line)
                .cwe("CWE-22")
                .masvs("MASVS-CODE"),
            );
        }
    }
    findings
}

fn check_backup_agent(extracted: &Path) -> Vec<Finding> {
    let manifest = extracted.join("AndroidManifest.xml");
    if !manifest.exists() {
        return vec![];
    }
    let raw = match std::fs::read(&manifest) {
        Ok(r) => r,
        Err(_) => return vec![],
    };
    let content = String::from_utf8_lossy(&raw);
    let mut findings = Vec::new();

    if content.contains("fullBackupContent") {
        findings.push(
            Finding::new(
                "PLAT_BACKUP_RULES",
                "Custom backup rules (fullBackupContent)",
                "The app defines fullBackupContent rules. Review which data is included/excluded from backups to ensure sensitive data is not backed up.",
                Info,
                "platform",
            )
            .masvs("MASVS-STORAGE"),
        );
    }
    if content.contains("backupAgent") {
        findings.push(
            Finding::new(
                "PLAT_BACKUP_AGENT",
                "Custom BackupAgent defined",
                "The app uses a custom BackupAgent. Verify that the backup/restore logic does not expose sensitive data or introduce deserialization vulnerabilities.",
                Medium,
                "platform",
            )
            .cwe("CWE-530")
            .masvs("MASVS-STORAGE"),
        );
    }
    findings
}

fn check_signature_bypass(files: &[(String, String)]) -> Vec<Finding> {
    let patterns = [
        (r#"PackageManager\.GET_SIGNATURES.*==\s*0"#, "Signature check always passing (== 0)"),
        (r#"signatures\s*==\s*null\s*\|\|\s*signatures\.length\s*==\s*0"#, "Null/empty signature check (may be bypassable)"),
        (r#"\.verify\s*\([^)]*\)\s*\{\s*return\s+true"#, "Signature verify always returns true"),
        (r#"checkSignatures.*SIGNATURE_MATCH"#, "Signature comparison (verify it's not bypassed)"),
    ];
    let compiled: Vec<_> = patterns
        .iter()
        .map(|(p, d)| (rx_flags(p, false, true, false), *d))
        .collect();
    let mut findings = Vec::new();
    for (rel_path, content) in files {
        for (re, desc) in &compiled {
            if let Ok(Some(m)) = re.find(content) {
                let line = line_of(content, m.start());
                findings.push(
                    Finding::new(
                        "PLAT_SIG_BYPASS",
                        "Signature verification issue",
                        format!("{desc} in {rel_path}:{line}. Weak signature verification can be bypassed by repackaging."),
                        High,
                        "platform",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .cwe("CWE-347")
                    .masvs("MASVS-RESILIENCE"),
                );
                break;
            }
        }
    }
    findings
}
