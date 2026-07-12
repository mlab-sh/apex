//! JAR/AAR analysis — embedded ELF binaries, obfuscation, trackers, manifests, certs.

use super::Analyzer;
use crate::cert_util::parse_pkcs7;
use crate::elf_util::parse_bytes;
use crate::models::{AppType, Finding, Severity};
use crate::util::{rel, walk_all_files};
use crate::xml;
use serde_json::json;
use std::io::Read;
use std::path::Path;

use Severity::*;

const TRACKER_PACKAGES: &[(&str, &str)] = &[
    ("com/google/firebase/analytics", "Google Firebase Analytics"),
    ("com/google/android/gms/analytics", "Google Analytics"),
    ("com/google/android/gms/ads", "Google Ads (AdMob)"),
    ("com/facebook/appevents", "Facebook App Events"),
    ("com/facebook/ads", "Facebook Audience Network"),
    ("com/adjust/sdk", "Adjust SDK"),
    ("com/appsflyer", "AppsFlyer"),
    ("io/branch", "Branch.io"),
    ("com/crashlytics", "Crashlytics"),
    ("com/flurry", "Flurry Analytics"),
    ("com/mixpanel", "Mixpanel"),
    ("com/amplitude", "Amplitude"),
    ("com/segment/analytics", "Segment"),
    ("com/newrelic", "New Relic"),
    ("io/sentry", "Sentry"),
    ("com/braze", "Braze"),
    ("com/onesignal", "OneSignal"),
    ("com/appdynamics", "AppDynamics"),
    ("com/bugsnag", "Bugsnag"),
    ("com/kochava", "Kochava"),
    ("com/moengage", "MoEngage"),
    ("com/clevertap", "CleverTap"),
    ("com/batch/android", "Batch"),
];

pub struct JarAarAnalyzer;

impl Analyzer for JarAarAnalyzer {
    fn name(&self) -> &'static str {
        "JAR/AAR Analysis"
    }
    fn category(&self) -> &'static str {
        "jar_aar"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let mut archives: Vec<_> = walk_all_files(extracted)
            .into_iter()
            .filter(|p| {
                matches!(
                    p.extension().and_then(|e| e.to_str()),
                    Some("jar") | Some("aar")
                )
            })
            .collect();
        // jars first, then aars, each sorted (mirrors rglob order roughly).
        archives.sort_by_key(|p| {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("").to_string();
            (if ext == "jar" { 0 } else { 1 }, p.clone())
        });

        let mut findings = Vec::new();
        for archive in &archives {
            let rel_archive = rel(archive, extracted);
            findings.extend(analyze_archive(archive, &rel_archive));
        }
        findings
    }
}

fn analyze_archive(archive_path: &Path, rel_archive: &str) -> Vec<Finding> {
    let file = match std::fs::File::open(archive_path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };
    let mut zip = match zip::ZipArchive::new(file) {
        Ok(z) => z,
        Err(_) => return vec![],
    };
    let namelist: Vec<String> = (0..zip.len())
        .filter_map(|i| zip.by_index(i).ok().map(|e| e.name().to_string()))
        .collect();

    let mut findings = Vec::new();
    findings.extend(check_elf_in_archive(&mut zip, &namelist, rel_archive));
    findings.extend(check_obfuscation(&mut zip, &namelist, rel_archive));
    findings.extend(check_trackers(&namelist, rel_archive));
    findings.extend(check_aar_manifest(&mut zip, &namelist, rel_archive));
    findings.extend(check_certificates(&mut zip, &namelist, rel_archive));
    findings
}

fn read_entry(zip: &mut zip::ZipArchive<std::fs::File>, name: &str) -> Option<Vec<u8>> {
    let mut entry = zip.by_name(name).ok()?;
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).ok()?;
    Some(buf)
}

fn check_elf_in_archive(
    zip: &mut zip::ZipArchive<std::fs::File>,
    namelist: &[String],
    rel_archive: &str,
) -> Vec<Finding> {
    let so_files: Vec<&String> = namelist.iter().filter(|n| n.ends_with(".so")).collect();
    let mut findings = Vec::new();
    for so_name in so_files {
        let data = match read_entry(zip, so_name) {
            Some(d) => d,
            None => continue,
        };
        let info = match parse_bytes(&data) {
            Some(i) => i,
            None => continue,
        };
        let has_nx = info.nx;
        let is_pie = info.pie;
        let has_canary = info.canary;

        let mut severity = Info;
        let mut issues = Vec::new();
        if !has_nx {
            issues.push("NX disabled");
            severity = High;
        }
        if !is_pie {
            issues.push("not PIE");
            severity = High;
        }
        if !has_canary {
            issues.push("no stack canary");
            if severity == Info {
                severity = Medium;
            }
        }
        let issues_str = if issues.is_empty() {
            String::new()
        } else {
            format!(" Issues: {}.", issues.join(", "))
        };
        findings.push(
            Finding::new(
                "JAR_ELF_FOUND",
                format!("ELF binary in archive: {so_name}"),
                format!(
                    "Native library '{so_name}' found inside {rel_archive}. Checksec: NX={}, PIE={}, Canary={}.{}",
                    if has_nx { "yes" } else { "NO" },
                    if is_pie { "yes" } else { "NO" },
                    if has_canary { "yes" } else { "NO" },
                    issues_str
                ),
                severity,
                "jar_aar",
            )
            .file_path(rel_archive)
            .masvs("MASVS-CODE")
            .meta("so_name", json!(so_name))
            .meta("nx", json!(has_nx))
            .meta("pie", json!(is_pie))
            .meta("canary", json!(has_canary)),
        );
    }
    findings
}

fn check_obfuscation(
    zip: &mut zip::ZipArchive<std::fs::File>,
    namelist: &[String],
    rel_archive: &str,
) -> Vec<Finding> {
    let class_files: Vec<&String> = namelist.iter().filter(|n| n.ends_with(".class")).collect();
    if class_files.is_empty() {
        return vec![];
    }
    let sample_size = class_files.len().min(20);
    let mut has_debug_info = 0usize;
    let mut checked = 0usize;
    for class_name in class_files.iter().take(sample_size) {
        if let Some(data) = read_entry(zip, class_name) {
            checked += 1;
            if find_bytes(&data, b"LocalVariableTable") {
                has_debug_info += 1;
            }
        }
    }
    if checked == 0 {
        return vec![];
    }
    let debug_ratio = has_debug_info as f64 / checked as f64;
    let total_classes = class_files.len();

    if debug_ratio > 0.5 {
        vec![Finding::new(
            "JAR_NOT_OBFUSCATED",
            format!("Code not obfuscated: {rel_archive}"),
            format!(
                "Archive '{rel_archive}' contains {total_classes} class file(s). {has_debug_info}/{checked} sampled classes have LocalVariableTable (debug info). Code is likely NOT obfuscated with ProGuard/R8."
            ),
            Medium,
            "jar_aar",
        )
        .file_path(rel_archive)
        .masvs("MASVS-RESILIENCE")
        .meta("total_classes", json!(total_classes))
        .meta("debug_ratio", json!(round2(debug_ratio)))
        .meta("sampled", json!(checked))]
    } else {
        vec![Finding::new(
            "JAR_OBFUSCATED",
            format!("Code appears obfuscated: {rel_archive}"),
            format!(
                "Archive '{rel_archive}' contains {total_classes} class file(s). {has_debug_info}/{checked} sampled classes have debug info. Code appears obfuscated (ProGuard/R8/DexGuard)."
            ),
            Info,
            "jar_aar",
        )
        .file_path(rel_archive)
        .meta("total_classes", json!(total_classes))
        .meta("debug_ratio", json!(round2(debug_ratio)))
        .meta("sampled", json!(checked))]
    }
}

fn check_trackers(namelist: &[String], rel_archive: &str) -> Vec<Finding> {
    let found: Vec<String> = TRACKER_PACKAGES
        .iter()
        .filter(|(pat, _)| namelist.iter().any(|n| n.starts_with(pat)))
        .map(|(_, name)| name.to_string())
        .collect();
    if found.is_empty() {
        return vec![];
    }
    vec![Finding::new(
        "JAR_TRACKERS",
        format!("Tracker libraries ({}): {rel_archive}", found.len()),
        format!(
            "Found {} tracker/analytics library(ies) in {rel_archive}: {}.",
            found.len(),
            found.join(", ")
        ),
        Medium,
        "jar_aar",
    )
    .file_path(rel_archive)
    .masvs("MASVS-PRIVACY")
    .meta("trackers", json!(found))]
}

fn check_aar_manifest(
    zip: &mut zip::ZipArchive<std::fs::File>,
    namelist: &[String],
    rel_archive: &str,
) -> Vec<Finding> {
    if !rel_archive.ends_with(".aar") {
        return vec![];
    }
    if !namelist.iter().any(|n| n == "AndroidManifest.xml") {
        return vec![];
    }
    let data = match read_entry(zip, "AndroidManifest.xml") {
        Some(d) => d,
        None => return vec![],
    };
    if let Some(root) = xml::parse_axml_or_xml(&data) {
        let package = root.attr("package").unwrap_or("unknown").to_string();
        return vec![Finding::new(
            "JAR_AAR_MANIFEST",
            format!("AAR manifest: {package}"),
            format!("AAR '{rel_archive}' contains AndroidManifest.xml for package '{package}'."),
            Info,
            "jar_aar",
        )
        .file_path(rel_archive)
        .meta("package", json!(package))];
    }
    vec![]
}

fn check_certificates(
    zip: &mut zip::ZipArchive<std::fs::File>,
    namelist: &[String],
    rel_archive: &str,
) -> Vec<Finding> {
    let sig_files: Vec<String> = namelist
        .iter()
        .filter(|n| {
            n.starts_with("META-INF/") && {
                let up = n.to_uppercase();
                up.ends_with(".RSA") || up.ends_with(".DSA") || up.ends_with(".EC")
            }
        })
        .cloned()
        .collect();

    let mut findings = Vec::new();
    for sig_name in sig_files {
        let raw = match read_entry(zip, &sig_name) {
            Some(r) => r,
            None => continue,
        };
        for cert in parse_pkcs7(&raw) {
            findings.push(
                Finding::new(
                    "JAR_CERTIFICATE",
                    format!("Certificate in archive: {rel_archive}"),
                    format!(
                        "X.509 certificate found in {rel_archive}/{sig_name}. Subject: {}.",
                        cert.subject
                    ),
                    Info,
                    "jar_aar",
                )
                .file_path(rel_archive)
                .meta("sig_file", json!(sig_name))
                .meta("subject", json!(cert.subject)),
            );
        }
    }
    findings
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
