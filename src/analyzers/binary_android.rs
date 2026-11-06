//! Android native binary (.so) analyzer — ELF checksec, symbols, strings, trackers.

use super::Analyzer;
use crate::elf_util::{extract_strings, parse_file, ElfInfo};
use crate::models::{AppType, Finding, Severity};
use crate::util::{rel, rx, walk_all_files};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;

use Severity::*;

const TRACKER_PATTERNS: &[(&str, &str)] = &[
    ("com.google.firebase.analytics", "Google Firebase Analytics"),
    ("com.google.android.gms.analytics", "Google Analytics"),
    ("com.facebook.appevents", "Facebook App Events"),
    ("com.facebook.GraphRequest", "Facebook SDK"),
    ("com.adjust.sdk", "Adjust SDK"),
    ("com.appsflyer", "AppsFlyer"),
    ("io.branch", "Branch.io"),
    ("com.crashlytics", "Crashlytics"),
    ("com.flurry", "Flurry Analytics"),
    ("com.mixpanel", "Mixpanel"),
    ("com.amplitude", "Amplitude"),
    ("com.segment", "Segment"),
    ("com.appdynamics", "AppDynamics"),
    ("com.newrelic", "New Relic"),
    ("com.bugsnag", "Bugsnag"),
    ("io.sentry", "Sentry"),
    ("com.braze", "Braze (Appboy)"),
    ("com.onesignal", "OneSignal"),
    ("com.urbanairship", "Urban Airship"),
    ("com.batch", "Batch"),
    ("com.kochava", "Kochava"),
    ("com.singular.sdk", "Singular"),
];

const FIREBASE_PATTERNS: &[&str] = &[
    r#"\.firebaseio\.com"#,
    r#"firebase-database"#,
    r#"AIza[0-9A-Za-z_-]{35}"#,
    r#"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"#,
    r#"\d+:android:[a-f0-9]+"#,
];

const DART_FLUTTER_SYMBOLS: &[&str] = &[
    "Dart_Initialize",
    "_kDartVmSnapshotInstructions",
    "dart:core",
    "flutter_engine",
    "libflutter.so",
    "libapp.so",
];

struct Checksec {
    path: String,
    nx: bool,
    pie: bool,
    canary: bool,
    relro: String,
    rpath: bool,
    stripped: bool,
    fortified: usize,
    unsafe_funcs: Vec<String>,
    dart: bool,
}

impl Checksec {
    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "nx": self.nx,
            "pie": self.pie,
            "canary": self.canary,
            "relro": self.relro,
            "rpath": self.rpath,
            "stripped": self.stripped,
            "fortified": self.fortified,
            "unsafe_funcs": self.unsafe_funcs,
            "dart": self.dart,
        })
    }
}

pub struct AndroidBinaryAnalyzer;

impl Analyzer for AndroidBinaryAnalyzer {
    fn name(&self) -> &'static str {
        "Android Native Binary (ELF)"
    }
    fn category(&self) -> &'static str {
        "binary"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let mut so_files: Vec<_> = walk_all_files(extracted)
            .into_iter()
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("so"))
            .collect();
        so_files.sort();
        if so_files.is_empty() {
            return vec![];
        }

        let mut all_checksec: Vec<Checksec> = Vec::new();
        let mut per_file: Vec<Finding> = Vec::new();

        for so in &so_files {
            let (bytes, info) = match parse_file(so) {
                Some(x) => x,
                None => continue,
            };
            let rel_path = rel(so, extracted);
            let is_dart = is_dart_flutter(&info, &rel_path);

            all_checksec.push(Checksec {
                path: rel_path.clone(),
                nx: info.nx,
                pie: info.pie,
                canary: info.canary,
                relro: info.relro.clone(),
                rpath: info.rpath,
                stripped: info.stripped,
                fortified: info.fortified,
                unsafe_funcs: info.unsafe_funcs.clone(),
                dart: is_dart,
            });

            per_file.extend(check_symbols(&info, &rel_path));
            let strings = extract_strings(&bytes, 6);
            per_file.extend(check_firebase(&strings, &rel_path));
            per_file.extend(check_urls_domains(&strings, &rel_path));
            per_file.extend(check_trackers(&strings, &rel_path));
        }

        let mut findings = emit_checksec_summary(&all_checksec);

        // Cap per-file findings at 5 per id.
        let mut id_counts: HashMap<String, usize> = HashMap::new();
        for f in per_file {
            let c = id_counts.entry(f.id.clone()).or_insert(0);
            *c += 1;
            if *c <= 5 {
                findings.push(f);
            }
        }

        findings
    }
}

fn is_dart_flutter(info: &ElfInfo, rel_path: &str) -> bool {
    if rel_path.contains("libflutter.so") || rel_path.contains("libapp.so") {
        return true;
    }
    let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for s in &info.exported {
        names.insert(s.as_str());
    }
    for s in &info.imported {
        names.insert(s.as_str());
    }
    DART_FLUTTER_SYMBOLS.iter().any(|s| names.contains(s))
}

fn check_symbols(info: &ElfInfo, rel_path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dangerous_set = ["system", "popen", "exec", "execve", "execvp", "dlopen", "dlsym"];
    let found_dangerous: Vec<String> = info
        .imported
        .iter()
        .filter(|s| dangerous_set.contains(&s.as_str()))
        .cloned()
        .collect();
    if !found_dangerous.is_empty() {
        findings.push(
            Finding::new(
                "BIN_DANGEROUS_IMPORT",
                format!("Dangerous function imports: {rel_path}"),
                format!(
                    "Native library '{rel_path}' imports dangerous functions: {}. These can be used for command execution or dynamic library loading.",
                    found_dangerous.join(", ")
                ),
                Medium,
                "binary",
            )
            .file_path(rel_path)
            .cwe("CWE-78")
            .masvs("MASVS-CODE")
            .meta("dangerous_imports", json!(found_dangerous)),
        );
    }

    let jni_exports: Vec<String> = info
        .exported
        .iter()
        .filter(|s| s.starts_with("Java_"))
        .cloned()
        .collect();
    if !jni_exports.is_empty() {
        let sample: Vec<String> = jni_exports.iter().take(20).cloned().collect();
        findings.push(
            Finding::new(
                "BIN_JNI_EXPORTS",
                format!("JNI exports ({}): {rel_path}", jni_exports.len()),
                format!(
                    "Native library '{rel_path}' exports {} JNI function(s). These are callable from Java/Kotlin code.",
                    jni_exports.len()
                ),
                Info,
                "binary",
            )
            .file_path(rel_path)
            .meta("jni_count", json!(jni_exports.len()))
            .meta("jni_functions", json!(sample)),
        );
    }
    findings
}

fn check_firebase(strings: &[String], rel_path: &str) -> Vec<Finding> {
    let all_text = strings.join("\n");
    for pat in FIREBASE_PATTERNS {
        let re = rx(pat);
        let matches: Vec<String> = re
            .find_iter(&all_text)
            .flatten()
            .map(|m| m.as_str().to_string())
            .collect();
        if !matches.is_empty() {
            let preview: String = matches[0].chars().take(80).collect();
            return vec![Finding::new(
                "BIN_FIREBASE",
                format!("Firebase config in binary: {rel_path}"),
                format!("Firebase configuration found in native library '{rel_path}': {preview}..."),
                Medium,
                "binary",
            )
            .file_path(rel_path)
            .masvs("MASVS-STORAGE")
            .meta("matches", json!(matches.iter().take(5).collect::<Vec<_>>()))];
        }
    }
    vec![]
}

fn check_urls_domains(strings: &[String], rel_path: &str) -> Vec<Finding> {
    let all_text = strings.join("\n");
    let url_re = rx(r#"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{4,}"#);
    // No `\b`: fancy-regex 0.13 treats word boundaries as "hard" and runs them in
    // its backtracking VM (10+ min on a 140 MB Instagram split). Without them the
    // pattern goes to the linear regex engine; boundaries are checked by hand below.
    let ip_re = rx(r#"(?:\d{1,3}\.){3}\d{1,3}"#);
    let bytes = all_text.as_bytes();
    let is_word = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_');

    let mut urls: Vec<String> = url_re
        .find_iter(&all_text)
        .flatten()
        .map(|m| m.as_str().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    let mut ips: Vec<String> = ip_re
        .find_iter(&all_text)
        .flatten()
        .filter(|m| !(m.start() > 0 && is_word(m.start() - 1)) && !is_word(m.end()))
        .map(|m| m.as_str().to_string())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .filter(|ip| !ip.starts_with("0.") && !ip.starts_with("127.") && ip != "255.255.255.255")
        .collect();

    let mut findings = Vec::new();
    if !urls.is_empty() {
        urls.sort();
        let sample: Vec<String> = urls.iter().take(50).cloned().collect();
        findings.push(
            Finding::new(
                "BIN_URLS",
                format!("URLs found in binary ({}): {rel_path}", urls.len()),
                format!("Found {} URL(s) embedded in native library '{rel_path}'.", urls.len()),
                Info,
                "binary",
            )
            .file_path(rel_path)
            .meta("urls", json!(sample)),
        );
    }
    if !ips.is_empty() {
        ips.sort();
        let head: Vec<String> = ips.iter().take(10).cloned().collect();
        findings.push(
            Finding::new(
                "BIN_HARDCODED_IPS",
                format!("Hardcoded IPs found ({}): {rel_path}", ips.len()),
                format!(
                    "Found {} hardcoded IP address(es) in native library '{rel_path}': {}.",
                    ips.len(),
                    head.join(", ")
                ),
                Medium,
                "binary",
            )
            .file_path(rel_path)
            .cwe("CWE-798")
            .masvs("MASVS-NETWORK")
            .meta("ips", json!(ips)),
        );
    }
    findings
}

fn check_trackers(strings: &[String], rel_path: &str) -> Vec<Finding> {
    let all_text = strings.join("\n");
    let found: Vec<String> = TRACKER_PATTERNS
        .iter()
        .filter(|(pat, _)| all_text.contains(pat))
        .map(|(_, name)| name.to_string())
        .collect();
    if found.is_empty() {
        return vec![];
    }
    vec![Finding::new(
        "BIN_TRACKERS",
        format!("Trackers in binary ({}): {rel_path}", found.len()),
        format!(
            "Found {} tracker(s) in native library '{rel_path}': {}.",
            found.len(),
            found.join(", ")
        ),
        Medium,
        "binary",
    )
    .file_path(rel_path)
    .masvs("MASVS-PRIVACY")
    .meta("trackers", json!(found))]
}

fn emit_checksec_summary(all: &[Checksec]) -> Vec<Finding> {
    if all.is_empty() {
        return vec![];
    }
    let total = all.len();
    let no_nx: Vec<String> = all.iter().filter(|d| !d.nx).map(|d| d.path.clone()).collect();
    let no_pie: Vec<String> = all.iter().filter(|d| !d.pie).map(|d| d.path.clone()).collect();
    let no_canary: Vec<String> = all
        .iter()
        .filter(|d| !d.canary && !d.dart)
        .map(|d| d.path.clone())
        .collect();
    let no_relro: Vec<String> = all
        .iter()
        .filter(|d| d.relro == "none")
        .map(|d| d.path.clone())
        .collect();
    let has_rpath: Vec<String> = all.iter().filter(|d| d.rpath).map(|d| d.path.clone()).collect();
    let not_stripped: Vec<String> = all
        .iter()
        .filter(|d| !d.stripped)
        .map(|d| d.path.clone())
        .collect();
    let no_fortify: Vec<String> = all
        .iter()
        .filter(|d| !d.unsafe_funcs.is_empty() && d.fortified == 0 && !d.dart)
        .map(|d| d.path.clone())
        .collect();
    let dart_libs: Vec<String> = all.iter().filter(|d| d.dart).map(|d| d.path.clone()).collect();

    let mut findings = Vec::new();

    let mut summary = |label: &str, fid: &str, affected: &[String], sev: Severity, cwe: Option<&str>| {
        if affected.is_empty() {
            return;
        }
        let sample: Vec<String> = affected.iter().take(3).cloned().collect();
        let more = if affected.len() > 3 {
            format!(" and {} more", affected.len() - 3)
        } else {
            String::new()
        };
        let mut f = Finding::new(
            fid,
            format!("{label} ({}/{total} libraries)", affected.len()),
            format!(
                "{} of {} native libraries: {}{}.",
                affected.len(),
                total,
                sample.join("; "),
                more
            ),
            sev,
            "binary",
        )
        .masvs("MASVS-CODE")
        .meta("affected", json!(affected))
        .meta("total", json!(total));
        if let Some(c) = cwe {
            f = f.cwe(c);
        }
        findings.push(f);
    };

    summary("NX bit disabled", "BIN_NO_NX", &no_nx, High, Some("CWE-119"));
    summary("PIE not enabled", "BIN_NO_PIE", &no_pie, Medium, Some("CWE-119"));
    summary("No stack canary", "BIN_NO_CANARY", &no_canary, Medium, Some("CWE-119"));
    summary("No RELRO", "BIN_NO_RELRO", &no_relro, Medium, Some("CWE-119"));
    summary("RPATH/RUNPATH set", "BIN_RPATH", &has_rpath, Medium, Some("CWE-426"));
    summary("Symbols not stripped", "BIN_NOT_STRIPPED", &not_stripped, Low, None);
    summary("No function fortification", "BIN_NO_FORTIFY", &no_fortify, Medium, Some("CWE-120"));

    if !dart_libs.is_empty() {
        findings.push(
            Finding::new(
                "BIN_DART_FLUTTER",
                format!("Dart/Flutter binaries ({})", dart_libs.len()),
                format!(
                    "{} Dart/Flutter library(ies) detected. Some checks are relaxed for Dart VM.",
                    dart_libs.len()
                ),
                Info,
                "binary",
            )
            .meta("libraries", json!(dart_libs)),
        );
    }

    let full = all.iter().filter(|d| d.relro == "full").count();
    let partial = all.iter().filter(|d| d.relro == "partial").count();
    let details: Vec<Value> = all.iter().map(|d| d.to_json()).collect();
    findings.push(
        Finding::new(
            "BIN_CHECKSEC",
            format!("Native libraries checksec ({total} .so files)"),
            format!(
                "{total} native libraries analyzed. NX={}/{total}, PIE={}/{total}, Canary={}/{total}, RELRO full/partial/none={}/{}/{}.",
                total - no_nx.len(),
                total - no_pie.len(),
                total - no_canary.len(),
                full,
                partial,
                no_relro.len()
            ),
            Info,
            "binary",
        )
        .meta("total", json!(total))
        .meta("details", json!(details)),
    );

    findings
}

#[cfg(test)]
mod ip_tests {
    use super::*;

    #[test]
    fn hardcoded_ips_respect_word_boundaries() {
        let s = vec!["dns 8.8.4.4, v1.2.3.4x a10.0.0.1 _9.9.9.9 192.168.1.20".to_string()];
        let f = check_urls_domains(&s, "lib/x.so");
        let ips = f.iter().find(|f| f.id == "BIN_HARDCODED_IPS").unwrap();
        assert_eq!(ips.metadata["ips"], json!(["192.168.1.20", "8.8.4.4"]));
    }
}
