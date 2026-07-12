//! Supply chain analyzer — SBOM generation, dependency extraction, version detection.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{read_text, rx, walk_all_files};
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;

use Severity::*;

#[derive(Clone)]
struct Dep {
    group: String,
    artifact: String,
    version: String,
}

const VULN_DB: &[(&str, &str, &str, &str)] = &[
    ("okhttp", "3.", "OkHttp 3.x is EOL. Upgrade to 4.x+.", "medium"),
    ("okhttp", "2.", "OkHttp 2.x is severely outdated.", "high"),
    ("gson", "2.8.0", "Gson 2.8.0 has known DoS via deeply nested JSON.", "medium"),
    ("log4j", "2.0", "Log4j 2.x < 2.17 is affected by Log4Shell (CVE-2021-44228).", "critical"),
    ("log4j", "2.1", "Log4j 2.1x may be affected by Log4Shell variants.", "critical"),
    ("jackson-databind", "2.9", "Jackson-databind 2.9.x has multiple deserialization RCE CVEs.", "critical"),
    ("jackson-databind", "2.8", "Jackson-databind 2.8.x has multiple deserialization RCE CVEs.", "critical"),
    ("commons-collections", "3.", "Apache Commons Collections 3.x has deserialization gadgets.", "high"),
    ("bouncy", "1.5", "BouncyCastle 1.5x has known vulnerabilities.", "medium"),
    ("retrofit", "1.", "Retrofit 1.x is EOL and has known issues.", "medium"),
];

pub struct SupplyChainAnalyzer;

impl Analyzer for SupplyChainAnalyzer {
    fn name(&self) -> &'static str {
        "Supply Chain & Dependencies"
    }
    fn category(&self) -> &'static str {
        "supply_chain"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let deps = extract_dependencies(extracted);
        let mut findings = Vec::new();
        findings.extend(emit_sbom(&deps));
        findings.extend(check_known_vulnerable(&deps));
        findings
    }
}

fn extract_dependencies(extracted: &Path) -> Vec<Dep> {
    let mut deps: Vec<Dep> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut all = walk_all_files(extracted);
    all.sort();

    // 1. META-INF/*.version
    let meta_inf = extracted.join("META-INF");
    for vfile in &all {
        if !vfile.starts_with(&meta_inf) {
            continue;
        }
        if vfile.extension().and_then(|e| e.to_str()) != Some("version") {
            continue;
        }
        if let Some(version) = read_text(vfile) {
            let version = version.trim().to_string();
            let name = vfile
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            let (group, artifact) = match name.rsplit_once('_') {
                Some((g, a)) => (g.replace('_', "."), a.to_string()),
                None => (String::new(), name.clone()),
            };
            let key = format!("{group}:{artifact}:{version}");
            if seen.insert(key) {
                deps.push(Dep { group, artifact, version });
            }
        }
    }

    // 2. *.properties
    let ver_at_start = rx(r#"^\d+\.\d+"#);
    for prop in &all {
        if prop.extension().and_then(|e| e.to_str()) != Some("properties") {
            continue;
        }
        if let Some(content) = read_text(prop) {
            for line in content.split('\n') {
                if line.to_lowercase().contains("version") && line.contains('=') {
                    if let Some((k, v)) = line.split_once('=') {
                        let k = k.trim();
                        let v = v.trim();
                        if !v.is_empty() && ver_at_start.is_match(v).unwrap_or(false) {
                            let key = format!("prop:{k}:{v}");
                            if seen.insert(key) {
                                deps.push(Dep {
                                    group: "properties".to_string(),
                                    artifact: k.to_string(),
                                    version: v.to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // 3. Package names from JAR class paths
    for jar in &all {
        if jar.extension().and_then(|e| e.to_str()) != Some("jar") {
            continue;
        }
        let file = match std::fs::File::open(jar) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut archive = match zip::ZipArchive::new(file) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let mut packages: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for i in 0..archive.len() {
            let name = match archive.by_index(i) {
                Ok(e) => e.name().to_string(),
                Err(_) => continue,
            };
            if name.ends_with(".class") && name.contains('/') {
                if let Some((pkg_path, _)) = name.rsplit_once('/') {
                    let pkg = pkg_path.replace('/', ".");
                    let parts: Vec<&str> = pkg.split('.').collect();
                    if parts.len() >= 3 {
                        packages.insert(parts[..3].join("."));
                    }
                }
            }
        }
        let jar_name = jar.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
        for pkg in packages {
            let key = format!("jar:{pkg}");
            if seen.insert(key) {
                deps.push(Dep {
                    group: pkg,
                    artifact: jar_name.clone(),
                    version: "unknown".to_string(),
                });
            }
        }
    }

    deps
}

fn emit_sbom(deps: &[Dep]) -> Vec<Finding> {
    if deps.is_empty() {
        return vec![Finding::new(
            "SC_NO_DEPS",
            "No dependencies detected",
            "Could not extract any dependency information from the APK.",
            Info,
            "supply_chain",
        )];
    }

    let versioned: Vec<&Dep> = deps.iter().filter(|d| d.version != "unknown").collect();
    let unversioned = deps.len() - versioned.len();

    let dep_list: Vec<String> = versioned
        .iter()
        .take(50)
        .map(|d| format!("{}:{}:{}", d.group, d.artifact, d.version))
        .collect();
    let top10 = dep_list.iter().take(10).cloned().collect::<Vec<_>>().join("; ");

    let all_deps: Vec<String> = deps
        .iter()
        .take(100)
        .map(|d| format!("{}:{}:{}", d.group, d.artifact, d.version))
        .collect();

    vec![Finding::new(
        "SC_SBOM",
        format!("Dependencies detected ({}, {} versioned)", deps.len(), versioned.len()),
        format!(
            "Extracted {} dependency(ies) ({} with version, {} without). Top dependencies: {}.",
            deps.len(),
            versioned.len(),
            unversioned,
            top10
        ),
        Info,
        "supply_chain",
    )
    .meta("total", json!(deps.len()))
    .meta("versioned_count", json!(versioned.len()))
    .meta("dependencies", json!(all_deps))]
}

fn check_known_vulnerable(deps: &[Dep]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for dep in deps {
        let artifact = dep.artifact.to_lowercase();
        if dep.version == "unknown" {
            continue;
        }
        for (vuln_art, vuln_ver, desc, sev_str) in VULN_DB {
            if artifact.contains(vuln_art) && dep.version.starts_with(vuln_ver) {
                let sev = match *sev_str {
                    "critical" => Critical,
                    "high" => High,
                    _ => Medium,
                };
                findings.push(
                    Finding::new(
                        "SC_VULNERABLE_DEP",
                        format!("Vulnerable dependency: {} {}", dep.artifact, dep.version),
                        format!(
                            "{desc} Found: {}:{}:{}.",
                            dep.group, dep.artifact, dep.version
                        ),
                        sev,
                        "supply_chain",
                    )
                    .cwe("CWE-1104")
                    .masvs("MASVS-CODE")
                    .meta("dependency", json!(format!("{}:{}:{}", dep.group, dep.artifact, dep.version))),
                );
            }
        }
    }
    findings
}
