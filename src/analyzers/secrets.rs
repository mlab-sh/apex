//! Secrets & entropy analyzer — hardcoded secrets, high-entropy strings, URLs, emails.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{
    distinct_chars, line_of, py_splitlines, read_text, rel, rx_flags, shannon_entropy,
    walk_all_files,
};
use fancy_regex::Regex;
use serde_json::json;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

use Severity::*;

struct SecretRule {
    id: &'static str,
    title: &'static str,
    desc: &'static str,
    pat: &'static str,
    sev: Severity,
    i: bool,
    m: bool,
}

fn secret_rules() -> Vec<SecretRule> {
    vec![
        SecretRule { id: "SEC_FIREBASE_API_KEY", title: "Firebase API key", desc: "Google/Firebase API key detected (AIza prefix). Can be used to access Firebase services.", pat: r#"AIza[0-9A-Za-z_-]{35}"#, sev: High, i: false, m: false },
        SecretRule { id: "SEC_FIREBASE_APP_ID", title: "Firebase App ID", desc: "Firebase App ID detected (format: number:android:hex).", pat: r#"\d{1,20}:android:[a-f0-9]{20,}"#, sev: Medium, i: false, m: false },
        SecretRule { id: "SEC_FIREBASE_CLIENT_ID", title: "Firebase/GCP client ID", desc: "Google OAuth client ID detected (.apps.googleusercontent.com).", pat: r#"[0-9]+-[a-z0-9_]+\.apps\.googleusercontent\.com"#, sev: Medium, i: false, m: false },
        SecretRule { id: "SEC_FIREBASE_DB_URL", title: "Firebase database URL", desc: "Firebase Realtime Database URL detected. May allow unauthorized data access if rules are weak.", pat: r#"https://[a-z0-9-]+\.firebaseio\.com"#, sev: High, i: false, m: false },
        SecretRule { id: "SEC_AWS_ACCESS_KEY", title: "AWS access key", desc: "AWS access key ID detected (AKIA/ASIA prefix). Grants access to AWS services.", pat: r#"(?:["'=:\s]|^)(AKIA[0-9A-Z]{16})(?:["'\s,;\n]|$)"#, sev: Critical, i: false, m: true },
        SecretRule { id: "SEC_AWS_SECRET_KEY", title: "AWS secret access key", desc: "Potential AWS secret access key detected (40 char base64 after key identifier).", pat: r#"(?:aws_secret_access_key|secret_access_key|aws_secret)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})"#, sev: Critical, i: true, m: false },
        SecretRule { id: "SEC_GCP_SERVICE_ACCOUNT", title: "GCP service account key", desc: "Google Cloud service account key JSON detected (private_key_id or type:service_account).", pat: r#"("type"\s*:\s*"service_account"|"private_key_id"\s*:\s*"[a-f0-9]{40}")"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_GCP_API_KEY", title: "GCP API key", desc: "Google Cloud API key detected (AIza prefix, same pattern as Firebase).", pat: r#"AIza[0-9A-Za-z_-]{35}"#, sev: High, i: false, m: false },
        SecretRule { id: "SEC_AZURE_CONNECTION", title: "Azure connection string", desc: "Azure storage or service bus connection string detected.", pat: r#"(?:DefaultEndpointsProtocol|AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{20,}"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_AZURE_TOKEN", title: "Azure AD token/secret", desc: "Azure Active Directory client secret or token detected.", pat: r#"(?:azure[_-]?(?:client[_-]?secret|tenant|subscription))\s*[=:]\s*["']?[A-Za-z0-9_~.-]{20,}"#, sev: High, i: true, m: false },
        SecretRule { id: "SEC_JWT_TOKEN", title: "JWT token", desc: "JSON Web Token detected. May contain sensitive claims or session data.", pat: r#"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"#, sev: High, i: false, m: false },
        SecretRule { id: "SEC_JWT_SECRET", title: "JWT secret key", desc: "Hardcoded JWT signing secret detected.", pat: r#"(?:jwt[_-]?secret|jwt[_-]?key|signing[_-]?key|token[_-]?secret)\s*[=:]\s*["'][^"']{8,}["']"#, sev: Critical, i: true, m: false },
        SecretRule { id: "SEC_OAUTH_SECRET", title: "OAuth client secret", desc: "OAuth client secret or app secret detected.", pat: r#"(?:client[_-]?secret|app[_-]?secret|consumer[_-]?secret|oauth[_-]?secret)\s*[=:]\s*["'][^"']{8,}["']"#, sev: High, i: true, m: false },
        SecretRule { id: "SEC_WEBHOOK_URL", title: "Webhook URL", desc: "Webhook URL detected (Slack, Discord, Teams, or generic). May allow unauthorized message injection.", pat: r#"https://(?:hooks\.slack\.com/services/|discord(?:app)?\.com/api/webhooks/|outlook\.office\.com/webhook/|[a-z0-9.-]+/(?:webhook|hook|callback))[^\s"']{10,}"#, sev: High, i: true, m: false },
        SecretRule { id: "SEC_DB_CONNECTION", title: "Database connection string", desc: "Database connection string detected (MySQL, PostgreSQL, MongoDB, Redis, MSSQL).", pat: r#"(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql)://[^\s"'<>]{10,}"#, sev: Critical, i: true, m: false },
        SecretRule { id: "SEC_PRIVATE_KEY", title: "Private key", desc: "PEM-encoded private key detected in source. Private keys must never be embedded in apps.", pat: r#"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_GENERIC_SECRET", title: "Hardcoded secret/password", desc: "Hardcoded secret, password, API key, or token detected via variable/key name pattern.", pat: r#"(?:password|passwd|pwd|secret|api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key|encryption[_-]?key|master[_-]?key)\s*[=:]\s*["'][^"']{8,}["']"#, sev: High, i: true, m: false },
        SecretRule { id: "SEC_SLACK_TOKEN", title: "Slack token", desc: "Slack API token detected (xoxb, xoxp, xoxa, xoxr, xoxs prefix).", pat: r#"xox[bpars]-[0-9]+-[0-9]+-[a-zA-Z0-9]+"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_GITHUB_TOKEN", title: "GitHub token", desc: "GitHub personal access token or fine-grained token detected.", pat: r#"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_STRIPE_KEY", title: "Stripe API key", desc: "Stripe secret or publishable API key detected.", pat: r#"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"#, sev: Critical, i: false, m: false },
        SecretRule { id: "SEC_TWILIO_KEY", title: "Twilio API key", desc: "Twilio Account SID or Auth Token detected.", pat: r#"(?:AC[a-f0-9]{32}|SK[a-f0-9]{32})"#, sev: High, i: false, m: false },
        SecretRule { id: "SEC_SENDGRID_KEY", title: "SendGrid API key", desc: "SendGrid API key detected.", pat: r#"SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}"#, sev: High, i: false, m: false },
    ]
}

const BASE64_ENTROPY_THRESHOLD: f64 = 4.5;
const HEX_ENTROPY_THRESHOLD: f64 = 3.0;
const MIN_SECRET_LENGTH: usize = 20;
const MAX_ENTROPY_PER_FILE: usize = 3;

const TEXT_EXTS: &[&str] = &[
    "java", "kt", "smali", "xml", "json", "properties", "yaml", "yml", "cfg", "conf", "ini", "txt",
    "html", "js", "gradle", "pro", "plist",
];

const ENTROPY_SKIP_FILENAMES: &[&str] = &[
    "lpms.json", "package-lock.json", "yarn.lock", "pubspec.lock", "gradlew", "gradlew.bat",
    "proguard-rules.pro",
];
const ENTROPY_SKIP_EXTENSIONS: &[&str] = &["html", "htm", "wasm", "map"];
const ENTROPY_EXCLUDE: &[&str] = &[
    "abcdefghijklmnopqrstuvwxyz",
    "0123456789",
];

fn is_entropy_false_positive(s: &str) -> bool {
    if !s.is_empty() && s.chars().all(char::is_alphabetic) {
        return true;
    }
    let lower = s.to_lowercase();
    if ENTROPY_EXCLUDE.contains(&lower.as_str()) {
        return true;
    }
    for p in ["http://", "https://", "file://", "/", "com.", "org."] {
        if s.starts_with(p) {
            return true;
        }
    }
    if rx_flags(r#"^[a-z]+(\.[a-z]+){2,}$"#, false, false, false)
        .is_match(s)
        .unwrap_or(false)
    {
        return true;
    }
    if distinct_chars(s) < 4 {
        return true;
    }
    false
}

fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

fn last_chars(s: &str, n: usize) -> String {
    let v: Vec<char> = s.chars().collect();
    let start = v.len().saturating_sub(n);
    v[start..].iter().collect()
}

pub struct SecretsAnalyzer;

impl SecretsAnalyzer {
    fn collect_text_content(&self, extracted: &Path) -> Vec<(PathBuf, String)> {
        let mut results = Vec::new();
        let mut files = walk_all_files(extracted);
        files.sort();
        for fpath in files {
            let size = std::fs::metadata(&fpath).map(|m| m.len()).unwrap_or(0);
            let ext = fpath
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase());
            if size > 10_000_000 {
                continue;
            }
            match &ext {
                Some(e) if TEXT_EXTS.contains(&e.as_str()) => {
                    if let Some(c) = read_text(&fpath) {
                        results.push((fpath, c));
                    }
                }
                None => {
                    if size < 100_000 {
                        if let Some(c) = read_text(&fpath) {
                            if c.contains('\n') || c.chars().all(|ch| !ch.is_control()) {
                                results.push((fpath, c));
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        results
    }
}

impl Analyzer for SecretsAnalyzer {
    fn name(&self) -> &'static str {
        "Secrets & Entropy"
    }
    fn category(&self) -> &'static str {
        "secrets"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(
            app_type,
            AppType::Apk | AppType::Aab | AppType::Xapk | AppType::Ipa
        )
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let contents = self.collect_text_content(extracted);
        let mut findings = Vec::new();
        findings.extend(scan_secrets(&contents, extracted));
        findings.extend(scan_entropy(&contents, extracted));
        findings.extend(extract_urls(&contents));
        findings.extend(extract_emails(&contents));
        findings
    }
}

fn scan_secrets(contents: &[(PathBuf, String)], extracted: &Path) -> Vec<Finding> {
    let compiled: Vec<(SecretRule, Regex)> = secret_rules()
        .into_iter()
        .map(|r| {
            let re = rx_flags(r.pat, r.i, false, r.m);
            (r, re)
        })
        .collect();
    let mut findings = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for (fpath, content) in contents {
        let rel_path = rel(fpath, extracted);
        for (rule, re) in &compiled {
            for m in re.find_iter(content).flatten() {
                let matched = take_chars(m.as_str(), 80);
                let key = (rule.id.to_string(), matched.clone());
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);
                let line = line_of(content, m.start());
                let len = matched.chars().count();
                let display = if len > 16 {
                    format!("{}...{}", take_chars(&matched, 8), last_chars(&matched, 4))
                } else {
                    matched.clone()
                };
                findings.push(
                    Finding::new(
                        rule.id,
                        rule.title,
                        format!("{} Found in {rel_path}:{line} — {display}", rule.desc),
                        rule.sev,
                        "secrets",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .cwe("CWE-798")
                    .masvs("MASVS-STORAGE")
                    .meta("matched_preview", json!(display)),
                );
            }
        }
    }
    findings
}

fn scan_entropy(contents: &[(PathBuf, String)], extracted: &Path) -> Vec<Finding> {
    let base64_re = rx_flags(r#"[A-Za-z0-9+/=]{20,}"#, false, false, false);
    let hex_re = rx_flags(r#"[0-9a-fA-F]{20,}"#, false, false, false);
    let mut findings = Vec::new();
    let mut seen_values: HashSet<String> = HashSet::new();

    for (fpath, content) in contents {
        let name = fpath
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        if ENTROPY_SKIP_FILENAMES.contains(&name.as_str()) {
            continue;
        }
        let ext = fpath
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        if ENTROPY_SKIP_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let lines: Vec<&str> = py_splitlines(content);
        let nlines = lines.len().max(1);
        if !lines.is_empty() && (content.chars().count() as f64 / nlines as f64) > 500.0 {
            continue;
        }

        let rel_path = rel(fpath, extracted);
        let mut file_findings = 0usize;

        for (idx, line) in lines.iter().enumerate() {
            if file_findings >= MAX_ENTROPY_PER_FILE {
                break;
            }
            let line_num = (idx + 1) as u64;

            for m in base64_re.find_iter(line).flatten() {
                let candidate = m.as_str();
                if candidate.chars().count() < MIN_SECRET_LENGTH {
                    continue;
                }
                if seen_values.contains(candidate) || is_entropy_false_positive(candidate) {
                    continue;
                }
                let entropy = shannon_entropy(candidate);
                if entropy >= BASE64_ENTROPY_THRESHOLD {
                    seen_values.insert(candidate.to_string());
                    let display = format!("{}...{}", take_chars(candidate, 12), last_chars(candidate, 4));
                    findings.push(
                        Finding::new(
                            "SEC_HIGH_ENTROPY_B64",
                            "High-entropy Base64 string",
                            format!(
                                "Base64 string with entropy {entropy:.2} (threshold {BASE64_ENTROPY_THRESHOLD}) in {rel_path}:{line_num} — {display}. May be a hardcoded secret or key."
                            ),
                            Medium,
                            "secrets",
                        )
                        .file_path(rel_path.clone())
                        .line(line_num)
                        .cwe("CWE-798")
                        .masvs("MASVS-STORAGE")
                        .meta("entropy", json!(round2(entropy)))
                        .meta("length", json!(candidate.chars().count()))
                        .meta("preview", json!(display)),
                    );
                    file_findings += 1;
                }
            }

            for m in hex_re.find_iter(line).flatten() {
                let candidate = m.as_str();
                if candidate.chars().count() < MIN_SECRET_LENGTH {
                    continue;
                }
                if seen_values.contains(candidate) || is_entropy_false_positive(candidate) {
                    continue;
                }
                let entropy = shannon_entropy(candidate);
                if entropy >= HEX_ENTROPY_THRESHOLD {
                    seen_values.insert(candidate.to_string());
                    let display = format!("{}...{}", take_chars(candidate, 12), last_chars(candidate, 4));
                    findings.push(
                        Finding::new(
                            "SEC_HIGH_ENTROPY_HEX",
                            "High-entropy hex string",
                            format!(
                                "Hex string with entropy {entropy:.2} (threshold 3.0) in {rel_path}:{line_num} — {display}. May be a hardcoded key or hash."
                            ),
                            Medium,
                            "secrets",
                        )
                        .file_path(rel_path.clone())
                        .line(line_num)
                        .cwe("CWE-798")
                        .masvs("MASVS-STORAGE")
                        .meta("entropy", json!(round2(entropy)))
                        .meta("length", json!(candidate.chars().count()))
                        .meta("preview", json!(display)),
                    );
                    file_findings += 1;
                }
            }
        }
    }
    findings
}

fn extract_urls(contents: &[(PathBuf, String)]) -> Vec<Finding> {
    let re = rx_flags(r#"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,}"#, false, false, false);
    let mut all: BTreeSet<String> = BTreeSet::new();
    for (_, content) in contents {
        for m in re.find_iter(content).flatten() {
            all.insert(m.as_str().to_string());
        }
    }
    if all.is_empty() {
        return vec![];
    }
    let schemas = [
        "schemas.android.com",
        "www.w3.org",
        "ns.adobe.com",
        "xmlpull.org",
        "apache.org",
        "google.com/schemas",
        "json-schema.org",
    ];
    let interesting: Vec<String> = all
        .iter()
        .filter(|u| !schemas.iter().any(|d| u.contains(d)))
        .cloned()
        .collect();
    let preview: Vec<String> = interesting.iter().take(100).cloned().collect();
    vec![Finding::new(
        "SEC_URLS",
        format!("URLs extracted ({})", interesting.len()),
        format!(
            "Found {} URL(s) in source files (excluding schema/namespace URLs). {} total.",
            interesting.len(),
            all.len()
        ),
        Info,
        "secrets",
    )
    .meta("urls", json!(preview))
    .meta("total", json!(all.len()))]
}

fn extract_emails(contents: &[(PathBuf, String)]) -> Vec<Finding> {
    let re = rx_flags(r#"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"#, false, false, false);
    let mut all: BTreeSet<String> = BTreeSet::new();
    for (_, content) in contents {
        for m in re.find_iter(content).flatten() {
            all.insert(m.as_str().to_string());
        }
    }
    let fake = ["example.com", "example.org", "test.com", "localhost", "noreply", "no-reply"];
    let real: Vec<String> = all
        .iter()
        .filter(|e| {
            let l = e.to_lowercase();
            !fake.iter().any(|d| l.contains(d))
        })
        .cloned()
        .collect();
    if real.is_empty() {
        return vec![];
    }
    let desc_list: Vec<String> = real.iter().take(10).cloned().collect();
    let meta_list: Vec<String> = real.iter().take(50).cloned().collect();
    vec![Finding::new(
        "SEC_EMAILS",
        format!("Email addresses extracted ({})", real.len()),
        format!(
            "Found {} email address(es): {}.",
            real.len(),
            desc_list.join(", ")
        ),
        Info,
        "secrets",
    )
    .meta("emails", json!(meta_list))]
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
