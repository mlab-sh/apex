//! Network Security Config analyzer + network code checks.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx, rx_flags, walk_all_files};
use crate::xml::{self, Element};
use chrono::{NaiveDate, TimeZone, Utc};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

use Severity::*;

pub struct NetworkSecurityAnalyzer;

impl Analyzer for NetworkSecurityAnalyzer {
    fn name(&self) -> &'static str {
        "Network Security"
    }
    fn category(&self) -> &'static str {
        "network"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(root) = find_and_parse_nsc(extracted) {
            findings.extend(check_cleartext_global(&root));
            findings.extend(check_cleartext_domains(&root));
            findings.extend(check_trust_anchors(&root));
            findings.extend(check_certificate_pinning(&root));
            findings.extend(check_debug_overrides(&root));
        }

        findings.extend(check_pinning_quality(extracted));
        findings.extend(check_mtls(extracted));
        findings.extend(check_proxy_bypass(extracted));

        findings
    }
}

fn find_and_parse_nsc(extracted: &Path) -> Option<Element> {
    let mut candidates: Vec<std::path::PathBuf> = vec![
        extracted.join("res/xml/network_security_config.xml"),
        extracted.join("res/xml/network_config.xml"),
    ];
    // glob res/xml/*network*security*.xml
    let xmldir = extracted.join("res/xml");
    for p in walk_all_files(&xmldir) {
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.contains("network") && name.contains("security") && name.ends_with(".xml") && !candidates.contains(&p) {
            candidates.push(p);
        }
    }
    for path in candidates {
        if !path.exists() {
            continue;
        }
        if let Ok(raw) = std::fs::read(&path) {
            if let Some(el) = xml::parse_axml_or_xml(&raw) {
                return Some(el);
            }
        }
    }
    None
}

fn domains_of(config: &Element) -> Vec<String> {
    config
        .iter("domain")
        .into_iter()
        .filter(|d| !d.text.is_empty())
        .map(|d| d.text.clone())
        .collect()
}

fn check_cleartext_global(root: &Element) -> Vec<Finding> {
    let base = match root.find("base-config") {
        Some(b) => b,
        None => return vec![],
    };
    if let Some(v) = base.attr("cleartextTrafficPermitted") {
        if v.eq_ignore_ascii_case("true") {
            return vec![Finding::new(
                "NSC_CLEARTEXT_GLOBAL",
                "Cleartext traffic allowed globally",
                "The base-config allows cleartext (HTTP) traffic for all domains. All communications can be intercepted.",
                High,
                "network",
            )
            .cwe("CWE-319")
            .masvs("MASVS-NETWORK")];
        }
    }
    vec![]
}

fn check_cleartext_domains(root: &Element) -> Vec<Finding> {
    let mut findings = Vec::new();
    for dc in root.iter("domain-config") {
        if let Some(v) = dc.attr("cleartextTrafficPermitted") {
            if v.eq_ignore_ascii_case("true") {
                for domain in domains_of(dc) {
                    findings.push(
                        Finding::new(
                            "NSC_CLEARTEXT_DOMAIN",
                            format!("Cleartext traffic allowed: {domain}"),
                            format!("Domain '{domain}' allows cleartext (HTTP) traffic. Communications with this domain can be intercepted."),
                            Medium,
                            "network",
                        )
                        .cwe("CWE-319")
                        .masvs("MASVS-NETWORK")
                        .meta("domain", json!(domain)),
                    );
                }
            }
        }
    }
    findings
}

fn check_trust_anchors(root: &Element) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut configs: Vec<&Element> = root.iter("base-config");
    configs.extend(root.iter("domain-config"));

    for config in configs {
        let trust_anchors = match config.find("trust-anchors") {
            Some(t) => t,
            None => continue,
        };
        let domains = domains_of(config);
        let scope = if domains.is_empty() {
            "global".to_string()
        } else {
            domains.join(", ")
        };

        for certs in trust_anchors.iter("certificates") {
            let src = certs.attr("src").unwrap_or("");
            if src == "user" {
                findings.push(
                    Finding::new(
                        "NSC_TRUST_USER_CERTS",
                        format!("Trust anchors: user certificates ({scope})"),
                        format!("Network config ({scope}) trusts user-installed certificates. This makes MITM interception easier via a proxy with a custom cert."),
                        High,
                        "network",
                    )
                    .cwe("CWE-295")
                    .masvs("MASVS-NETWORK")
                    .meta("scope", json!(scope))
                    .meta("src", json!(src)),
                );
            }
            if src.starts_with("@raw/") || src.starts_with("@xml/") {
                findings.push(
                    Finding::new(
                        "NSC_TRUST_BUNDLED",
                        format!("Trust anchors: bundled certificate ({scope})"),
                        format!("Network config ({scope}) uses a bundled certificate ({src}). Verify that this certificate is legitimate and up to date."),
                        Info,
                        "network",
                    )
                    .masvs("MASVS-NETWORK")
                    .meta("scope", json!(scope))
                    .meta("src", json!(src)),
                );
            }
        }
    }
    findings
}

fn check_certificate_pinning(root: &Element) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut has_any_pin = false;

    for dc in root.iter("domain-config") {
        let domains = domains_of(dc);
        let scope = if domains.is_empty() {
            "unknown".to_string()
        } else {
            domains.join(", ")
        };

        let pin_set = match dc.find("pin-set") {
            Some(p) => p,
            None => continue,
        };
        has_any_pin = true;
        let expiration = pin_set.attr("expiration");
        let pins: Vec<&Element> = pin_set.iter("pin");
        let mut digests: BTreeSet<String> = BTreeSet::new();
        for p in &pins {
            digests.insert(p.attr("digest").unwrap_or("SHA-256").to_string());
        }
        let pin_count = pins.iter().filter(|p| !p.text.is_empty()).count();

        if let Some(exp) = expiration {
            if let Ok(date) = NaiveDate::parse_from_str(exp, "%Y-%m-%d") {
                let exp_dt = Utc
                    .from_utc_datetime(&date.and_hms_opt(0, 0, 0).unwrap());
                let now = Utc::now();
                if exp_dt < now {
                    findings.push(
                        Finding::new(
                            "NSC_PIN_EXPIRED",
                            format!("Certificate pin expired: {scope}"),
                            format!("The pin-set for {scope} expired on {exp}. Pinning is no longer active, connections are not verified."),
                            High,
                            "network",
                        )
                        .cwe("CWE-295")
                        .masvs("MASVS-NETWORK")
                        .meta("domains", json!(domains))
                        .meta("expiration", json!(exp)),
                    );
                } else {
                    let days = (exp_dt - now).num_days();
                    if days < 30 {
                        findings.push(
                            Finding::new(
                                "NSC_PIN_EXPIRING",
                                format!("Certificate pin expiring soon: {scope}"),
                                format!("The pin-set for {scope} expires on {exp} (in {days} days)."),
                                Medium,
                                "network",
                            )
                            .masvs("MASVS-NETWORK")
                            .meta("domains", json!(domains))
                            .meta("expiration", json!(exp))
                            .meta("days_left", json!(days)),
                        );
                    }
                }
            }
        }

        if pin_count < 2 {
            findings.push(
                Finding::new(
                    "NSC_PIN_NO_BACKUP",
                    format!("Certificate pin without backup: {scope}"),
                    format!("The pin-set for {scope} contains only {pin_count} pin(s). Google recommends at least 2 pins (primary + backup) to avoid lockout."),
                    Medium,
                    "network",
                )
                .masvs("MASVS-NETWORK")
                .meta("domains", json!(domains))
                .meta("pin_count", json!(pin_count)),
            );
        }

        let digest_list: Vec<String> = digests.iter().cloned().collect();
        findings.push(
            Finding::new(
                "NSC_PIN_FOUND",
                format!("Certificate pinning configured: {scope}"),
                format!(
                    "Certificate pinning active for {scope} with {pin_count} pin(s), digest(s): {}.",
                    digest_list.join(", ")
                ),
                Info,
                "network",
            )
            .masvs("MASVS-NETWORK")
            .meta("domains", json!(domains))
            .meta("pin_count", json!(pin_count))
            .meta("digests", json!(digest_list))
            .meta("expiration", json!(expiration)),
        );
    }

    if !has_any_pin {
        findings.push(
            Finding::new(
                "NSC_NO_PINNING",
                "No certificate pinning in NSC",
                "No pin-set defined in the network security config. Without pinning, the app is vulnerable to MITM attacks with a valid certificate.",
                Medium,
                "network",
            )
            .cwe("CWE-295")
            .masvs("MASVS-NETWORK"),
        );
    }

    findings
}

fn check_debug_overrides(root: &Element) -> Vec<Finding> {
    let debug = match root.find("debug-overrides") {
        Some(d) => d,
        None => return vec![],
    };
    let mut findings = vec![Finding::new(
        "NSC_DEBUG_OVERRIDES",
        "Debug overrides present in NSC",
        "The network security config contains debug-overrides. In debug mode, network restrictions can be bypassed.",
        Medium,
        "network",
    )
    .cwe("CWE-489")
    .masvs("MASVS-NETWORK")];

    if let Some(trust_anchors) = debug.find("trust-anchors") {
        for certs in trust_anchors.iter("certificates") {
            if certs.attr("src") == Some("user") {
                findings.push(
                    Finding::new(
                        "NSC_DEBUG_USER_CERTS",
                        "Debug overrides: trust user certs",
                        "In debug mode, the app trusts user-installed certificates. This allows MITM via proxy in debug mode.",
                        Info,
                        "network",
                    )
                    .masvs("MASVS-NETWORK"),
                );
            }
        }
    }
    findings
}

fn network_code_files(extracted: &Path) -> Vec<std::path::PathBuf> {
    find_files_by_ext(extracted, &["java", "kt", "smali", "js"])
}

fn check_pinning_quality(extracted: &Path) -> Vec<Finding> {
    let patterns: Vec<(fancy_regex::Regex, &str)> = vec![
        (rx(r#"TrustManager\s*\[\]\s*\{"#), "Custom TrustManager (potential pinning bypass)"),
        (rx_flags(r#"\.checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*\}"#, false, true, false), "Empty checkServerTrusted (validation bypass)"),
        (rx(r#"X509TrustManager"#), "Custom X509TrustManager detected"),
        (rx(r#"setHostnameVerifier\s*\(\s*(ALLOW_ALL|SSLSocketFactory\.ALLOW_ALL|allHostsValid)"#), "HostnameVerifier ALLOW_ALL"),
        (rx(r#"onReceivedSslError.*\.proceed\s*\("#), "WebView SSL error proceed (bypass)"),
    ];
    let mut findings = Vec::new();
    for fpath in network_code_files(extracted) {
        let content = match read_text(&fpath) {
            Some(c) => c,
            None => continue,
        };
        let rel_path = rel(&fpath, extracted);
        for (re, desc) in &patterns {
            for m in re.find_iter(&content).flatten() {
                let line = line_of(&content, m.start());
                findings.push(
                    Finding::new(
                        "NET_PINNING_BYPASS",
                        *desc,
                        format!("{desc} in {rel_path}:{line}. This may disable SSL/TLS validation."),
                        High,
                        "network",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .cwe("CWE-295")
                    .masvs("MASVS-NETWORK"),
                );
            }
        }
    }
    findings
}

fn check_mtls(extracted: &Path) -> Vec<Finding> {
    let re = rx(r#"(KeyManagerFactory|ClientCertRequest|setNeedClientAuth|\.loadKeyMaterial|sslSocketFactory\s*\()"#);
    let mut findings = Vec::new();
    for fpath in network_code_files(extracted) {
        let content = match read_text(&fpath) {
            Some(c) => c,
            None => continue,
        };
        if re.is_match(&content).unwrap_or(false) {
            let rel_path = rel(&fpath, extracted);
            findings.push(
                Finding::new(
                    "NET_MTLS_DETECTED",
                    format!("mTLS configuration detected: {rel_path}"),
                    format!("Client certificate / mTLS usage in {rel_path}. Verify that client certificates are not hardcoded in the APK."),
                    Info,
                    "network",
                )
                .file_path(rel_path.clone())
                .masvs("MASVS-NETWORK"),
            );
        }
    }
    findings
}

fn check_proxy_bypass(extracted: &Path) -> Vec<Finding> {
    let patterns: Vec<(fancy_regex::Regex, &str)> = vec![
        (rx(r#"Proxy\.NO_PROXY"#), "Proxy.NO_PROXY — bypasses system proxy"),
        (rx(r#"\.setProxy\s*\(\s*null\s*\)"#), "setProxy(null) — disables proxy"),
        (rx(r#"ProxySelector\.setDefault\s*\("#), "Custom ProxySelector — potential proxy bypass"),
        (rx(r#"System\.setProperty\s*\(\s*["']http\.proxy"#), "Manual HTTP proxy configuration"),
    ];
    let mut findings = Vec::new();
    for fpath in network_code_files(extracted) {
        let content = match read_text(&fpath) {
            Some(c) => c,
            None => continue,
        };
        let rel_path = rel(&fpath, extracted);
        for (re, desc) in &patterns {
            for m in re.find_iter(&content).flatten() {
                let line = line_of(&content, m.start());
                findings.push(
                    Finding::new(
                        "NET_PROXY_BYPASS",
                        *desc,
                        format!("{desc} in {rel_path}:{line}. The app may bypass system proxy settings, making network interception harder for security testing."),
                        Medium,
                        "network",
                    )
                    .file_path(rel_path.clone())
                    .line(line)
                    .cwe("CWE-693")
                    .masvs("MASVS-NETWORK"),
                );
            }
        }
    }
    findings
}
