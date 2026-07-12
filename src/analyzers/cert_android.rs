//! Android APK certificate & signature analyzer.

use super::Analyzer;
use crate::cert_util::{parse_pkcs7, CertData};
use crate::models::{AppType, Finding, Severity};
use crate::util::{rel, walk_all_files};
use crate::xml;
use md5::Md5;
use serde_json::json;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::path::Path;

use Severity::*;

const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";
const SCHEME_V2_ID: u32 = 0x7109_871A;
const SCHEME_V3_ID: u32 = 0xF053_68C0;
const SCHEME_V31_ID: u32 = 0x1B93_AD61;

const DEBUG_SUBJECTS: &[&str] = &["Android Debug", "CN=Android Debug", "O=Android,CN=Android Debug"];
const WEAK_HASH_ALGOS: &[&str] = &["md5", "md2", "sha1"];

fn min_key_size(algo: &str) -> Option<usize> {
    match algo {
        "rsa" => Some(2048),
        "dsa" => Some(2048),
        "ec" => Some(256),
        _ => None,
    }
}

pub struct AndroidCertAnalyzer;

impl Analyzer for AndroidCertAnalyzer {
    fn name(&self) -> &'static str {
        "Android Certificates & Signature"
    }
    fn category(&self) -> &'static str {
        "certificate"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, original: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();

        let schemes = detect_schemes(extracted, original);
        findings.extend(check_schemes(&schemes));

        for (cert, sig_file) in extract_v1_certs(extracted) {
            findings.extend(check_debug_cert(&cert, &sig_file));
            findings.extend(check_weak_algo(&cert, &sig_file));
            findings.extend(check_key_size(&cert, &sig_file));
            findings.extend(check_validity(&cert, &sig_file));
            findings.push(emit_cert_info(&cert, &sig_file));
        }

        findings.extend(check_janus(&schemes, extracted));
        findings.extend(check_hardcoded_certs(extracted));

        findings
    }
}

struct Schemes {
    v1: bool,
    v2: bool,
    v3: bool,
    v4: bool,
}

fn detect_schemes(extracted: &Path, original: &Path) -> Schemes {
    let mut s = Schemes {
        v1: false,
        v2: false,
        v3: false,
        v4: false,
    };

    let meta_inf = extracted.join("META-INF");
    if meta_inf.is_dir() {
        if let Ok(rd) = std::fs::read_dir(&meta_inf) {
            for entry in rd.flatten() {
                if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                    let up = ext.to_ascii_uppercase();
                    if up == "RSA" || up == "DSA" || up == "EC" {
                        s.v1 = true;
                        break;
                    }
                }
            }
        }
    }

    if original.exists() {
        let (v2, v3) = parse_signing_block(original);
        s.v2 = v2;
        s.v3 = v3;
    }

    let idsig = original.with_extension("idsig");
    if idsig.exists() {
        s.v4 = true;
    }

    s
}

fn parse_signing_block(apk_path: &Path) -> (bool, bool) {
    let data = match std::fs::read(apk_path) {
        Ok(d) => d,
        Err(_) => return (false, false),
    };
    let eocd = match rfind(&data, &[0x50, 0x4b, 0x05, 0x06]) {
        Some(i) => i,
        None => return (false, false),
    };
    let cd_offset = match read_u32_le(&data, eocd + 16) {
        Some(v) => v as usize,
        None => return (false, false),
    };
    if cd_offset < 24 {
        return (false, false);
    }
    let magic_start = cd_offset - 16;
    if magic_start + 16 > data.len() || data[magic_start..magic_start + 16] != APK_SIG_BLOCK_MAGIC[..]
    {
        return (false, false);
    }
    let block_size = match read_u64_le(&data, magic_start.wrapping_sub(8)) {
        Some(v) => v as usize,
        None => return (false, false),
    };
    let block_start = match cd_offset.checked_sub(block_size).and_then(|v| v.checked_sub(8)) {
        Some(v) => v,
        None => return (false, false),
    };
    let mut pos = block_start + 8;
    let block_end = magic_start - 8;
    let (mut v2, mut v3) = (false, false);

    while pos < block_end {
        if pos + 12 > block_end {
            break;
        }
        let pair_size = match read_u64_le(&data, pos) {
            Some(v) => v as usize,
            None => break,
        };
        let pair_id = match read_u32_le(&data, pos + 8) {
            Some(v) => v,
            None => break,
        };
        if pair_id == SCHEME_V2_ID {
            v2 = true;
        } else if pair_id == SCHEME_V3_ID || pair_id == SCHEME_V31_ID {
            v3 = true;
        }
        pos = match pos.checked_add(8).and_then(|v| v.checked_add(pair_size)) {
            Some(v) => v,
            None => break,
        };
    }
    (v2, v3)
}

fn check_schemes(s: &Schemes) -> Vec<Finding> {
    let mut findings = Vec::new();
    let all = [("v1", s.v1), ("v2", s.v2), ("v3", s.v3), ("v4", s.v4)];
    let present: Vec<&str> = all.iter().filter(|(_, v)| *v).map(|(k, _)| *k).collect();
    let absent: Vec<&str> = all.iter().filter(|(_, v)| !*v).map(|(k, _)| *k).collect();

    if present.is_empty() {
        findings.push(Finding::new(
            "CERT_NOT_SIGNED",
            "APK not signed",
            "No signing scheme detected. The APK is not signed.",
            Critical,
            "certificate",
        ));
    } else {
        findings.push(
            Finding::new(
                "CERT_SCHEMES",
                format!("Signing schemes: {}", present.join(", ")),
                format!("Present: {}. Missing: {}.", present.join(", "), absent.join(", ")),
                Info,
                "certificate",
            )
            .meta(
                "schemes",
                json!({"v1": s.v1, "v2": s.v2, "v3": s.v3, "v4": s.v4}),
            ),
        );

        if s.v1 && !s.v2 && !s.v3 {
            findings.push(
                Finding::new(
                    "CERT_V1_ONLY",
                    "v1 signature only (JAR)",
                    "The APK uses only v1 (JAR) signature. v2/v3 schemes provide stronger protection against modification.",
                    Medium,
                    "certificate",
                )
                .cwe("CWE-347")
                .masvs("MASVS-RESILIENCE"),
            );
        }
    }
    findings
}

fn extract_v1_certs(extracted: &Path) -> Vec<(CertData, String)> {
    let mut out = Vec::new();
    let meta_inf = extracted.join("META-INF");
    if !meta_inf.is_dir() {
        return out;
    }
    let mut entries: Vec<_> = match std::fs::read_dir(&meta_inf) {
        Ok(rd) => rd.flatten().map(|e| e.path()).collect(),
        Err(_) => return out,
    };
    entries.sort();
    for path in entries {
        let up = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_uppercase());
        if !matches!(up.as_deref(), Some("RSA") | Some("DSA") | Some("EC")) {
            continue;
        }
        let raw = match std::fs::read(&path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("").to_string();
        for cert in parse_pkcs7(&raw) {
            out.push((cert, name.clone()));
        }
    }
    out
}

fn check_debug_cert(cert: &CertData, sig_file: &str) -> Vec<Finding> {
    let subject_l = cert.subject.to_lowercase();
    for pattern in DEBUG_SUBJECTS {
        if subject_l.contains(&pattern.to_lowercase()) {
            return vec![Finding::new(
                "CERT_DEBUG",
                "Debug certificate detected",
                format!(
                    "Certificate in {sig_file} is a debug certificate (subject: {}). A production app must not be signed with a debug cert.",
                    cert.subject
                ),
                Critical,
                "certificate",
            )
            .cwe("CWE-489")
            .masvs("MASVS-RESILIENCE")
            .meta("subject", json!(cert.subject))
            .meta("file", json!(sig_file))];
        }
    }
    vec![]
}

fn check_weak_algo(cert: &CertData, sig_file: &str) -> Vec<Finding> {
    if WEAK_HASH_ALGOS.contains(&cert.hash_algo.as_str()) {
        return vec![Finding::new(
            "CERT_WEAK_ALGO",
            format!("Weak signature algorithm: {}", cert.sig_algo_name),
            format!(
                "Certificate in {sig_file} uses {} (hash: {}), which is considered cryptographically weak.",
                cert.sig_algo_name, cert.hash_algo
            ),
            High,
            "certificate",
        )
        .cwe("CWE-327")
        .masvs("MASVS-CRYPTO")
        .meta("algorithm", json!(cert.sig_algo_name))
        .meta("hash", json!(cert.hash_algo))
        .meta("file", json!(sig_file))];
    }
    vec![]
}

fn check_key_size(cert: &CertData, sig_file: &str) -> Vec<Finding> {
    if let Some(min_size) = min_key_size(&cert.key_algo) {
        if cert.key_bits > 0 && cert.key_bits < min_size {
            return vec![Finding::new(
                "CERT_WEAK_KEY",
                format!("{} key too small ({} bits)", cert.key_algo.to_uppercase(), cert.key_bits),
                format!(
                    "Certificate in {sig_file} uses a {} key of {} bits. Minimum recommended: {} bits.",
                    cert.key_algo.to_uppercase(),
                    cert.key_bits,
                    min_size
                ),
                High,
                "certificate",
            )
            .cwe("CWE-326")
            .masvs("MASVS-CRYPTO")
            .meta("algorithm", json!(cert.key_algo))
            .meta("bit_size", json!(cert.key_bits))
            .meta("min_size", json!(min_size))
            .meta("file", json!(sig_file))];
        }
    }
    vec![]
}

fn check_validity(cert: &CertData, sig_file: &str) -> Vec<Finding> {
    if let Some(not_after) = cert.not_after_unix {
        let now = chrono::Utc::now().timestamp();
        if not_after < now {
            let date = fmt_date(not_after);
            return vec![Finding::new(
                "CERT_EXPIRED",
                "Certificate expired",
                format!("Certificate in {sig_file} expired on {date}."),
                Medium,
                "certificate",
            )
            .cwe("CWE-298")
            .meta("not_after", json!(cert.not_after))
            .meta("file", json!(sig_file))];
        }
    }
    vec![]
}

fn emit_cert_info(cert: &CertData, sig_file: &str) -> Finding {
    Finding::new(
        "CERT_INFO",
        format!("X.509 certificate: {sig_file}"),
        format!("Subject: {} | Issuer: {}", cert.subject, cert.issuer),
        Info,
        "certificate",
    )
    .meta("file", json!(sig_file))
    .meta("subject", json!(cert.subject))
    .meta("issuer", json!(cert.issuer))
    .meta("serial", json!(cert.serial_dec))
    .meta("not_before", json!(cert.not_before))
    .meta("not_after", json!(cert.not_after))
    .meta("signature_algorithm", json!(cert.sig_algo_name))
    .meta("public_key_algorithm", json!(cert.key_algo))
    .meta("public_key_size", json!(cert.key_bits))
    .meta("fingerprint_md5", json!(hex_upper(&Md5::digest(&cert.der))))
    .meta("fingerprint_sha1", json!(hex_upper(&Sha1::digest(&cert.der))))
    .meta("fingerprint_sha256", json!(hex_upper(&Sha256::digest(&cert.der))))
    .meta("fingerprint_sha512", json!(hex_upper(&Sha512::digest(&cert.der))))
}

fn check_janus(s: &Schemes, extracted: &Path) -> Vec<Finding> {
    if !s.v1 || s.v2 || s.v3 {
        return vec![];
    }
    if let Some(min_sdk) = get_min_sdk(extracted) {
        if min_sdk <= 26 {
            return vec![Finding::new(
                "CERT_JANUS",
                "Janus vulnerability (CVE-2017-13156)",
                format!(
                    "The APK uses v1 signature only with minSdkVersion={min_sdk} (<= 26). On Android 5.0-8.0, an attacker can modify the APK without invalidating the signature (Janus vulnerability)."
                ),
                High,
                "certificate",
            )
            .cwe("CWE-347")
            .masvs("MASVS-RESILIENCE")
            .meta("min_sdk", json!(min_sdk))
            .meta("schemes", json!({"v1": s.v1, "v2": s.v2, "v3": s.v3, "v4": s.v4}))];
        }
    }
    vec![]
}

fn get_min_sdk(extracted: &Path) -> Option<i64> {
    let manifest = extracted.join("AndroidManifest.xml");
    let raw = std::fs::read(&manifest).ok()?;
    let root = xml::parse_axml_or_xml(&raw)?;
    let uses_sdk = root.find("uses-sdk")?;
    let val = uses_sdk.android("minSdkVersion")?;
    if val.chars().all(|c| c.is_ascii_digit()) && !val.is_empty() {
        val.parse::<i64>().ok()
    } else {
        None
    }
}

fn check_hardcoded_certs(extracted: &Path) -> Vec<Finding> {
    let cert_exts = ["cer", "pem", "key", "der", "crt"];
    let keystore_exts = ["jks", "bks", "p12", "pfx", "keystore"];
    let mut findings = Vec::new();

    let mut files = walk_all_files(extracted);
    files.sort();
    for fpath in files {
        let rel_str = rel(&fpath, extracted);
        if rel_str.starts_with("META-INF") {
            continue;
        }
        let ext = match fpath.extension().and_then(|e| e.to_str()) {
            Some(e) => e.to_ascii_lowercase(),
            None => continue,
        };

        if cert_exts.contains(&ext.as_str()) {
            let mut is_private = false;
            if let Ok(bytes) = std::fs::read(&fpath) {
                let header = &bytes[..bytes.len().min(512)];
                is_private = find_bytes(header, b"PRIVATE KEY");
            }
            if is_private || ext == "key" {
                findings.push(
                    Finding::new(
                        "CERT_HARDCODED_PRIVATE_KEY",
                        format!("Hardcoded private key: {rel_str}"),
                        format!("Private key file found in the package: {rel_str}. Private keys must never be embedded in the APK."),
                        Critical,
                        "certificate",
                    )
                    .file_path(rel_str.clone())
                    .cwe("CWE-321")
                    .masvs("MASVS-CRYPTO"),
                );
            } else {
                findings.push(
                    Finding::new(
                        "CERT_HARDCODED_CERT",
                        format!("Embedded certificate: {rel_str}"),
                        format!("Public certificate file found in the package: {rel_str}. This may be legitimate (e.g. CA pinning, 3D-Secure) but should be reviewed."),
                        Medium,
                        "certificate",
                    )
                    .file_path(rel_str.clone())
                    .masvs("MASVS-CRYPTO"),
                );
            }
        }

        if keystore_exts.contains(&ext.as_str()) {
            findings.push(
                Finding::new(
                    "CERT_HARDCODED_KEYSTORE",
                    format!("Hardcoded keystore: {rel_str}"),
                    format!("Keystore file found in the package: {rel_str}. An embedded keystore may contain extractable private keys."),
                    High,
                    "certificate",
                )
                .file_path(rel_str.clone())
                .cwe("CWE-321")
                .masvs("MASVS-CRYPTO"),
            );
        }
    }
    findings
}

// -- byte helpers --

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

fn fmt_date(unix: i64) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt(unix, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d").to_string(),
        _ => "unknown".to_string(),
    }
}
