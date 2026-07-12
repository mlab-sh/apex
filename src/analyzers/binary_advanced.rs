//! Advanced binary analysis — packer detection, DWARF exposure, obfuscation scoring, anti-RE.

use super::Analyzer;
use crate::elf_util::parse_file;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, read_text, rel, rx_flags, walk_all_files};
use serde_json::json;
use std::io::Read;
use std::path::Path;

use Severity::*;

const PACKER_SIGNATURES: &[(&str, &str)] = &[
    ("libjiagu", "Qihoo 360 Jiagu"),
    ("libDexHelper", "DEXProtector"),
    ("libexec", "Bangcle"),
    ("libsecexe", "Bangcle"),
    ("libbaiduprotect", "Baidu Protect"),
    ("libprotectClass", "Ijiami"),
    ("libijiami", "Ijiami"),
    ("libAPKProtect", "APKProtect"),
    ("libSecShell", "SecShell"),
    ("libmobisec", "Alibaba MobiSec"),
    ("libtencentloc", "Tencent Legu"),
    ("libshell", "Tencent Legu"),
    ("libtosprotection", "Tencent"),
    ("libnesec", "NetEase Yidun"),
    ("libdexjni", "Pangxie"),
    ("libegis", "Nagain"),
    ("libcmsgurd", "China Mobile Guard"),
    ("libNSaferOnly", "NSafer"),
    ("libDexGuard", "DexGuard (GuardSquare)"),
    ("libxposed", "Xposed Framework"),
];

const PACKER_STRINGS: &[&str] = &[
    "assets/classes.dex.dat",
    "assets/ijm_lib/",
    "assets/bangcle",
    "assets/360SelfProtect",
    "assets/libjiagu",
    "META-INF/BNDLTOOL",
    "tencent_stub",
    "com.secneo.apkwrapper",
    "com.qihoo.util",
    "com.stub.StubApp",
];

const ANTI_RE_TECHNIQUES: &[(&str, &str, &str)] = &[
    ("root_detection", r#"(RootBeer|isDeviceRooted|checkForSuBinary|test-keys|/system/app/Superuser)"#, "Root detection"),
    ("debugger_detection", r#"(Debug\.isDebuggerConnected|TracerPid|android\.os\.Debug|isDebuggerConnected)"#, "Debugger detection"),
    ("emulator_detection", r#"(generic.*Build|goldfish|ranchu|google_sdk|sdk_gphone|emulator)"#, "Emulator detection"),
    ("frida_detection", r#"(frida-server|frida-agent|frida-gadget|27042|libfrida)"#, "Frida detection"),
    ("xposed_detection", r#"(de\.robv\.android\.xposed|XposedBridge|XposedHelpers)"#, "Xposed detection"),
    ("tamper_detection", r#"(classes\.dex.*crc|ZipEntry.*getCrc|getPackageCodePath.*checksum|apk.*integrity)"#, "Tamper/integrity check"),
    ("signature_check", r#"(PackageManager\.GET_SIGNATURES|GET_SIGNING_CERTIFICATES|signatures\[0\])"#, "Signature verification"),
    ("ssl_pinning", r#"(CertificatePinner|sha256/|TrustManagerFactory|X509TrustManager.*verify)"#, "SSL pinning"),
    ("native_anti_debug", r#"(ptrace|PTRACE_TRACEME|PR_SET_DUMPABLE)"#, "Native anti-debug (ptrace)"),
];

pub struct AdvancedBinaryAnalyzer;

impl Analyzer for AdvancedBinaryAnalyzer {
    fn name(&self) -> &'static str {
        "Advanced Binary Analysis"
    }
    fn category(&self) -> &'static str {
        "binary_advanced"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let mut findings = Vec::new();
        findings.extend(detect_packers(extracted));
        findings.extend(detect_string_encryption(extracted));
        findings.extend(check_dwarf(extracted));
        findings.extend(score_obfuscation(extracted));
        findings.extend(assess_anti_re(extracted));
        findings
    }
}

fn so_files(extracted: &Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = walk_all_files(extracted)
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("so"))
        .collect();
    v.sort();
    v
}

fn all_rel_paths(extracted: &Path) -> String {
    let mut v: Vec<String> = walk_all_files(extracted)
        .iter()
        .map(|p| rel(p, extracted))
        .collect();
    v.sort();
    v.join("\n")
}

fn detect_packers(extracted: &Path) -> Vec<Finding> {
    let mut detected: Vec<String> = Vec::new();

    for so in so_files(extracted) {
        let name = so.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        for (sig, packer) in PACKER_SIGNATURES {
            if name.contains(sig) && !detected.iter().any(|d| d == packer) {
                detected.push(packer.to_string());
            }
        }
    }

    let all_paths = all_rel_paths(extracted);
    for sig in PACKER_STRINGS {
        if all_paths.contains(sig) {
            let label = format!("Packer artifact: {sig}");
            if !detected.contains(&label) {
                detected.push(label);
            }
        }
    }

    if detected.is_empty() {
        return vec![];
    }
    vec![Finding::new(
        "ADV_PACKER_DETECTED",
        format!("Packer/protector detected ({})", detected.len()),
        format!(
            "The APK appears to be packed or protected: {}. Packed apps require unpacking before full static analysis is possible.",
            detected.join(", ")
        ),
        Medium,
        "binary_advanced",
    )
    .masvs("MASVS-RESILIENCE")
    .meta("packers", json!(detected))]
}

fn detect_string_encryption(extracted: &Path) -> Vec<Finding> {
    let smali = find_files_by_ext(extracted, &["smali"]);
    if smali.is_empty() {
        return vec![];
    }
    let patterns = [
        r#"invoke-static.*->decrypt\("#,
        r#"invoke-static.*->decode\("#,
        r#"invoke-static.*->a\(Ljava/lang/String;\)Ljava/lang/String;"#,
        r#"const-string.*\\u[0-9a-f]{4}"#,
        r#"invoke-static.*->getString\(I\)"#,
    ];
    let compiled: Vec<_> = patterns.iter().map(|p| rx_flags(p, false, false, false)).collect();

    let mut encrypted_count = 0usize;
    let mut sampled = 0usize;
    for smali_path in smali.iter().take(100) {
        if let Some(content) = read_text(smali_path) {
            sampled += 1;
            for re in &compiled {
                if re.is_match(&content).unwrap_or(false) {
                    encrypted_count += 1;
                    break;
                }
            }
        }
    }

    if encrypted_count == 0 {
        return vec![];
    }
    let ratio = encrypted_count as f64 / (sampled.max(1)) as f64;
    vec![Finding::new(
        "ADV_STRING_ENCRYPTION",
        format!("String encryption detected ({encrypted_count}/{sampled} files)"),
        format!(
            "String decryption patterns found in {encrypted_count} out of {sampled} sampled smali files ({}%). Strings are likely encrypted at rest and decrypted at runtime.",
            (ratio * 100.0).round() as i64
        ),
        Info,
        "binary_advanced",
    )
    .masvs("MASVS-RESILIENCE")
    .meta("encrypted_files", json!(encrypted_count))
    .meta("sampled", json!(sampled))
    .meta("ratio", json!(round2(ratio)))]
}

fn check_dwarf(extracted: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    for so in so_files(extracted) {
        let info = match parse_file(&so) {
            Some((_, info)) => info,
            None => continue,
        };
        let dwarf: Vec<String> = info
            .sections
            .iter()
            .filter(|s| s.starts_with(".debug_"))
            .cloned()
            .collect();
        if !dwarf.is_empty() {
            let rel_path = rel(&so, extracted);
            findings.push(
                Finding::new(
                    "ADV_DWARF_EXPOSED",
                    format!("DWARF debug info exposed: {rel_path}"),
                    format!(
                        "Native library '{rel_path}' contains DWARF debug sections: {}. This reveals source file paths, function names, and variable types to reverse engineers.",
                        dwarf.join(", ")
                    ),
                    Medium,
                    "binary_advanced",
                )
                .file_path(rel_path.clone())
                .cwe("CWE-215")
                .masvs("MASVS-RESILIENCE")
                .meta("dwarf_sections", json!(dwarf)),
            );
        }
    }
    findings
}

fn score_obfuscation(extracted: &Path) -> Vec<Finding> {
    let mut score = 0i64;
    let mut max_score = 0i64;
    let mut details: Vec<(&str, bool)> = Vec::new();

    // short smali class names
    let smali = find_files_by_ext(extracted, &["smali"]);
    if !smali.is_empty() {
        max_score += 3;
        let short_names = smali
            .iter()
            .filter(|f| f.file_stem().and_then(|s| s.to_str()).map(|s| s.len() <= 2).unwrap_or(false))
            .count();
        let ratio = short_names as f64 / smali.len().max(1) as f64;
        if ratio > 0.3 {
            score += 3;
            details.push(("short_class_names", true));
        } else if ratio > 0.1 {
            score += 1;
            details.push(("short_class_names", true));
        } else {
            details.push(("short_class_names", false));
        }
    }

    // debug info in jars
    let mut class_in_jars = 0usize;
    let mut debug_in_jars = 0usize;
    for jar in walk_all_files(extracted)
        .into_iter()
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jar"))
    {
        if let Ok(file) = std::fs::File::open(&jar) {
            if let Ok(mut archive) = zip::ZipArchive::new(file) {
                for i in 0..archive.len() {
                    let is_class;
                    let mut data = Vec::new();
                    {
                        let mut entry = match archive.by_index(i) {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        is_class = entry.name().ends_with(".class");
                        if is_class {
                            entry.read_to_end(&mut data).ok();
                        }
                    }
                    if is_class {
                        class_in_jars += 1;
                        if find_bytes(&data, b"LocalVariableTable") {
                            debug_in_jars += 1;
                        }
                    }
                }
            }
        }
    }
    if class_in_jars > 0 {
        max_score += 2;
        let debug_ratio = debug_in_jars as f64 / class_in_jars as f64;
        if debug_ratio < 0.1 {
            score += 2;
            details.push(("debug_stripped", true));
        } else {
            details.push(("debug_stripped", false));
        }
    }

    // native stripped
    let sos = so_files(extracted);
    if !sos.is_empty() {
        max_score += 2;
        let mut stripped_count = 0usize;
        for so in &sos {
            if let Some((_, info)) = parse_file(so) {
                if info.stripped {
                    stripped_count += 1;
                }
            }
        }
        if stripped_count == sos.len() {
            score += 2;
            details.push(("native_stripped", true));
        } else {
            details.push(("native_stripped", false));
        }
    }

    // packer
    max_score += 3;
    let all_paths = all_rel_paths(extracted);
    let has_packer = PACKER_STRINGS.iter().any(|sig| all_paths.contains(sig))
        || sos.iter().any(|p| {
            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            PACKER_SIGNATURES.iter().any(|(sig, _)| stem.contains(sig))
        });
    if has_packer {
        score += 3;
        details.push(("packer", true));
    } else {
        details.push(("packer", false));
    }

    if max_score == 0 {
        return vec![];
    }

    let pct = score as f64 / max_score as f64;
    let (level, sev) = if pct >= 0.7 {
        ("strong", Info)
    } else if pct >= 0.4 {
        ("moderate", Low)
    } else {
        ("weak", Medium)
    };

    let present: Vec<&str> = details.iter().filter(|(_, v)| *v).map(|(k, _)| *k).collect();
    let missing: Vec<&str> = details.iter().filter(|(_, v)| !*v).map(|(k, _)| *k).collect();
    let present_s = if present.is_empty() { "none".to_string() } else { present.join(", ") };
    let missing_s = if missing.is_empty() { "none".to_string() } else { missing.join(", ") };

    let mut details_json = serde_json::Map::new();
    for (k, v) in &details {
        details_json.insert(k.to_string(), json!(v));
    }

    vec![Finding::new(
        "ADV_OBFUSCATION_SCORE",
        format!("Obfuscation strength: {level} ({score}/{max_score})"),
        format!(
            "Obfuscation assessment: {level} ({}%). Indicators: {present_s}. Missing: {missing_s}.",
            (pct * 100.0).round() as i64
        ),
        sev,
        "binary_advanced",
    )
    .masvs("MASVS-RESILIENCE")
    .meta("score", json!(score))
    .meta("max_score", json!(max_score))
    .meta("percentage", json!(round2(pct)))
    .meta("details", serde_json::Value::Object(details_json))]
}

fn assess_anti_re(extracted: &Path) -> Vec<Finding> {
    let mut code = String::new();
    for ext in ["java", "kt", "smali", "js"] {
        for fpath in find_files_by_ext(extracted, &[ext]) {
            if std::fs::metadata(&fpath).map(|m| m.len()).unwrap_or(u64::MAX) < 5_000_000 {
                if let Some(c) = read_text(&fpath) {
                    code.push_str(&c);
                    code.push('\n');
                }
            }
        }
    }
    if code.is_empty() {
        return vec![];
    }

    let mut detected: Vec<&str> = Vec::new();
    let mut missing: Vec<&str> = Vec::new();
    for (_tech, pattern, desc) in ANTI_RE_TECHNIQUES {
        if rx_flags(pattern, true, false, false).is_match(&code).unwrap_or(false) {
            detected.push(desc);
        } else {
            missing.push(desc);
        }
    }

    let total = ANTI_RE_TECHNIQUES.len();
    let count = detected.len();
    let pct = count as f64 / total as f64;
    let (level, sev) = if pct >= 0.7 {
        ("strong", Info)
    } else if pct >= 0.3 {
        ("moderate", Low)
    } else {
        ("weak", Medium)
    };

    let present_s = if detected.is_empty() { "none".to_string() } else { detected.join(", ") };
    let missing_s = if missing.is_empty() { "none".to_string() } else { missing.join(", ") };

    vec![Finding::new(
        "ADV_ANTI_RE",
        format!("Anti-reverse engineering: {level} ({count}/{total})"),
        format!("Anti-RE assessment: {level}. Present: {present_s}. Missing: {missing_s}."),
        sev,
        "binary_advanced",
    )
    .masvs("MASVS-RESILIENCE")
    .meta("detected", json!(detected))
    .meta("missing", json!(missing))
    .meta("score", json!(count))
    .meta("total", json!(total))]
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
