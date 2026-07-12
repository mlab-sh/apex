//! Android SAST — Java/Kotlin/Smali security rules via pattern matching.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx_flags};
use fancy_regex::Regex;
use std::collections::HashSet;
use std::path::Path;

struct Rule {
    id: &'static str,
    title: &'static str,
    desc: &'static str,
    sev: Severity,
    pat: &'static str,
    i: bool,
    s: bool,
    cwe: Option<&'static str>,
    masvs: Option<&'static str>,
}

use Severity::*;

fn rules() -> Vec<Rule> {
    vec![
        Rule { id: "SAST_SSL_INSECURE", title: "Insecure SSL implementation", desc: "Custom SSLSocketFactory or TrustManager that may disable SSL validation.", sev: High, pat: r#"(AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|InsecureSSLSocketFactory|SSLCertificateSocketFactory\.getInsecure)"#, i: false, s: false, cwe: Some("CWE-295"), masvs: Some("MASVS-NETWORK") },
        Rule { id: "SAST_WEBVIEW_SSL_BYPASS", title: "WebView SSL certificate validation bypass", desc: "onReceivedSslError calls handler.proceed(), accepting invalid certificates in a WebView.", sev: High, pat: r#"onReceivedSslError[^}]*?\.proceed\s*\("#, i: false, s: true, cwe: Some("CWE-295"), masvs: Some("MASVS-NETWORK") },
        Rule { id: "SAST_SELF_SIGNED_CERT", title: "Self-signed certificate acceptance", desc: "Custom TrustManager that accepts all certificates without validation (empty or always-returning checkServerTrusted).", sev: High, pat: r#"checkServerTrusted\s*\([^)]*\)\s*\{[\s\n]*(return\s*;?\s*)?\}"#, i: false, s: true, cwe: Some("CWE-295"), masvs: Some("MASVS-NETWORK") },
        Rule { id: "SAST_ECB_MODE", title: "ECB mode detected", desc: "ECB (Electronic Codebook) mode is used. This mode does not mask patterns in encrypted data.", sev: High, pat: r#"(?:Cipher\.getInstance\s*\(\s*["'][^"']*?/ECB[/"']|["']AES/ECB[/"']|["']DES/ECB[/"']|["']DESede/ECB[/"'])"#, i: false, s: false, cwe: Some("CWE-327"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_WEAK_CIPHER", title: "Weak cipher detected", desc: "Weak or obsolete cipher algorithm used (RC2, RC4, DES, Blowfish, 3DES).", sev: High, pat: r#"Cipher\.getInstance\s*\(\s*["'](RC2|RC4|ARCFOUR|DES(?!ede)|Blowfish|DESede)[/"']"#, i: false, s: false, cwe: Some("CWE-327"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_WEAK_HASH", title: "Weak hash (MD5/SHA-1)", desc: "MD5 or SHA-1 used for hashing. These algorithms are vulnerable to collisions.", sev: Medium, pat: r#"MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-?1)["']\s*\)"#, i: false, s: false, cwe: Some("CWE-328"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_RSA_NO_OAEP", title: "RSA without OAEP padding", desc: "RSA used without OAEP padding (RSA/ECB/PKCS1Padding or RSA/None). Vulnerable to padding oracle attacks.", sev: High, pat: r#"Cipher\.getInstance\s*\(\s*["']RSA/(ECB|None)/(PKCS1Padding|NoPadding)["']\s*\)"#, i: false, s: false, cwe: Some("CWE-780"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_WEAK_IV", title: "Weak initialization vector", desc: "IV initialized with constant bytes, zeros, or a hardcoded value. IVs must be random and unique.", sev: High, pat: r#"IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[\s*\]\s*\{[0-9, ]+\}|["'][^"']+["']\.getBytes)"#, i: false, s: false, cwe: Some("CWE-329"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_WORLD_READABLE", title: "World-readable / world-writable file", desc: "File created with MODE_WORLD_READABLE or MODE_WORLD_WRITABLE. Any app can access it.", sev: High, pat: r#"MODE_WORLD_(READABLE|WRITABLE)"#, i: false, s: false, cwe: Some("CWE-276"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_SHARED_PREFS_INSECURE", title: "SharedPreferences in non-private mode", desc: "SharedPreferences opened with a mode other than MODE_PRIVATE. Data may be readable by other apps.", sev: Medium, pat: r#"getSharedPreferences\s*\([^)]*,\s*(MODE_WORLD_READABLE|MODE_WORLD_WRITABLE|Context\.MODE_MULTI_PROCESS|[1-9])\s*\)"#, i: false, s: false, cwe: Some("CWE-276"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_TEMP_FILE", title: "Temporary file creation", desc: "File.createTempFile() creates files in a potentially accessible directory. Check permissions and cleanup.", sev: Low, pat: r#"File\.createTempFile\s*\("#, i: false, s: false, cwe: Some("CWE-377"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_WEBVIEW_JS", title: "WebView JavaScript enabled", desc: "JavaScript is enabled in a WebView. Malicious JS could access app resources.", sev: Medium, pat: r#"\.setJavaScriptEnabled\s*\(\s*true\s*\)"#, i: false, s: false, cwe: Some("CWE-749"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "SAST_WEBVIEW_FILE_ACCESS", title: "WebView file access from URLs", desc: "File system access enabled in WebView (setAllowFileAccess / setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs).", sev: High, pat: r#"\.(setAllowFileAccess|setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)\s*\(\s*true\s*\)"#, i: false, s: false, cwe: Some("CWE-200"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "SAST_WEBVIEW_DEBUG", title: "WebView remote debugging enabled", desc: "Remote debugging enabled on WebView via setWebContentsDebuggingEnabled(true).", sev: High, pat: r#"setWebContentsDebuggingEnabled\s*\(\s*true\s*\)"#, i: false, s: false, cwe: Some("CWE-489"), masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_WEBVIEW_INTERFACE", title: "WebView unsafe interface exposure", desc: "addJavascriptInterface() exposes Java objects to JavaScript. May allow code execution if improperly protected.", sev: Medium, pat: r#"\.addJavascriptInterface\s*\("#, i: false, s: false, cwe: Some("CWE-749"), masvs: Some("MASVS-PLATFORM") },
        Rule { id: "SAST_JACKSON_DESER", title: "Unsafe Jackson deserialization", desc: "ObjectMapper with enableDefaultTyping() or DefaultTyping enabled. Allows deserialization of arbitrary classes (potential RCE).", sev: Critical, pat: r#"(enableDefaultTyping\s*\(|DefaultTyping\.(EVERYTHING|NON_FINAL|OBJECT_AND_NON_CONCRETE|NON_CONCRETE_AND_ARRAYS)|activateDefaultTyping\s*\()"#, i: false, s: false, cwe: Some("CWE-502"), masvs: Some("MASVS-CODE") },
        Rule { id: "SAST_DEBUG_BUILD", title: "Debug build detection", desc: "BuildConfig.DEBUG or debuggable flag check detected. Ensure debug features are disabled in release.", sev: Info, pat: r#"(BuildConfig\.DEBUG|isDebuggable|ApplicationInfo\.FLAG_DEBUGGABLE)"#, i: false, s: false, cwe: None, masvs: None },
        Rule { id: "SAST_EXTERNAL_STORAGE", title: "External storage access", desc: "App accesses external storage (getExternalStorageDirectory, getExternalFilesDir). Data there is readable by all apps.", sev: Medium, pat: r#"(getExternalStorageDirectory|getExternalFilesDir|getExternalCacheDir|Environment\.DIRECTORY_)"#, i: false, s: false, cwe: Some("CWE-276"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_CLIPBOARD", title: "Clipboard operations", desc: "App interacts with the clipboard (copy/paste). Copied data is accessible to all apps.", sev: Medium, pat: r#"(ClipboardManager|ClipData\.newPlainText|setPrimaryClip|getPrimaryClip|android\.content\.ClipboardManager)"#, i: false, s: false, cwe: Some("CWE-200"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_LOGGING", title: "Potentially insecure logging", desc: "Usage of Log.d/Log.v/Log.i/System.out.println. Logs may expose sensitive data on a compromised device.", sev: Low, pat: r#"(Log\.(d|v|i|w|e|wtf)\s*\(|System\.(out|err)\.(println|print)\s*\(|\.log\s*\(\s*Level\.(FINE|FINER|FINEST))"#, i: false, s: false, cwe: Some("CWE-532"), masvs: Some("MASVS-STORAGE") },
        Rule { id: "SAST_SQL_INJECTION", title: "Potential SQL injection", desc: "Raw SQL query using rawQuery() or execSQL() with string concatenation. Use parameterized queries.", sev: High, pat: r#"\.(?:rawQuery|execSQL)\s*\([^)]*\+"#, i: false, s: false, cwe: Some("CWE-89"), masvs: Some("MASVS-CODE") },
        Rule { id: "SAST_INSECURE_RNG", title: "Insecure RNG", desc: "java.util.Random used instead of java.security.SecureRandom. Use SecureRandom for crypto operations.", sev: Medium, pat: r#"(?<!\.)new\s+Random\s*\("#, i: false, s: false, cwe: Some("CWE-330"), masvs: Some("MASVS-CRYPTO") },
        Rule { id: "SAST_ROOT_ACCESS", title: "Root/superuser access request", desc: "The app requests or checks for root/superuser access. May indicate malicious behavior or a security tool.", sev: Medium, pat: r#"(Runtime\.getRuntime\(\)\.exec\s*\(\s*["']su["']|/system/xbin/su|/system/bin/su|com\.noshufou\.android\.su|eu\.chainfire\.supersu|com\.topjohnwu\.magisk)"#, i: false, s: false, cwe: Some("CWE-250"), masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_TAPJACKING", title: "Tapjacking prevention", desc: "filterTouchesWhenObscured detected. Good practice: protects against overlay attacks (tapjacking).", sev: Info, pat: r#"(filterTouchesWhenObscured|FLAG_WINDOW_IS_OBSCURED|setFilterTouchesWhenObscured\s*\(\s*true\s*\))"#, i: false, s: false, cwe: None, masvs: Some("MASVS-PLATFORM") },
        Rule { id: "SAST_SCREENSHOT_BLOCK", title: "Screenshot blocking", desc: "FLAG_SECURE detected. Good practice: prevents screenshots and screen recording.", sev: Info, pat: r#"(FLAG_SECURE|LayoutParams\.FLAG_SECURE|WindowManager\.LayoutParams\.FLAG_SECURE)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_SSL_PINNING", title: "SSL pinning implemented", desc: "Certificate pinning implementation detected. Good practice to prevent MITM attacks.", sev: Info, pat: r#"(CertificatePinner|\.sha256/|networkSecurityConfig|TrustManagerFactory\.getInstance|X509TrustManager.*checkServerTrusted.*verify)"#, i: false, s: true, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "SAST_CERT_TRANSPARENCY", title: "Certificate Transparency", desc: "Certificate Transparency implementation detected. Good practice to detect fraudulent certificates.", sev: Info, pat: r#"(certificateTransparency|ct-log|CTLogInfo|CertificateTransparencyInterceptor|installCertificateTransparency)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-NETWORK") },
        Rule { id: "SAST_PACKAGE_VERIFY", title: "Package signature verification", desc: "Package signature verification detected. Good practice to detect repackaging.", sev: Info, pat: r#"(PackageManager\.GET_SIGNATURES|PackageManager\.GET_SIGNING_CERTIFICATES|packageManager\.getPackageInfo.*signatures|getPackageInfo\([^)]*PackageManager)"#, i: false, s: true, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_TAMPER_DETECT", title: "Tamper detection", desc: "Tamper detection mechanism found (CRC check, APK checksum, integrity verification).", sev: Info, pat: r#"(classes\.dex.*crc|ZipEntry.*getCrc|getPackageCodePath|ApplicationInfo\.sourceDir.*checksum|apk.*integrity)"#, i: true, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_ROOT_DETECT", title: "Root detection", desc: "Root detection mechanism found (RootBeer, su binary check, build tags verification).", sev: Info, pat: r#"(RootBeer|isDeviceRooted|checkForSuBinary|test-keys|/system/app/Superuser|com\.scottyab\.rootbeer)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_DEBUGGER_DETECT", title: "Debugger detection", desc: "Debugger detection mechanism found (isDebuggerConnected, ptrace, anti-debug).", sev: Info, pat: r#"(Debug\.isDebuggerConnected|Debug\.waitingForDebugger|isDebuggerConnected|android\.os\.Debug|TracerPid)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_EMULATOR_DETECT", title: "Emulator detection", desc: "Emulator detection mechanism found (Build properties check, specific files).", sev: Info, pat: r#"(Build\.(FINGERPRINT|MODEL|MANUFACTURER|BRAND|DEVICE|PRODUCT).*(?:generic|sdk|emulator|genymotion|google_sdk|Emulator|goldfish|ranchu)|/dev/socket/qemud|/dev/qemu_pipe|qemu\.hw\.)"#, i: true, s: true, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_FRIDA_DETECT", title: "Frida detection", desc: "Frida detection mechanism found (port 27042, frida libraries, named pipes).", sev: Info, pat: r#"(frida-server|frida-agent|27042|libfrida|frida-gadget|re\.frida\.server|/proc/self/maps.*frida|linjector)"#, i: true, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_DEXGUARD", title: "DexGuard protections", desc: "DexGuard usage detected. Commercial protection against reverse engineering.", sev: Info, pat: r#"(dexguard|DexGuard|com\.guardsquare\.dexguard)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
        Rule { id: "SAST_SAFETYNET", title: "Usage SafetyNet / Play Integrity API", desc: "SafetyNet Attestation or Play Integrity API detected for device integrity verification.", sev: Info, pat: r#"(SafetyNet|safetynet|PlayIntegrity|IntegrityManager|IntegrityTokenRequest|SafetyNetApi\.attest|com\.google\.android\.gms\.safetynet|com\.google\.android\.play\.core\.integrity)"#, i: false, s: false, cwe: None, masvs: Some("MASVS-RESILIENCE") },
    ]
}

pub struct AndroidSastAnalyzer;

impl Analyzer for AndroidSastAnalyzer {
    fn name(&self) -> &'static str {
        "SAST Android (Java/Kotlin)"
    }
    fn category(&self) -> &'static str {
        "sast"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let files = find_files_by_ext(extracted, &["java", "kt", "smali"]);
        if files.is_empty() {
            return vec![];
        }

        let compiled: Vec<(Rule, Regex)> = rules()
            .into_iter()
            .map(|r| {
                let re = rx_flags(r.pat, r.i, r.s, false);
                (r, re)
            })
            .collect();

        let mut findings = Vec::new();
        let mut seen: HashSet<(String, String)> = HashSet::new();

        for fpath in &files {
            let content = match read_text(fpath) {
                Some(c) => c,
                None => continue,
            };
            let rel_path = rel(fpath, extracted);

            for (rule, re) in &compiled {
                let m = match re.find(&content) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };
                let key = (rule.id.to_string(), rel_path.clone());
                if seen.contains(&key) {
                    continue;
                }
                seen.insert(key);
                let line = line_of(&content, m.start());

                let mut f = Finding::new(rule.id, rule.title, rule.desc, rule.sev, "sast")
                    .file_path(rel_path.clone())
                    .line(line);
                if let Some(c) = rule.cwe {
                    f = f.cwe(c);
                }
                if let Some(m) = rule.masvs {
                    f = f.masvs(m);
                }
                findings.push(f);
            }
        }

        findings
    }
}
