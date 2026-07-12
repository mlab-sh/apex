//! Privacy & compliance analyzer — trackers, fingerprinting, GDPR/CCPA mapping.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{read_text, rel, rx_flags, walk_all_files};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

use Severity::*;

const TRACKER_SIGNATURES: &[(&str, &str)] = &[
    ("com/google/firebase/analytics", "Google Firebase Analytics"),
    ("com/google/android/gms/analytics", "Google Analytics"),
    ("com/google/android/gms/measurement", "Google Analytics (Measurement)"),
    ("com/facebook/appevents", "Facebook Analytics"),
    ("com/flurry/android", "Flurry (Yahoo)"),
    ("com/mixpanel/android", "Mixpanel"),
    ("com/amplitude/api", "Amplitude"),
    ("com/segment/analytics", "Segment"),
    ("com/heapanalytics", "Heap Analytics"),
    ("com/countly", "Countly"),
    ("ly/count/android", "Countly"),
    ("com/adjust/sdk", "Adjust"),
    ("com/appsflyer", "AppsFlyer"),
    ("io/branch/referral", "Branch.io"),
    ("com/kochava", "Kochava"),
    ("com/singular/sdk", "Singular"),
    ("com/tenjin", "Tenjin"),
    ("com/crashlytics", "Crashlytics (Firebase)"),
    ("com/bugsnag", "Bugsnag"),
    ("io/sentry/android", "Sentry"),
    ("com/instabug", "Instabug"),
    ("com/newrelic/agent", "New Relic"),
    ("com/google/android/gms/ads", "Google AdMob"),
    ("com/facebook/ads", "Facebook Audience Network"),
    ("com/mopub", "MoPub (Twitter)"),
    ("com/applovin", "AppLovin"),
    ("com/unity3d/ads", "Unity Ads"),
    ("com/vungle", "Vungle"),
    ("com/ironsource", "ironSource"),
    ("com/inmobi/ads", "InMobi"),
    ("com/chartboost", "Chartboost"),
    ("com/adcolony", "AdColony"),
    ("com/onesignal", "OneSignal"),
    ("com/braze", "Braze"),
    ("com/urbanairship", "Airship (Urban Airship)"),
    ("com/batch/android", "Batch"),
    ("com/clevertap", "CleverTap"),
    ("com/moengage", "MoEngage"),
    ("com/pushwoosh", "Pushwoosh"),
    ("com/leanplum", "Leanplum"),
    ("com/hotjar", "Hotjar"),
    ("com/fullstory", "FullStory"),
    ("com/smartlook", "Smartlook"),
    ("io/uxcam", "UXCam"),
    ("com/appdynamics", "AppDynamics"),
    ("com/datadog", "Datadog"),
];

const FINGERPRINT_PATTERNS: &[(&str, &str)] = &[
    (r#"(Settings\.Secure\.ANDROID_ID|getString.*android_id)"#, "Android ID collection"),
    (r#"(Build\.SERIAL|Build\.getSerial)"#, "Device serial number access"),
    (r#"(getDeviceId|getImei|getMeid)\s*\("#, "IMEI/MEID collection"),
    (r#"(getSubscriberId|getSimSerialNumber)\s*\("#, "SIM/subscriber ID collection"),
    (r#"(getMacAddress|getHardwareAddress)\s*\("#, "MAC address collection"),
    (r#"(AdvertisingIdClient|getAdvertisingIdInfo|isLimitAdTrackingEnabled)"#, "Advertising ID access"),
    (r#"(fingerprint|deviceFingerprint|generateFingerprint)"#, "Custom device fingerprinting"),
    (r#"(getInstalledPackages|getInstalledApplications).*(?:hash|fingerprint|signature)"#, "App-based fingerprinting"),
];

const DATA_COLLECTION: &[(&str, &str, &str, Severity)] = &[
    ("PII_NAME", r#"(?:firstName|lastName|fullName|displayName|userName)\s*[=:]"#, "User name/identity collection", Medium),
    ("PII_EMAIL", r#"(?:email|emailAddress|userEmail)\s*[=:]"#, "Email address collection", Medium),
    ("PII_PHONE", r#"(?:phoneNumber|mobileNumber|contactNumber)\s*[=:]"#, "Phone number collection", Medium),
    ("PII_ADDRESS", r#"(?:streetAddress|postalCode|zipCode|city|country)\s*[=:]"#, "Physical address collection", Medium),
    ("PII_DOB", r#"(?:dateOfBirth|birthDate|birthday|age)\s*[=:]"#, "Date of birth/age collection", Medium),
    ("PII_SSN", r#"(?:ssn|socialSecurity|nationalId|taxId)\s*[=:]"#, "Government ID collection", High),
    ("PII_FINANCIAL", r#"(?:creditCard|cardNumber|bankAccount|iban|routingNumber)\s*[=:]"#, "Financial data collection", High),
    ("PII_HEALTH", r#"(?:healthData|medicalRecord|bloodType|heartRate|stepCount)\s*[=:]"#, "Health data collection", High),
    ("PII_BIOMETRIC", r#"(?:fingerprint|faceId|voicePrint|retinaScan)\s*[=:]"#, "Biometric data collection", High),
    ("PII_LOCATION_HISTORY", r#"(?:locationHistory|trackLocation|geoFence|geolocation.*store)\s*"#, "Location history tracking", High),
];

const TELEMETRY_PATTERNS: &[(&str, &str)] = &[
    (r#"https?://[a-z0-9.-]*\.?analytics\.google\.com"#, "Google Analytics endpoint"),
    (r#"https?://[a-z0-9.-]*\.?facebook\.com/tr"#, "Facebook Pixel/tracking endpoint"),
    (r#"https?://[a-z0-9.-]*app-measurement\.com"#, "Firebase App Measurement endpoint"),
    (r#"https?://[a-z0-9.-]*\.?appsflyer\.com"#, "AppsFlyer tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?adjust\.com"#, "Adjust tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?branch\.io"#, "Branch.io tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?mixpanel\.com"#, "Mixpanel tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?amplitude\.com"#, "Amplitude tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?segment\.(io|com)"#, "Segment tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?sentry\.io"#, "Sentry error tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?bugsnag\.com"#, "Bugsnag error tracking endpoint"),
    (r#"https?://[a-z0-9.-]*\.?datadog-agent"#, "Datadog agent endpoint"),
    (r#"https?://[a-z0-9.-]*\.?onesignal\.com"#, "OneSignal push endpoint"),
];

const CODE_EXTS: &[&str] = &["java", "kt", "smali", "xml", "json", "js", "properties"];

pub struct PrivacyAnalyzer;

impl PrivacyAnalyzer {
    fn collect_file_paths(&self, extracted: &Path) -> Vec<String> {
        walk_all_files(extracted)
            .iter()
            .map(|p| rel(p, extracted))
            .collect()
    }

    fn collect_code(&self, extracted: &Path) -> String {
        let mut parts = Vec::new();
        for fpath in walk_all_files(extracted) {
            let ext = fpath
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase());
            let size = std::fs::metadata(&fpath).map(|m| m.len()).unwrap_or(u64::MAX);
            if let Some(ext) = ext {
                if CODE_EXTS.contains(&ext.as_str()) && size < 5_000_000 {
                    if let Some(c) = read_text(&fpath) {
                        parts.push(c);
                    }
                }
            }
        }
        parts.join("\n")
    }
}

impl Analyzer for PrivacyAnalyzer {
    fn name(&self) -> &'static str {
        "Privacy & Compliance"
    }
    fn category(&self) -> &'static str {
        "privacy"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(
            app_type,
            AppType::Apk | AppType::Aab | AppType::Xapk | AppType::Ipa
        )
    }

    fn analyze(&self, extracted: &Path, app_type: AppType, _original: &Path) -> Vec<Finding> {
        let file_paths = self.collect_file_paths(extracted);
        let all_code = self.collect_code(extracted);
        let mut findings = Vec::new();

        // Tracker detection
        findings.extend(detect_trackers(&file_paths));

        // Fingerprinting
        let mut fp_detected: Vec<&str> = Vec::new();
        for (pat, desc) in FINGERPRINT_PATTERNS {
            if rx_flags(pat, true, false, false)
                .is_match(&all_code)
                .unwrap_or(false)
            {
                fp_detected.push(desc);
            }
        }
        if !fp_detected.is_empty() {
            findings.push(
                Finding::new(
                    "PRIV_FINGERPRINTING",
                    format!("Device fingerprinting ({} methods)", fp_detected.len()),
                    format!(
                        "The app collects device identifiers: {}. This may violate GDPR/CCPA if done without user consent.",
                        fp_detected.join("; ")
                    ),
                    High,
                    "privacy",
                )
                .cwe("CWE-359")
                .masvs("MASVS-PRIVACY")
                .meta("methods", json!(fp_detected)),
            );
        }

        // Data collection
        let mut collected: Vec<(&str, Severity)> = Vec::new();
        for (_id, pat, desc, sev) in DATA_COLLECTION {
            if rx_flags(pat, true, false, false)
                .is_match(&all_code)
                .unwrap_or(false)
            {
                collected.push((desc, *sev));
            }
        }
        if !collected.is_empty() {
            let sevs: Vec<Severity> = collected.iter().map(|(_, s)| *s).collect();
            let max_sev = Severity::py_max(&sevs).unwrap_or(Info);
            let descs: Vec<&str> = collected.iter().map(|(d, _)| *d).collect();
            findings.push(
                Finding::new(
                    "PRIV_DATA_COLLECTION",
                    format!("Personal data collection ({} types)", collected.len()),
                    format!(
                        "The app appears to collect: {}. Under GDPR/CCPA, explicit user consent and a privacy policy are required.",
                        descs.join("; ")
                    ),
                    max_sev,
                    "privacy",
                )
                .cwe("CWE-359")
                .masvs("MASVS-PRIVACY")
                .meta("data_types", json!(descs))
                .meta("count", json!(collected.len())),
            );
        }

        // Telemetry
        let mut tele: Vec<&str> = Vec::new();
        for (pat, desc) in TELEMETRY_PATTERNS {
            if rx_flags(pat, true, false, false)
                .is_match(&all_code)
                .unwrap_or(false)
            {
                tele.push(desc);
            }
        }
        if !tele.is_empty() {
            findings.push(
                Finding::new(
                    "PRIV_TELEMETRY",
                    format!("Telemetry endpoints ({})", tele.len()),
                    format!(
                        "Found {} telemetry/tracking endpoint(s): {}. Verify data sent to these endpoints complies with your privacy policy.",
                        tele.len(),
                        tele.join("; ")
                    ),
                    Medium,
                    "privacy",
                )
                .masvs("MASVS-PRIVACY")
                .meta("endpoints", json!(tele)),
            );
        }

        // iOS privacy manifest
        if app_type == AppType::Ipa {
            let privacy_files: Vec<_> = walk_all_files(extracted)
                .into_iter()
                .filter(|p| {
                    let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
                    n == "PrivacyInfo.xcprivacy" || n == ".xcprivacy" || n.ends_with(".xcprivacy")
                })
                .collect();
            if privacy_files.is_empty() {
                findings.push(
                    Finding::new(
                        "PRIV_NO_PRIVACY_MANIFEST",
                        "Missing iOS Privacy Manifest",
                        "No PrivacyInfo.xcprivacy file found. Since iOS 17, apps must declare privacy-impacting APIs and data collection in a privacy manifest.",
                        High,
                        "privacy",
                    )
                    .masvs("MASVS-PRIVACY"),
                );
            } else {
                findings.push(Finding::new(
                    "PRIV_PRIVACY_MANIFEST",
                    "iOS Privacy Manifest found",
                    format!(
                        "PrivacyInfo.xcprivacy found at: {}.",
                        rel(&privacy_files[0], extracted)
                    ),
                    Info,
                    "privacy",
                ));
            }
        }

        // Android data safety
        if matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk) {
            let mut all_xml = String::new();
            for fpath in walk_all_files(extracted) {
                if fpath.extension().and_then(|e| e.to_str()) == Some("xml") {
                    if std::fs::metadata(&fpath).map(|m| m.len()).unwrap_or(u64::MAX) < 1_000_000 {
                        if let Some(c) = read_text(&fpath) {
                            all_xml.push_str(&c);
                        }
                    }
                }
            }
            if rx_flags(
                r#"com\.google\.android\.play\.core\.integrity|data.safety|dataSafety"#,
                true,
                false,
                false,
            )
            .is_match(&all_xml)
            .unwrap_or(false)
            {
                findings.push(Finding::new(
                    "PRIV_DATA_SAFETY",
                    "Play Store Data Safety references found",
                    "References to Google Play Data Safety or integrity APIs detected. Verify data safety declarations match actual data collection practices.",
                    Info,
                    "privacy",
                ));
            }
        }

        findings
    }
}

fn detect_trackers(file_paths: &[String]) -> Vec<Finding> {
    // tracker name -> first matched path, preserving signature order.
    let mut found: Vec<(String, String)> = Vec::new();
    let mut found_names: BTreeSet<String> = BTreeSet::new();

    for (pattern, name) in TRACKER_SIGNATURES {
        if found_names.contains(*name) {
            continue;
        }
        for fpath in file_paths {
            let normalized = fpath.replace('\\', "/");
            if normalized.contains(pattern) {
                found.push((name.to_string(), normalized));
                found_names.insert(name.to_string());
                break;
            }
        }
    }

    if found.is_empty() {
        return vec![Finding::new(
            "PRIV_NO_TRACKERS",
            "No known trackers detected",
            "No known third-party trackers or analytics SDKs were found in the app.",
            Info,
            "privacy",
        )];
    }

    let names: Vec<String> = found.iter().map(|(n, _)| n.clone()).collect();
    let has = |name: &str, keys: &[&str]| {
        let l = name.to_lowercase();
        keys.iter().any(|k| l.contains(k))
    };
    let analytics: Vec<&String> = names
        .iter()
        .filter(|n| has(n, &["analytics", "measurement", "mixpanel", "amplitude", "segment", "heap", "countly", "flurry"]))
        .collect();
    let ads: Vec<&String> = names
        .iter()
        .filter(|n| has(n, &["ad", "admob", "audience", "applovin", "unity ads", "vungle", "ironsource", "inmobi", "chartboost"]))
        .collect();
    let attribution: Vec<&String> = names
        .iter()
        .filter(|n| has(n, &["adjust", "appsflyer", "branch", "kochava", "singular", "tenjin"]))
        .collect();
    let crash: Vec<&String> = names
        .iter()
        .filter(|n| has(n, &["crash", "bugsnag", "sentry", "instabug", "new relic"]))
        .collect();
    let push: Vec<&String> = names
        .iter()
        .filter(|n| has(n, &["onesignal", "braze", "airship", "batch", "clevertap", "moengage", "pushwoosh", "leanplum"]))
        .collect();

    let sorted_names: Vec<String> = found_names.iter().cloned().collect();

    vec![Finding::new(
        "PRIV_TRACKERS",
        format!("Third-party trackers detected ({})", found.len()),
        format!(
            "Found {} tracker/analytics SDK(s): {}.",
            found.len(),
            sorted_names.join(", ")
        ),
        Medium,
        "privacy",
    )
    .masvs("MASVS-PRIVACY")
    .meta("trackers", json!(sorted_names))
    .meta("count", json!(found.len()))
    .meta("analytics", json!(analytics))
    .meta("advertising", json!(ads))
    .meta("attribution", json!(attribution))
    .meta("crash_reporting", json!(crash))
    .meta("push_engagement", json!(push))]
}
