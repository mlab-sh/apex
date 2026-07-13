//! Privacy & compliance analyzer — trackers, fingerprinting, GDPR/CCPA mapping.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{read_text, rel, rx_flags, walk_all_files};
use serde_json::json;
use std::collections::BTreeSet;
use std::fmt::Write;
use std::path::Path;

use Severity::*;

/// Tracker classification, aligned with the Exodus Privacy taxonomy
/// (<https://reports.exodus-privacy.eu.org/info/trackers/>). The three
/// "high-risk" categories drive cross-app tracking / device identity /
/// on-screen behaviour capture, which is where the GDPR/CCPA exposure sits:
///   - `Identification`: cross-app attribution SDKs (device graph / probabilistic ID)
///   - `Advertising`: ad networks (RTB, audience profiling)
///   - `Profiling`: session-replay / behaviour recording
const CAT_ANALYTICS: &str = "analytics";
const CAT_ADVERTISING: &str = "advertising";
const CAT_IDENTIFICATION: &str = "identification";
const CAT_PROFILING: &str = "profiling";
const CAT_CRASH: &str = "crash_reporting";
const CAT_PUSH: &str = "push_engagement";

/// `(package-path signature, display name, Exodus-aligned category)`.
const TRACKER_SIGNATURES: &[(&str, &str, &str)] = &[
    ("com/google/firebase/analytics", "Google Firebase Analytics", CAT_ANALYTICS),
    ("com/google/android/gms/analytics", "Google Analytics", CAT_ANALYTICS),
    ("com/google/android/gms/measurement", "Google Analytics (Measurement)", CAT_ANALYTICS),
    ("com/facebook/appevents", "Facebook Analytics", CAT_ANALYTICS),
    ("com/flurry/android", "Flurry (Yahoo)", CAT_ADVERTISING),
    ("com/mixpanel/android", "Mixpanel", CAT_ANALYTICS),
    ("com/amplitude/api", "Amplitude", CAT_ANALYTICS),
    ("com/segment/analytics", "Segment", CAT_ANALYTICS),
    ("com/heapanalytics", "Heap Analytics", CAT_ANALYTICS),
    ("com/countly", "Countly", CAT_ANALYTICS),
    ("ly/count/android", "Countly", CAT_ANALYTICS),
    ("com/adjust/sdk", "Adjust", CAT_IDENTIFICATION),
    ("com/appsflyer", "AppsFlyer", CAT_IDENTIFICATION),
    ("io/branch/referral", "Branch.io", CAT_IDENTIFICATION),
    ("com/kochava", "Kochava", CAT_IDENTIFICATION),
    ("com/singular/sdk", "Singular", CAT_IDENTIFICATION),
    ("com/tenjin", "Tenjin", CAT_IDENTIFICATION),
    ("com/crashlytics", "Crashlytics (Firebase)", CAT_CRASH),
    ("com/bugsnag", "Bugsnag", CAT_CRASH),
    ("io/sentry/android", "Sentry", CAT_CRASH),
    ("com/instabug", "Instabug", CAT_CRASH),
    ("com/newrelic/agent", "New Relic", CAT_ANALYTICS),
    ("com/google/android/gms/ads", "Google AdMob", CAT_ADVERTISING),
    ("com/facebook/ads", "Facebook Audience Network", CAT_ADVERTISING),
    ("com/mopub", "MoPub (Twitter)", CAT_ADVERTISING),
    ("com/applovin", "AppLovin", CAT_ADVERTISING),
    ("com/unity3d/ads", "Unity Ads", CAT_ADVERTISING),
    ("com/vungle", "Vungle", CAT_ADVERTISING),
    ("com/ironsource", "ironSource", CAT_ADVERTISING),
    ("com/inmobi/ads", "InMobi", CAT_ADVERTISING),
    ("com/chartboost", "Chartboost", CAT_ADVERTISING),
    ("com/adcolony", "AdColony", CAT_ADVERTISING),
    ("com/onesignal", "OneSignal", CAT_PUSH),
    ("com/braze", "Braze", CAT_PUSH),
    ("com/urbanairship", "Airship (Urban Airship)", CAT_PUSH),
    ("com/batch/android", "Batch", CAT_PUSH),
    ("com/clevertap", "CleverTap", CAT_PUSH),
    ("com/moengage", "MoEngage", CAT_PUSH),
    ("com/pushwoosh", "Pushwoosh", CAT_PUSH),
    ("com/leanplum", "Leanplum", CAT_PUSH),
    ("com/hotjar", "Hotjar", CAT_PROFILING),
    ("com/fullstory", "FullStory", CAT_PROFILING),
    ("com/smartlook", "Smartlook", CAT_PROFILING),
    ("io/uxcam", "UXCam", CAT_PROFILING),
    ("com/appdynamics", "AppDynamics", CAT_ANALYTICS),
    ("com/datadog", "Datadog", CAT_ANALYTICS),
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
    // tracker name -> (first matched path, Exodus-aligned category), preserving
    // signature order and deduping by display name.
    let mut found: Vec<(String, String, &'static str)> = Vec::new();
    let mut found_names: BTreeSet<String> = BTreeSet::new();

    for (pattern, name, category) in TRACKER_SIGNATURES {
        if found_names.contains(*name) {
            continue;
        }
        for fpath in file_paths {
            let normalized = fpath.replace('\\', "/");
            if normalized.contains(pattern) {
                found.push((name.to_string(), normalized, category));
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

    // Precise per-category grouping from the classification table (no more
    // fuzzy substring matching on the display name).
    let by_cat = |cat: &str| -> Vec<String> {
        found
            .iter()
            .filter(|(_, _, c)| *c == cat)
            .map(|(n, _, _)| n.clone())
            .collect()
    };
    let analytics = by_cat(CAT_ANALYTICS);
    let ads = by_cat(CAT_ADVERTISING);
    let attribution = by_cat(CAT_IDENTIFICATION);
    let profiling = by_cat(CAT_PROFILING);
    let crash = by_cat(CAT_CRASH);
    let push = by_cat(CAT_PUSH);

    // High-risk = the categories driving cross-app tracking / device identity /
    // behaviour capture — the ones that carry the real GDPR/CCPA exposure.
    let mut high_risk: Vec<String> = Vec::new();
    high_risk.extend(ads.iter().cloned());
    high_risk.extend(attribution.iter().cloned());
    high_risk.extend(profiling.iter().cloned());
    high_risk.sort();
    high_risk.dedup();

    // Session-replay / behaviour recording is the most intrusive class (it can
    // capture on-screen PII), so its presence escalates the finding.
    let severity = if !profiling.is_empty() { High } else { Medium };

    let sorted_names: Vec<String> = found_names.iter().cloned().collect();

    let mut description = format!(
        "Found {} tracker/analytics SDK(s): {}.",
        found.len(),
        sorted_names.join(", ")
    );
    if !high_risk.is_empty() {
        let _ = write!(
            description,
            " {} classified high-risk (advertising/identification/profiling): {}.",
            high_risk.len(),
            high_risk.join(", ")
        );
    }
    if !profiling.is_empty() {
        let _ = write!(
            description,
            " Includes session-replay/behaviour tracker(s) that can record on-screen activity: {}.",
            profiling.join(", ")
        );
    }

    let title = if high_risk.is_empty() {
        format!("Third-party trackers detected ({})", found.len())
    } else {
        format!(
            "Third-party trackers detected ({}, {} high-risk)",
            found.len(),
            high_risk.len()
        )
    };

    vec![Finding::new("PRIV_TRACKERS", title, description, severity, "privacy")
        .masvs("MASVS-PRIVACY")
        .meta("trackers", json!(sorted_names))
        .meta("count", json!(found.len()))
        .meta("analytics", json!(analytics))
        .meta("advertising", json!(ads))
        .meta("attribution", json!(attribution))
        .meta("profiling", json!(profiling))
        .meta("crash_reporting", json!(crash))
        .meta("push_engagement", json!(push))
        .meta("high_risk", json!(high_risk))]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker_finding(paths: &[&str]) -> Finding {
        let owned: Vec<String> = paths.iter().map(|s| s.to_string()).collect();
        detect_trackers(&owned).into_iter().next().unwrap()
    }

    fn meta_list<'a>(f: &'a Finding, key: &str) -> Vec<&'a str> {
        f.metadata
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn no_trackers_yields_info() {
        let f = tracker_finding(&["classes/com/example/App.smali"]);
        assert_eq!(f.id, "PRIV_NO_TRACKERS");
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn analytics_only_stays_medium_and_not_high_risk() {
        let f = tracker_finding(&["smali/com/mixpanel/android/Mixpanel.smali"]);
        assert_eq!(f.id, "PRIV_TRACKERS");
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(meta_list(&f, "analytics"), vec!["Mixpanel"]);
        assert!(meta_list(&f, "high_risk").is_empty());
    }

    #[test]
    fn ad_and_attribution_are_high_risk_but_not_escalated() {
        let f = tracker_finding(&[
            "smali/com/google/android/gms/ads/Ad.smali",
            "smali/com/appsflyer/AF.smali",
        ]);
        assert_eq!(f.severity, Severity::Medium);
        assert_eq!(meta_list(&f, "advertising"), vec!["Google AdMob"]);
        assert_eq!(meta_list(&f, "attribution"), vec!["AppsFlyer"]);
        let hr = meta_list(&f, "high_risk");
        assert!(hr.contains(&"Google AdMob") && hr.contains(&"AppsFlyer"));
    }

    #[test]
    fn session_replay_tracker_escalates_to_high() {
        let f = tracker_finding(&["smali/io/uxcam/UXCam.smali"]);
        assert_eq!(f.severity, Severity::High);
        assert_eq!(meta_list(&f, "profiling"), vec!["UXCam"]);
        assert!(meta_list(&f, "high_risk").contains(&"UXCam"));
    }
}
