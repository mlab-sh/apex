//! AndroidManifest.xml analyzer — security checks on the Android manifest.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, read_text, rel, rx};
use crate::xml::{self, Element};
use serde_json::json;
use std::path::Path;

use Severity::*;

// (tag, label) in declaration order.
const COMPONENT_TAGS: &[(&str, &str)] = &[
    ("activity", "Activity"),
    ("activity-alias", "Activity-Alias"),
    ("service", "Service"),
    ("receiver", "BroadcastReceiver"),
    ("provider", "ContentProvider"),
];

fn component_name(el: &Element) -> String {
    el.android("name").unwrap_or("(unknown)").to_string()
}

fn min_sdk_of(root: &Element) -> i64 {
    if let Some(us) = root.find("uses-sdk") {
        if let Some(v) = us.android("minSdkVersion") {
            if v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty() {
                return v.parse().unwrap_or(1);
            }
        }
    }
    1
}

/// Interpret an intent-filter priority string. axmldecoder emits the raw u32,
/// which for Android's signed priority must be reinterpreted as i32.
fn signed_priority(s: &str) -> Option<i64> {
    if let Ok(u) = s.parse::<u32>() {
        return Some(u as i32 as i64);
    }
    let stripped = s.trim_start_matches('-');
    if !stripped.is_empty() && stripped.chars().all(|c| c.is_ascii_digit()) {
        return s.parse::<i64>().ok();
    }
    None
}

/// Python-style list repr: ['a', 'b'].
fn py_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

fn truncate_names(names: &[String]) -> String {
    let head: Vec<String> = names.iter().take(5).cloned().collect();
    let mut s = head.join("; ");
    if names.len() > 5 {
        s.push_str(&format!(" and {} more", names.len() - 5));
    }
    s
}

pub struct AndroidManifestAnalyzer;

impl Analyzer for AndroidManifestAnalyzer {
    fn name(&self) -> &'static str {
        "Android Manifest"
    }
    fn category(&self) -> &'static str {
        "manifest"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let manifest = extracted.join("AndroidManifest.xml");
        if !manifest.exists() {
            return vec![Finding::new(
                "MANIFEST_MISSING",
                "AndroidManifest.xml missing",
                "AndroidManifest.xml was not found in the package.",
                Critical,
                "manifest",
            )];
        }
        let raw = match std::fs::read(&manifest) {
            Ok(r) => r,
            Err(_) => Vec::new(),
        };
        let root = match xml::parse_axml_or_xml(&raw) {
            Some(r) => r,
            None => {
                return vec![Finding::new(
                    "MANIFEST_PARSE_ERROR",
                    "Failed to parse AndroidManifest.xml",
                    "Could not parse the manifest (neither binary AXML nor standard XML).",
                    High,
                    "manifest",
                )]
            }
        };

        let mut f = Vec::new();
        f.extend(check_sdk_versions(&root));
        f.extend(check_debuggable(&root));
        f.extend(check_test_only(&root));
        f.extend(check_allow_backup(&root));
        f.extend(check_cleartext_traffic(&root));
        f.extend(check_direct_boot_aware(&root));
        f.extend(check_network_security_config(&root));
        f.extend(check_exported_components(&root));
        f.extend(check_custom_permissions(&root));
        f.extend(check_content_providers(&root));
        f.extend(check_browsable_activities(&root));
        f.extend(check_task_affinity(&root));
        f.extend(check_launch_mode(&root));
        f.extend(check_intent_priority(&root));
        f.extend(check_dialer_codes(&root));
        f.extend(check_sms_port(&root));
        f.extend(check_app_links(&root));
        f.extend(check_pending_intent(extracted));
        f.extend(check_webview_jsinterface(&root, extracted));
        f
    }
}

fn check_sdk_versions(root: &Element) -> Vec<Finding> {
    let mut findings = Vec::new();
    let uses_sdk = match root.find("uses-sdk") {
        Some(u) => u,
        None => {
            findings.push(Finding::new(
                "MANIFEST_NO_SDK",
                "Missing uses-sdk element",
                "The manifest does not declare uses-sdk. System defaults will be used.",
                Medium,
                "manifest",
            ));
            return findings;
        }
    };
    if let Some(v) = uses_sdk.android("minSdkVersion") {
        if v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty() {
            let sdk: i64 = v.parse().unwrap_or(0);
            if sdk < 26 {
                findings.push(
                    Finding::new(
                        "MANIFEST_MIN_SDK_LOW",
                        format!("minSdkVersion too low ({sdk})"),
                        format!("minSdkVersion={sdk} (< 26 / Android 8.0). The app supports Android versions lacking modern security protections."),
                        Medium,
                        "manifest",
                    )
                    .cwe("CWE-1104")
                    .masvs("MASVS-PLATFORM")
                    .meta("min_sdk", json!(sdk)),
                );
            }
        }
    }
    if let Some(v) = uses_sdk.android("targetSdkVersion") {
        if v.chars().all(|c| c.is_ascii_digit()) && !v.is_empty() {
            let sdk: i64 = v.parse().unwrap_or(0);
            if sdk < 29 {
                findings.push(
                    Finding::new(
                        "MANIFEST_TARGET_SDK_LOW",
                        format!("targetSdkVersion too low ({sdk})"),
                        format!("targetSdkVersion={sdk} (< 29 / Android 10). The app does not benefit from the latest security restrictions."),
                        Medium,
                        "manifest",
                    )
                    .cwe("CWE-1104")
                    .masvs("MASVS-PLATFORM")
                    .meta("target_sdk", json!(sdk)),
                );
            }
        }
    }
    findings
}

fn app<'a>(root: &'a Element) -> Option<&'a Element> {
    root.find("application")
}

fn check_debuggable(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        if a.android_bool("debuggable") == Some(true) {
            return vec![Finding::new(
                "MANIFEST_DEBUGGABLE",
                "Application is debuggable",
                "android:debuggable=true. The application can be debugged, exposing memory and sensitive data.",
                Critical,
                "manifest",
            )
            .cwe("CWE-489")
            .masvs("MASVS-RESILIENCE")];
        }
    }
    vec![]
}

fn check_test_only(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        if a.android_bool("testOnly") == Some(true) {
            return vec![Finding::new(
                "MANIFEST_TEST_ONLY",
                "Application in testOnly mode",
                "android:testOnly=true. The application is marked as test-only and should not be distributed.",
                High,
                "manifest",
            )
            .cwe("CWE-489")];
        }
    }
    vec![]
}

fn check_allow_backup(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        let val = a.android_bool("allowBackup");
        if val == Some(true) || val.is_none() {
            return vec![Finding::new(
                "MANIFEST_ALLOW_BACKUP",
                "Backup allowed",
                "android:allowBackup is true (or absent, defaults to true). App data can be extracted via adb backup.",
                Medium,
                "manifest",
            )
            .cwe("CWE-530")
            .masvs("MASVS-STORAGE")
            .meta("explicit", json!(val == Some(true)))];
        }
    }
    vec![]
}

fn check_cleartext_traffic(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        if a.android_bool("usesCleartextTraffic") == Some(true) {
            return vec![Finding::new(
                "MANIFEST_CLEARTEXT",
                "Cleartext traffic allowed",
                "android:usesCleartextTraffic=true. The application allows unencrypted HTTP traffic.",
                High,
                "manifest",
            )
            .cwe("CWE-319")
            .masvs("MASVS-NETWORK")];
        }
    }
    vec![]
}

fn check_direct_boot_aware(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        if a.android_bool("directBootAware") == Some(true) {
            return vec![Finding::new(
                "MANIFEST_DIRECT_BOOT",
                "Application is Direct Boot Aware",
                "android:directBootAware=true. The app can run before device unlock, with access to device-encrypted storage only.",
                Info,
                "manifest",
            )];
        }
    }
    vec![]
}

fn check_network_security_config(root: &Element) -> Vec<Finding> {
    if let Some(a) = app(root) {
        let nsc = a.android("networkSecurityConfig");
        if nsc.map(|s| s.is_empty()).unwrap_or(true) {
            return vec![Finding::new(
                "MANIFEST_NO_NSC",
                "No Network Security Config",
                "No networkSecurityConfig declared. The application uses the system default network configuration.",
                Info,
                "manifest",
            )
            .masvs("MASVS-NETWORK")];
        }
    }
    vec![]
}

struct Comp {
    name: String,
    tag: String,
    label: String,
}

fn check_exported_components(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut exported_no_perm: Vec<Comp> = Vec::new();
    let mut implicit_export: Vec<Comp> = Vec::new();

    for (tag, label) in COMPONENT_TAGS {
        for comp in a.iter(tag) {
            let name = component_name(comp);
            let exported = comp.android_bool("exported");
            let permission = comp.android("permission");
            let has_intent_filter = comp.find("intent-filter").is_some();

            if exported == Some(true) && permission.is_none() {
                exported_no_perm.push(Comp {
                    name: name.clone(),
                    tag: tag.to_string(),
                    label: label.to_string(),
                });
            }
            if has_intent_filter && exported.is_none() {
                implicit_export.push(Comp {
                    name: name.clone(),
                    tag: tag.to_string(),
                    label: label.to_string(),
                });
            }
        }
    }

    let mut findings = Vec::new();

    if !exported_no_perm.is_empty() {
        let dangerous: Vec<&Comp> = exported_no_perm
            .iter()
            .filter(|c| matches!(c.tag.as_str(), "service" | "receiver" | "provider"))
            .collect();
        let activities: Vec<&Comp> = exported_no_perm
            .iter()
            .filter(|c| matches!(c.tag.as_str(), "activity" | "activity-alias"))
            .collect();

        if !dangerous.is_empty() {
            let names: Vec<String> = dangerous.iter().map(|c| format!("{} '{}'", c.label, c.name)).collect();
            findings.push(
                Finding::new(
                    "MANIFEST_EXPORTED_NO_PERM",
                    format!("Exported services/receivers/providers without permission ({})", dangerous.len()),
                    format!(
                        "{} non-activity component(s) exported without permission: {}.",
                        dangerous.len(),
                        truncate_names(&names)
                    ),
                    High,
                    "manifest",
                )
                .cwe("CWE-926")
                .masvs("MASVS-PLATFORM")
                .meta("components", json!(dangerous.iter().map(|c| c.name.clone()).collect::<Vec<_>>())),
            );
        }

        if !activities.is_empty() {
            let names: Vec<String> = activities.iter().map(|c| c.name.clone()).collect();
            findings.push(
                Finding::new(
                    "MANIFEST_EXPORTED_ACTIVITY",
                    format!("Exported activities without permission ({})", activities.len()),
                    format!(
                        "{} activity(ies) exported without permission: {}. Verify these don't expose sensitive functionality.",
                        activities.len(),
                        truncate_names(&names)
                    ),
                    Medium,
                    "manifest",
                )
                .cwe("CWE-926")
                .masvs("MASVS-PLATFORM")
                .meta("components", json!(names)),
            );
        }
    }

    if !implicit_export.is_empty() {
        let names: Vec<String> = implicit_export.iter().map(|c| format!("{} '{}'", c.label, c.name)).collect();
        findings.push(
            Finding::new(
                "MANIFEST_IMPLICIT_EXPORT",
                format!("Implicitly exported components ({})", implicit_export.len()),
                format!(
                    "{} component(s) with intent-filter but no explicit exported=false: {}.",
                    implicit_export.len(),
                    truncate_names(&names)
                ),
                Medium,
                "manifest",
            )
            .cwe("CWE-926")
            .masvs("MASVS-PLATFORM")
            .meta("components", json!(implicit_export.iter().map(|c| c.name.clone()).collect::<Vec<_>>())),
        );
    }

    findings
}

fn check_custom_permissions(root: &Element) -> Vec<Finding> {
    let mut findings = Vec::new();
    for perm in root.iter("permission") {
        let perm_name = perm.android("name").unwrap_or("(unknown)").to_string();
        let level = perm.android("protectionLevel").unwrap_or("normal").to_string();
        let ll = level.to_lowercase();
        if ll == "normal" || ll == "dangerous" {
            findings.push(
                Finding::new(
                    "MANIFEST_WEAK_CUSTOM_PERM",
                    format!("Custom permission with protectionLevel '{level}'"),
                    format!("Permission '{perm_name}' declared with protectionLevel='{level}'. Normal/dangerous permissions can be obtained by any app."),
                    Medium,
                    "manifest",
                )
                .cwe("CWE-732")
                .masvs("MASVS-PLATFORM")
                .meta("permission", json!(perm_name))
                .meta("level", json!(level)),
            );
        }
    }
    findings
}

fn check_content_providers(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let min_sdk = min_sdk_of(root);
    let mut findings = Vec::new();

    for provider in a.iter("provider") {
        let prov_name = component_name(provider);
        let exported = provider.android_bool("exported");
        let permission = provider.android("permission");
        let read_perm = provider.android("readPermission");
        let write_perm = provider.android("writePermission");
        let has_perm = permission.is_some() || read_perm.is_some() || write_perm.is_some();

        if min_sdk < 17 && exported.is_none() && !has_perm {
            findings.push(
                Finding::new(
                    "MANIFEST_PROVIDER_DEFAULT_EXPORT",
                    "ContentProvider exported by default (pre-API 17)",
                    format!("ContentProvider '{prov_name}' is exported by default because minSdkVersion < 17 and exported is not set."),
                    High,
                    "manifest",
                )
                .cwe("CWE-926")
                .masvs("MASVS-PLATFORM")
                .meta("provider", json!(prov_name))
                .meta("min_sdk", json!(min_sdk)),
            );
        }

        if provider.android_bool("grantUriPermissions") == Some(true) {
            let has_path_perm = provider.find("grant-uri-permission").is_some();
            if !has_path_perm {
                findings.push(
                    Finding::new(
                        "MANIFEST_GRANT_URI_NO_PATH",
                        "grantUriPermissions without path restriction",
                        format!("ContentProvider '{prov_name}' has grantUriPermissions=true without a grant-uri-permission element to restrict accessible paths."),
                        Medium,
                        "manifest",
                    )
                    .cwe("CWE-284")
                    .masvs("MASVS-PLATFORM")
                    .meta("provider", json!(prov_name)),
                );
            } else {
                for grant in provider.iter("grant-uri-permission") {
                    let path = grant.android("path");
                    let path_prefix = grant.android("pathPrefix");
                    let path_pattern = grant.android("pathPattern");
                    if path_prefix == Some("/") || path_pattern == Some(".*") {
                        findings.push(
                            Finding::new(
                                "MANIFEST_GRANT_URI_WIDE",
                                "Overly broad grant-uri-permission",
                                format!("ContentProvider '{prov_name}' has a grant-uri-permission with an overly permissive path (pathPrefix='/' or pathPattern='.*')."),
                                Medium,
                                "manifest",
                            )
                            .cwe("CWE-284")
                            .masvs("MASVS-PLATFORM")
                            .meta("provider", json!(prov_name))
                            .meta("path", json!(path))
                            .meta("prefix", json!(path_prefix))
                            .meta("pattern", json!(path_pattern)),
                        );
                    }
                }
            }
        }
    }
    findings
}

fn activities_and_aliases<'a>(a: &'a Element) -> Vec<&'a Element> {
    let mut v = a.iter("activity");
    v.extend(a.iter("activity-alias"));
    v
}

fn check_browsable_activities(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for activity in activities_and_aliases(a) {
        let act_name = component_name(activity);
        for intent_filter in activity.iter("intent-filter") {
            let categories: Vec<String> = intent_filter
                .iter("category")
                .into_iter()
                .filter_map(|c| c.android("name").map(|s| s.to_string()))
                .collect();
            if !categories.iter().any(|c| c == "android.intent.category.BROWSABLE") {
                continue;
            }
            let schemes: Vec<String> = intent_filter
                .iter("data")
                .into_iter()
                .filter_map(|d| d.android("scheme").map(|s| s.to_string()))
                .collect();
            let hosts: Vec<String> = intent_filter
                .iter("data")
                .into_iter()
                .filter_map(|d| d.android("host").map(|s| s.to_string()))
                .collect();
            findings.push(
                Finding::new(
                    "MANIFEST_BROWSABLE",
                    format!("Browsable activity: {act_name}"),
                    format!(
                        "Activity '{act_name}' is browsable with schemes={}, hosts={}. It can be invoked from a browser.",
                        py_list(&schemes),
                        py_list(&hosts)
                    ),
                    Info,
                    "manifest",
                )
                .masvs("MASVS-PLATFORM")
                .meta("activity", json!(act_name))
                .meta("schemes", json!(schemes))
                .meta("hosts", json!(hosts)),
            );
        }
    }
    findings
}

fn check_task_affinity(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for activity in a.iter("activity") {
        let act_name = component_name(activity);
        if let Some(affinity) = activity.android("taskAffinity") {
            if !affinity.is_empty() {
                findings.push(
                    Finding::new(
                        "MANIFEST_TASK_AFFINITY",
                        format!("Custom task affinity: {act_name}"),
                        format!("Activity '{act_name}' has taskAffinity='{affinity}'. This can be exploited for task hijacking."),
                        Medium,
                        "manifest",
                    )
                    .cwe("CWE-1021")
                    .masvs("MASVS-PLATFORM")
                    .meta("activity", json!(act_name))
                    .meta("affinity", json!(affinity)),
                );
            }
        }
    }
    findings
}

fn check_launch_mode(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for activity in a.iter("activity") {
        let act_name = component_name(activity);
        let launch_mode = activity.android("launchMode");
        let affinity = activity.android("taskAffinity");

        if launch_mode == Some("singleTask") && affinity.is_none() {
            findings.push(
                Finding::new(
                    "MANIFEST_STRANDHOGG_1",
                    format!("StrandHogg 1.0: {act_name}"),
                    format!("Activity '{act_name}' uses launchMode=singleTask without explicit taskAffinity. Vulnerable to task hijacking (StrandHogg 1.0)."),
                    High,
                    "manifest",
                )
                .cwe("CWE-1021")
                .masvs("MASVS-PLATFORM")
                .meta("activity", json!(act_name))
                .meta("launch_mode", json!("singleTask")),
            );
        }

        if matches!(launch_mode, Some("singleTask") | Some("singleInstance")) {
            let lm = launch_mode.unwrap();
            findings.push(
                Finding::new(
                    "MANIFEST_STRANDHOGG_2",
                    format!("Potential StrandHogg 2.0: {act_name}"),
                    format!("Activity '{act_name}' uses launchMode={lm}. Combined with other factors, this can be exploited (StrandHogg 2.0)."),
                    Medium,
                    "manifest",
                )
                .cwe("CWE-1021")
                .masvs("MASVS-PLATFORM")
                .meta("activity", json!(act_name))
                .meta("launch_mode", json!(lm)),
            );
        }
    }
    findings
}

fn check_intent_priority(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for (tag, _label) in COMPONENT_TAGS {
        for comp in a.iter(tag) {
            let comp_name = component_name(comp);
            for intent_filter in comp.iter("intent-filter") {
                if let Some(priority_raw) = intent_filter.android("priority") {
                    // axmldecoder renders Dec integer attributes as unsigned u32;
                    // Android priority is a signed 32-bit value, so reinterpret.
                    if let Some(p) = signed_priority(priority_raw) {
                        let priority = p.to_string();
                        {
                            if p > 100 {
                                findings.push(
                                    Finding::new(
                                        "MANIFEST_HIGH_PRIORITY",
                                        format!("Intent priority > 100: {comp_name}"),
                                        format!("Component '{comp_name}' has an intent-filter with priority={priority}. High priority can intercept system intents."),
                                        Medium,
                                        "manifest",
                                    )
                                    .cwe("CWE-940")
                                    .masvs("MASVS-PLATFORM")
                                    .meta("component", json!(comp_name))
                                    .meta("priority", json!(p)),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
    findings
}

fn check_dialer_codes(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for tag in ["activity", "activity-alias"] {
        for activity in a.iter(tag) {
            let act_name = component_name(activity);
            for intent_filter in activity.iter("intent-filter") {
                for data in intent_filter.iter("data") {
                    let scheme = data.android("scheme").unwrap_or("");
                    let sl = scheme.to_lowercase();
                    if sl == "tel" || sl == "voicemail" || sl == "sip" {
                        findings.push(
                            Finding::new(
                                "MANIFEST_DIALER_CODE",
                                format!("Dialer code handler: {act_name}"),
                                format!("Activity '{act_name}' handles the '{scheme}' scheme. It can be invoked via dialer codes."),
                                Info,
                                "manifest",
                            )
                            .meta("activity", json!(act_name))
                            .meta("scheme", json!(scheme)),
                        );
                    }
                }
            }
        }
    }
    findings
}

fn check_sms_port(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for receiver in a.iter("receiver") {
        let recv_name = component_name(receiver);
        for intent_filter in receiver.iter("intent-filter") {
            for data in intent_filter.iter("data") {
                let port = data.android("port");
                let scheme = data.android("scheme").unwrap_or("");
                if let Some(port) = port {
                    if scheme.to_lowercase() == "sms" {
                        findings.push(
                            Finding::new(
                                "MANIFEST_SMS_PORT",
                                format!("SMS receiver with exposed port: {recv_name}"),
                                format!("BroadcastReceiver '{recv_name}' listens for SMS on port {port}. SMS on specific ports can be intercepted."),
                                Medium,
                                "manifest",
                            )
                            .cwe("CWE-927")
                            .masvs("MASVS-PLATFORM")
                            .meta("receiver", json!(recv_name))
                            .meta("port", json!(port)),
                        );
                    }
                }
            }
        }
    }
    findings
}

fn check_app_links(root: &Element) -> Vec<Finding> {
    let a = match app(root) {
        Some(a) => a,
        None => return vec![],
    };
    let mut findings = Vec::new();
    for activity in activities_and_aliases(a) {
        let act_name = component_name(activity);
        for intent_filter in activity.iter("intent-filter") {
            let auto_verify = intent_filter.android_bool("autoVerify");
            let categories: Vec<String> = intent_filter
                .iter("category")
                .into_iter()
                .filter_map(|c| c.android("name").map(|s| s.to_string()))
                .collect();
            if !categories.iter().any(|c| c == "android.intent.category.BROWSABLE") {
                continue;
            }
            let schemes: Vec<String> = intent_filter
                .iter("data")
                .into_iter()
                .filter_map(|d| d.android("scheme").map(|s| s.to_string()))
                .collect();
            let has_http = schemes.iter().any(|s| s == "http" || s == "https");
            if !has_http {
                continue;
            }
            if auto_verify != Some(true) {
                findings.push(
                    Finding::new(
                        "MANIFEST_NO_AUTO_VERIFY",
                        format!("App Link without autoVerify: {act_name}"),
                        format!("Activity '{act_name}' handles browsable http/https links without android:autoVerify=true. Without verification, any app can claim these URLs (no assetlinks.json validation)."),
                        Medium,
                        "manifest",
                    )
                    .cwe("CWE-940")
                    .masvs("MASVS-PLATFORM")
                    .meta("activity", json!(act_name))
                    .meta("schemes", json!(schemes)),
                );
            }
        }
    }
    findings
}

fn check_pending_intent(extracted: &Path) -> Vec<Finding> {
    let code_files = find_files_by_ext(extracted, &["java", "kt", "smali", "xml", "js"]);
    if code_files.is_empty() {
        return vec![];
    }
    let re_pending = rx(r#"PendingIntent\s*\.\s*(getActivity|getService|getBroadcast|getForegroundService)\s*\("#);
    let re_flag = rx(r#"FLAG_IMMUTABLE|FLAG_MUTABLE"#);
    let re_implicit = rx(r#"new\s+Intent\s*\(\s*\)"#);
    let re_setcomp = rx(r#"\.(setComponent|setClass|setPackage|setClassName)\s*\("#);

    let mut findings = Vec::new();
    for fpath in &code_files {
        let content = match read_text(fpath) {
            Some(c) => c,
            None => continue,
        };
        let lines: Vec<&str> = content.split('\n').collect();
        let n = lines.len();
        for (li, line) in lines.iter().enumerate() {
            let i = li + 1; // 1-indexed
            if re_pending.is_match(line).unwrap_or(false) {
                let start = i.saturating_sub(4);
                let end = (i + 3).min(n);
                let context = lines[start..end].join("\n");
                if !re_flag.is_match(&context).unwrap_or(false) {
                    let rel_path = rel(fpath, extracted);
                    findings.push(
                        Finding::new(
                            "MANIFEST_PENDING_NO_IMMUTABLE",
                            "PendingIntent without FLAG_IMMUTABLE",
                            "PendingIntent created without FLAG_IMMUTABLE or FLAG_MUTABLE. Since API 31, a mutability flag is required. Without FLAG_IMMUTABLE, the PendingIntent can be modified by a malicious app.",
                            High,
                            "manifest",
                        )
                        .file_path(rel_path)
                        .line(i as u64)
                        .cwe("CWE-927")
                        .masvs("MASVS-PLATFORM"),
                    );
                }
            }

            if re_implicit.is_match(line).unwrap_or(false) {
                let start = i.saturating_sub(4);
                let end = (i + 6).min(n);
                let context = lines[start..end].join("\n");
                if re_pending.is_match(&context).unwrap_or(false)
                    && !re_setcomp.is_match(&context).unwrap_or(false)
                {
                    let rel_path = rel(fpath, extracted);
                    findings.push(
                        Finding::new(
                            "MANIFEST_PENDING_IMPLICIT",
                            "PendingIntent with implicit Intent",
                            "PendingIntent created with an Intent without an explicit component (no setComponent/setClass/setPackage). An implicit Intent in a PendingIntent can be hijacked by a malicious app.",
                            High,
                            "manifest",
                        )
                        .file_path(rel_path)
                        .line(i as u64)
                        .cwe("CWE-927")
                        .masvs("MASVS-PLATFORM"),
                    );
                }
            }
        }
    }
    findings
}

fn check_webview_jsinterface(root: &Element, extracted: &Path) -> Vec<Finding> {
    let min_sdk = min_sdk_of(root);
    if min_sdk >= 17 {
        return vec![];
    }
    let code_files = find_files_by_ext(extracted, &["java", "kt", "smali", "xml", "js"]);
    let re = rx(r#"\.addJavascriptInterface\s*\("#);
    let mut findings = Vec::new();
    for fpath in &code_files {
        let content = match read_text(fpath) {
            Some(c) => c,
            None => continue,
        };
        for (li, line) in content.split('\n').enumerate() {
            if re.is_match(line).unwrap_or(false) {
                let rel_path = rel(fpath, extracted);
                findings.push(
                    Finding::new(
                        "MANIFEST_WEBVIEW_JSINTERFACE",
                        "addJavascriptInterface with minSdk < 17",
                        format!("addJavascriptInterface() used while minSdkVersion={min_sdk} (< 17). On pre-API 17 devices, this allows arbitrary Java code execution via JavaScript (CVE-2012-6636)."),
                        Critical,
                        "manifest",
                    )
                    .file_path(rel_path)
                    .line((li + 1) as u64)
                    .cwe("CWE-749")
                    .masvs("MASVS-PLATFORM"),
                );
            }
        }
    }
    findings
}
