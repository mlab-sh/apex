//! Firebase & Cloud backend analyzer.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{read_text, rx, rx_flags, walk_all_files};
use serde_json::json;
use std::collections::BTreeSet;
use std::path::Path;

const CLOUD_BACKENDS: &[(&str, &str, &str)] = &[
    ("Supabase", r#"https?://[a-z0-9]+\.supabase\.co"#, "Supabase backend URL"),
    ("AWS Amplify", r#"(aws-exports|Amplify\.configure|awsmobile|amplify-meta)"#, "AWS Amplify configuration"),
    ("AWS AppSync", r#"(appsync|AppSyncClient|https?://[a-z0-9]+\.appsync-api\.[a-z0-9-]+\.amazonaws\.com)"#, "AWS AppSync GraphQL API"),
    ("AWS Cognito", r#"(cognito-idp\.[a-z0-9-]+\.amazonaws\.com|CognitoUserPool|us-east-1_[A-Za-z0-9]+)"#, "AWS Cognito user pool"),
    ("AWS S3", r#"(https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com|s3://[a-z0-9.-]+)"#, "AWS S3 bucket URL"),
    ("Google Cloud Storage", r#"https?://storage\.googleapis\.com/[a-z0-9._-]+"#, "Google Cloud Storage bucket"),
    ("Azure Blob", r#"https?://[a-z0-9]+\.blob\.core\.windows\.net"#, "Azure Blob Storage"),
    ("Parse Server", r#"(parse-server|ParseClient|https?://[a-z0-9.-]+/parse)"#, "Parse Server backend"),
    ("Hasura", r#"(hasura\.app|HasuraClient|x-hasura-admin-secret)"#, "Hasura GraphQL backend"),
    ("Appwrite", r#"(appwrite\.io|AppwriteClient|https?://[a-z0-9.-]+/v1/account)"#, "Appwrite backend"),
];

const TEXT_EXTS: &[&str] = &[
    "java", "kt", "xml", "json", "properties", "js", "html", "yaml", "yml", "plist", "smali",
];

pub struct FirebaseCloudAnalyzer;

impl FirebaseCloudAnalyzer {
    fn collect_content(&self, extracted: &Path) -> String {
        let mut parts: Vec<String> = Vec::new();
        for fpath in walk_all_files(extracted) {
            let meta = match std::fs::metadata(&fpath) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.len() > 5_000_000 {
                continue;
            }
            let ext = fpath
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_lowercase());
            if let Some(ext) = ext {
                if TEXT_EXTS.contains(&ext.as_str()) {
                    if let Some(c) = read_text(&fpath) {
                        parts.push(c);
                    }
                }
            }
        }
        parts.join("\n")
    }
}

impl Analyzer for FirebaseCloudAnalyzer {
    fn name(&self) -> &'static str {
        "Firebase & Cloud"
    }
    fn category(&self) -> &'static str {
        "cloud"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(
            app_type,
            AppType::Apk | AppType::Aab | AppType::Xapk | AppType::Ipa
        )
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let content = self.collect_content(extracted);
        let mut findings = Vec::new();

        // Firebase Realtime Database
        let db_re = rx(r#"https://([a-z0-9-]+)\.firebaseio\.com"#);
        let mut dbs: BTreeSet<String> = BTreeSet::new();
        for cap in db_re.captures_iter(&content).flatten() {
            if let Some(m) = cap.get(1) {
                dbs.insert(m.as_str().to_string());
            }
        }
        if !dbs.is_empty() {
            for db_name in &dbs {
                let url = format!("https://{db_name}.firebaseio.com");
                findings.push(
                    Finding::new(
                        "CLOUD_FIREBASE_DB",
                        format!("Firebase Realtime Database: {db_name}"),
                        format!(
                            "Firebase database URL found: {url}. Verify that security rules require authentication and are not set to public read/write."
                        ),
                        Severity::Medium,
                        "cloud",
                    )
                    .masvs("MASVS-STORAGE")
                    .meta("db_name", json!(db_name))
                    .meta("url", json!(url)),
                );
            }

            let read_re = rx(r#"["']\.read["']\s*:\s*["']?true"#);
            let write_re = rx(r#"["']\.write["']\s*:\s*["']?true"#);
            if read_re.is_match(&content).unwrap_or(false)
                || write_re.is_match(&content).unwrap_or(false)
            {
                findings.push(
                    Finding::new(
                        "CLOUD_FIREBASE_RULES_OPEN",
                        "Firebase rules may allow public access",
                        "Firebase security rules patterns found that suggest public read/write access ('.read': true / '.write': true). Verify rules in Firebase Console.",
                        Severity::High,
                        "cloud",
                    )
                    .cwe("CWE-284")
                    .masvs("MASVS-STORAGE"),
                );
            }
        }

        // Firebase Remote Config
        let rc_patterns = [
            "FirebaseRemoteConfig",
            "remoteConfig",
            "remote_config",
            "RemoteConfigSettings",
        ];
        let has_rc = rc_patterns
            .iter()
            .any(|p| rx(p).is_match(&content).unwrap_or(false));
        if has_rc {
            findings.push(
                Finding::new(
                    "CLOUD_FIREBASE_REMOTE_CONFIG",
                    "Firebase Remote Config detected",
                    "The app uses Firebase Remote Config for dynamic configuration. Ensure no sensitive values (API keys, secrets) are stored in Remote Config as it may be accessible.",
                    Severity::Info,
                    "cloud",
                )
                .masvs("MASVS-STORAGE"),
            );

            if rx(r#"(?:setDefaults|setDefaultsAsync)\s*\("#)
                .is_match(&content)
                .unwrap_or(false)
            {
                let secret_re = rx_flags(
                    r#"(?:api[_-]?key|secret|token|password|credential).*(?:setDefaults|remoteConfig)"#,
                    true,
                    true,
                    false,
                );
                if secret_re.is_match(&content).unwrap_or(false) {
                    findings.push(
                        Finding::new(
                            "CLOUD_FIREBASE_RC_SECRETS",
                            "Potential secrets in Firebase Remote Config defaults",
                            "Firebase Remote Config defaults may contain sensitive values (API keys, secrets, tokens). Remote Config defaults are embedded in the app binary and extractable.",
                            Severity::Medium,
                            "cloud",
                        )
                        .cwe("CWE-798")
                        .masvs("MASVS-STORAGE"),
                    );
                }
            }
        }

        // Other cloud backends
        for (name, pattern, desc) in CLOUD_BACKENDS {
            let re = rx_flags(pattern, true, false, false);
            if let Ok(Some(m)) = re.find(&content) {
                let preview: String = m.as_str().chars().take(80).collect();
                findings.push(
                    Finding::new(
                        "CLOUD_BACKEND_DETECTED",
                        format!("Cloud backend: {name}"),
                        format!(
                            "{desc} detected in the app. Verify that proper authentication and authorization are in place."
                        ),
                        Severity::Info,
                        "cloud",
                    )
                    .masvs("MASVS-NETWORK")
                    .meta("backend", json!(name))
                    .meta("preview", json!(preview)),
                );
            }
        }

        findings
    }
}
