//! Data flow / taint analysis — source-to-sink patterns in the same file.

use super::Analyzer;
use crate::models::{AppType, Finding, Severity};
use crate::util::{find_files_by_ext, line_of, read_text, rel, rx};
use fancy_regex::Regex;
use serde_json::json;
use std::collections::HashSet;
use std::path::Path;

use Severity::*;

struct Taint {
    id: &'static str,
    title: &'static str,
    desc: &'static str,
    sev: Severity,
    src: &'static str,
    sink: &'static str,
    cwe: &'static str,
}

fn taint_rules() -> Vec<Taint> {
    vec![
        Taint { id: "TAINT_SQL_INJECTION", title: "SQL injection via user input", desc: "User-controlled input flows into a raw SQL query without parameterization. Use parameterized queries or prepared statements.", sev: High, src: r#"(getIntent\(\)|getStringExtra|getQueryParameter|EditText.*getText|getInput|request\.getParameter|Bundle.*getString)"#, sink: r#"\.(rawQuery|execSQL)\s*\("#, cwe: "CWE-89" },
        Taint { id: "TAINT_XSS_WEBVIEW", title: "XSS in WebView via user input", desc: "User-controlled input flows into WebView content loading (loadUrl, loadData, evaluateJavascript). Sanitize input before rendering in WebViews.", sev: High, src: r#"(getIntent\(\)|getStringExtra|getQueryParameter|EditText.*getText|getInput|Uri\.parse|getUrl)"#, sink: r#"\.(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript)\s*\("#, cwe: "CWE-79" },
        Taint { id: "TAINT_PATH_TRAVERSAL", title: "Path traversal via user input", desc: "User-controlled input flows into file path construction. An attacker could use ../ sequences to access arbitrary files.", sev: High, src: r#"(getIntent\(\)|getStringExtra|getQueryParameter|EditText.*getText|getInput|Uri\.getPath|getLastPathSegment)"#, sink: r#"(new\s+File\s*\(|new\s+FileInputStream\s*\(|new\s+FileOutputStream\s*\(|openFileInput\s*\(|openFileOutput\s*\()"#, cwe: "CWE-22" },
        Taint { id: "TAINT_INTENT_REDIRECT", title: "Intent redirection", desc: "The app receives an Intent and uses it to start another component. An attacker can craft a malicious Intent to redirect to internal components.", sev: High, src: r#"(getIntent\(\)|getParcelableExtra.*Intent|intent\s*=\s*getIntent)"#, sink: r#"(startActivity\s*\(|startService\s*\(|sendBroadcast\s*\(|startActivityForResult\s*\()"#, cwe: "CWE-940" },
        Taint { id: "TAINT_PROVIDER_TRAVERSAL", title: "ContentProvider path traversal", desc: "ContentProvider receives a URI from a client and uses it for file access without validation. Validate and sanitize URI paths in openFile/query/insert/update/delete.", sev: High, src: r#"(openFile\s*\(|query\s*\(|insert\s*\(|update\s*\(|delete\s*\(.*Uri)"#, sink: r#"(new\s+File\s*\(.*getPath|new\s+File\s*\(.*getLastPathSegment|ParcelFileDescriptor\.open)"#, cwe: "CWE-22" },
        Taint { id: "TAINT_LOG_SENSITIVE", title: "Sensitive data logged", desc: "User input or sensitive data flows into log statements. Logs are accessible on rooted devices and via ADB.", sev: Medium, src: r#"(getPassword|getToken|getSecret|getApiKey|password|token|secret|creditCard|ssn|getStringExtra)"#, sink: r#"(Log\.(d|v|i|w|e)\s*\(|System\.out\.print|println\s*\(|logger\.(info|debug|warn|error)\s*\()"#, cwe: "CWE-532" },
    ]
}

pub struct DataFlowAnalyzer;

impl Analyzer for DataFlowAnalyzer {
    fn name(&self) -> &'static str {
        "Data Flow / Taint Analysis"
    }
    fn category(&self) -> &'static str {
        "dataflow"
    }
    fn can_analyze(&self, app_type: AppType) -> bool {
        matches!(app_type, AppType::Apk | AppType::Aab | AppType::Xapk)
    }

    fn analyze(&self, extracted: &Path, _app_type: AppType, _original: &Path) -> Vec<Finding> {
        let files = find_files_by_ext(extracted, &["java", "kt", "smali"]);
        if files.is_empty() {
            return vec![];
        }

        let compiled: Vec<(Taint, Regex, Regex)> = taint_rules()
            .into_iter()
            .map(|t| {
                let s = rx(t.src);
                let k = rx(t.sink);
                (t, s, k)
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

            for (rule, src_re, sink_re) in &compiled {
                let key = (rule.id.to_string(), rel_path.clone());
                if seen.contains(&key) {
                    continue;
                }
                let src_m = match src_re.find(&content) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };
                let sink_m = match sink_re.find(&content) {
                    Ok(Some(m)) => m,
                    _ => continue,
                };
                let src_line = line_of(&content, src_m.start()) as i64;
                let sink_line = line_of(&content, sink_m.start()) as i64;

                if sink_line < src_line - 5 {
                    continue;
                }
                if sink_line - src_line > 50 {
                    continue;
                }

                seen.insert(key);
                findings.push(
                    Finding::new(
                        rule.id,
                        rule.title,
                        format!(
                            "{} Source at line {}, sink at line {} in {}.",
                            rule.desc, src_line, sink_line, rel_path
                        ),
                        rule.sev,
                        "dataflow",
                    )
                    .file_path(rel_path.clone())
                    .line(sink_line as u64)
                    .cwe(rule.cwe)
                    .masvs("MASVS-CODE")
                    .meta("source_line", json!(src_line))
                    .meta("sink_line", json!(sink_line)),
                );
            }
        }

        findings
    }
}
