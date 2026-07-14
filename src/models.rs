//! Data models for analysis results.

use serde_json::{json, Map, Value};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    // Ordered so that CRITICAL is the "max". Ord derives from declaration order,
    // so keep the most severe last to make `max()` return the most severe.
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn value(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    /// ANSI-ish color name (kept as reference to the original Rich palette).
    #[allow(dead_code)]
    pub fn color(self) -> &'static str {
        match self {
            Severity::Critical => "bright_red",
            Severity::High => "red",
            Severity::Medium => "yellow",
            Severity::Low => "blue",
            Severity::Info => "dim",
        }
    }

    /// Raw ANSI SGR code used by the terminal output.
    pub fn ansi(self) -> &'static str {
        match self {
            Severity::Critical => "91",  // bright red
            Severity::High => "31",      // red
            Severity::Medium => "33",    // yellow
            Severity::Low => "34",       // blue
            Severity::Info => "2",       // dim
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Severity::Critical => "[!]",
            Severity::High => "[H]",
            Severity::Medium => "[M]",
            Severity::Low => "[L]",
            Severity::Info => "[i]",
        }
    }

    pub const ALL: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    /// Faithful reproduction of the Python `max(severities)` behaviour: the
    /// original `Severity(str, Enum)` compares by its lowercase value string,
    /// so `max` returns the lexicographically-greatest value (info < low <
    /// medium, etc.), NOT the most severe. Analyzers that aggregate a category
    /// severity rely on this quirk, so we keep it.
    pub fn py_max(sevs: &[Severity]) -> Option<Severity> {
        sevs.iter().copied().max_by(|a, b| a.value().cmp(b.value()))
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.value())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppType {
    Apk,
    Aab,
    Xapk,
    Ipa,
}

impl AppType {
    pub fn value(self) -> &'static str {
        match self {
            AppType::Apk => "apk",
            AppType::Aab => "aab",
            AppType::Xapk => "xapk",
            AppType::Ipa => "ipa",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub category: String,
    pub file_path: Option<String>,
    pub line: Option<u64>,
    pub cwe: Option<String>,
    pub masvs: Option<String>,
    /// MITRE ATT&CK for Mobile technique ID (e.g. `T1638`, `T1406.002`).
    /// Auto-populated from the finding id via [`default_mitre`] and overridable
    /// with [`Finding::mitre`], so SOCs can pivot findings into ATT&CK.
    pub mitre: Option<String>,
    pub metadata: Map<String, Value>,
}

/// Default MITRE ATT&CK for Mobile technique for a finding id.
///
/// Kept as one auditable table rather than sprinkled across analyzers. Only
/// findings whose described capability maps to a genuine adversary technique
/// are tagged — control weaknesses with no clean ATT&CK equivalent (weak
/// crypto, cert config, debuggable flags) intentionally return `None`. IDs are
/// from ATT&CK for Mobile (verified against attack.mitre.org).
pub fn default_mitre(id: &str) -> Option<&'static str> {
    let technique = match id {
        // Network interception → Adversary-in-the-Middle. Cleartext traffic,
        // trusting user/custom CAs, and absent/bypassed pinning all enable MitM.
        "NSC_CLEARTEXT_GLOBAL"
        | "NSC_CLEARTEXT_DOMAIN"
        | "NSC_TRUST_USER_CERTS"
        | "NSC_DEBUG_USER_CERTS"
        | "NSC_DEBUG_OVERRIDES"
        | "NSC_NO_PINNING"
        | "NET_PINNING_BYPASS"
        | "SAST_SSL_INSECURE"
        | "SAST_WEBVIEW_SSL_BYPASS"
        | "SAST_SELF_SIGNED_CERT"
        // A device-wide HTTP proxy is the on-device AiTM interception point.
        | "DEV_HTTP_PROXY" => "T1638",

        // A notification listener reads every notification → Access Notifications.
        "DEV_NOTIF_LISTENER" => "T1517",

        // Anti-analysis → Obfuscated Files or Information (packing is .002).
        "ADV_PACKER_DETECTED" => "T1406.002",
        "ADV_STRING_ENCRYPTION" | "ADV_OBFUSCATION_SCORE" | "SAST_DEXGUARD" => "T1406",

        // Insecure at-rest exposure → Access Stored Application Data.
        "SAST_WORLD_READABLE" | "SAST_SHARED_PREFS_INSECURE" | "SAST_EXTERNAL_STORAGE" => "T1409",

        // Collection — data/sensor capture capabilities.
        "API_GPS_LOCATION" | "PERM_LOCATION" => "T1430", // Location Tracking
        "API_MICROPHONE" => "T1429",                     // Audio Capture
        "API_CAMERA" => "T1512",                         // Video Capture
        "API_SCREEN_CAPTURE" => "T1513",                 // Screen Capture
        "API_CLIPBOARD" | "SAST_CLIPBOARD" => "T1414",   // Clipboard Data
        "API_CONTACTS" | "PERM_CONTACTS_ACCOUNTS" => "T1636.003", // Protected User Data: Contact List
        "API_SMS_SEND" => "T1582",                       // SMS Control

        // Discovery — device/network reconnaissance.
        "API_INSTALLED_APPS" => "T1418", // Software Discovery
        "API_WIFI_INFO" | "API_NETWORK_INTERFACE" => "T1422", // System Network Configuration Discovery
        // Device profiling by trackers/telemetry → System Information Discovery.
        "PRIV_TRACKERS" | "PRIV_FINGERPRINTING" | "PRIV_TELEMETRY" => "T1426",

        _ => return None,
    };
    Some(technique)
}

impl Finding {
    /// Builder-style constructor mirroring the Python dataclass defaults.
    pub fn new(
        id: &str,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        category: &str,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            title: title.into(),
            description: description.into(),
            severity,
            category: category.to_string(),
            file_path: None,
            line: None,
            cwe: None,
            masvs: None,
            mitre: default_mitre(id).map(str::to_string),
            metadata: Map::new(),
        }
    }

    pub fn file_path(mut self, p: impl Into<String>) -> Self {
        self.file_path = Some(p.into());
        self
    }
    pub fn line(mut self, l: u64) -> Self {
        self.line = Some(l);
        self
    }
    pub fn cwe(mut self, c: &str) -> Self {
        self.cwe = Some(c.to_string());
        self
    }
    pub fn masvs(mut self, m: &str) -> Self {
        self.masvs = Some(m.to_string());
        self
    }
    /// Override the MITRE ATT&CK for Mobile technique (defaults from the id).
    #[allow(dead_code)]
    pub fn mitre(mut self, m: &str) -> Self {
        self.mitre = Some(m.to_string());
        self
    }
    pub fn meta(mut self, key: &str, value: Value) -> Self {
        self.metadata.insert(key.to_string(), value);
        self
    }

    pub fn to_json(&self) -> Value {
        let mut d = Map::new();
        d.insert("id".into(), json!(self.id));
        d.insert("title".into(), json!(self.title));
        d.insert("description".into(), json!(self.description));
        d.insert("severity".into(), json!(self.severity.value()));
        d.insert("category".into(), json!(self.category));
        if let Some(fp) = &self.file_path {
            d.insert("file_path".into(), json!(fp));
        }
        if let Some(l) = self.line {
            d.insert("line".into(), json!(l));
        }
        if let Some(c) = &self.cwe {
            d.insert("cwe".into(), json!(c));
        }
        if let Some(m) = &self.masvs {
            d.insert("masvs".into(), json!(m));
        }
        if let Some(m) = &self.mitre {
            d.insert("mitre".into(), json!(m));
        }
        if !self.metadata.is_empty() {
            d.insert("metadata".into(), Value::Object(self.metadata.clone()));
        }
        Value::Object(d)
    }
}

pub struct ScanResult {
    pub file_path: String,
    pub file_hash: String,
    pub app_type: AppType,
    pub app_info: Map<String, Value>,
    pub findings: Vec<Finding>,
    pub scan_duration: f64,
}

impl ScanResult {
    pub fn summary(&self) -> Map<String, Value> {
        severity_counts(&self.findings)
    }

    /// Weighted security score 0-100 (100 = no issues).
    pub fn security_score(&self) -> i64 {
        security_score(&self.findings)
    }

    pub fn to_json(&self) -> Value {
        let mut d = Map::new();
        d.insert("schema_version".into(), json!(1));
        d.insert("file".into(), json!(self.file_path));
        d.insert("hash_sha256".into(), json!(self.file_hash));
        d.insert("app_type".into(), json!(self.app_type.value()));
        d.insert("app_info".into(), Value::Object(self.app_info.clone()));
        d.insert("security_score".into(), json!(self.security_score()));
        d.insert("summary".into(), Value::Object(self.summary()));
        d.insert(
            "scan_duration_seconds".into(),
            json!(round2(self.scan_duration)),
        );
        d.insert(
            "findings".into(),
            Value::Array(self.findings.iter().map(|f| f.to_json()).collect()),
        );
        Value::Object(d)
    }
}

/// Weighted security score 0-100 (100 = no issues) for any finding set.
///
/// Same weighting the Python reference uses for a package scan, reused for the
/// on-device posture report so both surfaces score consistently.
pub fn security_score(findings: &[Finding]) -> i64 {
    let count = |sev: Severity| findings.iter().filter(|f| f.severity == sev).count() as f64;
    let c = count(Severity::Critical);
    let h = count(Severity::High);
    let m = count(Severity::Medium);
    let l = count(Severity::Low);
    let penalty = (c * 15.0).min(60.0)
        + (h * 5.0).min(30.0)
        + (m * 1.0).min(15.0)
        + (l * 0.5).min(5.0);
    let score = 100.0 - penalty;
    // Python round() uses banker's rounding, but penalties here are always
    // integers or x.5 sums; round half to even to stay faithful.
    round_half_even(score).max(0) as i64
}

/// Severity histogram (`critical`,`high`,… + `total`) for a finding set.
pub fn severity_counts(findings: &[Finding]) -> Map<String, Value> {
    let mut counts = Map::new();
    for s in Severity::ALL {
        counts.insert(s.value().to_string(), json!(0u64));
    }
    for f in findings {
        let key = f.severity.value();
        let cur = counts.get(key).and_then(|v| v.as_u64()).unwrap_or(0);
        counts.insert(key.to_string(), json!(cur + 1));
    }
    counts.insert("total".into(), json!(findings.len() as u64));
    counts
}

fn round_half_even(x: f64) -> i64 {
    let floor = x.floor();
    let diff = x - floor;
    if (diff - 0.5).abs() < 1e-9 {
        let f = floor as i64;
        if f % 2 == 0 {
            f
        } else {
            f + 1
        }
    } else {
        x.round() as i64
    }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mitre_auto_populates_from_id() {
        // A finding whose id maps to a verified ATT&CK Mobile technique.
        let f = Finding::new("API_GPS_LOCATION", "GPS", "desc", Severity::High, "api");
        assert_eq!(f.mitre.as_deref(), Some("T1430"));
        // Serialization surfaces it next to cwe/masvs.
        assert_eq!(f.to_json().get("mitre").and_then(|v| v.as_str()), Some("T1430"));
    }

    #[test]
    fn mitre_absent_when_id_unmapped() {
        // Control-weakness findings with no clean adversary technique stay null.
        let f = Finding::new("SAST_WEAK_HASH", "MD5", "desc", Severity::High, "sast");
        assert!(f.mitre.is_none());
        assert!(f.to_json().get("mitre").is_none());
    }

    #[test]
    fn mitre_builder_overrides_default() {
        let f = Finding::new("PRIV_TRACKERS", "t", "d", Severity::Medium, "privacy").mitre("T9999");
        assert_eq!(f.mitre.as_deref(), Some("T9999"));
    }

    #[test]
    fn mitre_technique_ids_are_well_formed() {
        // Every mapped id must yield a syntactically valid technique id.
        for id in [
            "NSC_CLEARTEXT_GLOBAL",
            "ADV_PACKER_DETECTED",
            "SAST_CLIPBOARD",
            "API_CONTACTS",
            "API_INSTALLED_APPS",
            "PRIV_FINGERPRINTING",
        ] {
            let t = default_mitre(id).expect("mapped id must resolve");
            assert!(t.starts_with('T'), "{id} -> {t}");
            assert!(t[1..].chars().all(|c| c.is_ascii_digit() || c == '.'));
        }
    }
}
