//! STIX2 indicator loading and matching against an acquisition.
//!
//! Loads STIX 2.x bundles (Echap stalkerware-indicators, MVT/Amnesty feeds, …)
//! and matches their indicators against what an acquisition holds: package
//! names, APK file hashes, APK signing certificates, and domains / IPs / URLs
//! appearing anywhere in the collected text (dumpsys, logcat, bugreport…).
//!
//! Supported patterns (one or several `OR`-ed comparisons per indicator):
//! `app:id`, `app:cert.sha1|sha256`, `file:hashes.sha256|sha1|md5`,
//! `domain-name:value`, `ipv4-addr:value`, `ipv6-addr:value`, `url:value`.
//! Anything else is counted as unsupported and reported, never silently lost.

use fancy_regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

/// Normalized indicator kind.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Kind {
    Package,
    CertSha1,
    CertSha256,
    Sha256,
    Sha1,
    Md5,
    Domain,
    Ip,
    Url,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Package => "package",
            Kind::CertSha1 => "cert_sha1",
            Kind::CertSha256 => "cert_sha256",
            Kind::Sha256 => "sha256",
            Kind::Sha1 => "sha1",
            Kind::Md5 => "md5",
            Kind::Domain => "domain",
            Kind::Ip => "ip",
            Kind::Url => "url",
        }
    }

    fn from_stix(path: &str) -> Option<Kind> {
        let p = path.replace(['\'', '"'], "").to_ascii_lowercase();
        Some(match p.as_str() {
            "app:id" => Kind::Package,
            "app:cert.sha1" => Kind::CertSha1,
            "app:cert.sha256" => Kind::CertSha256,
            "file:hashes.sha256" | "file:hashes.sha-256" => Kind::Sha256,
            "file:hashes.sha1" | "file:hashes.sha-1" => Kind::Sha1,
            "file:hashes.md5" => Kind::Md5,
            "domain-name:value" => Kind::Domain,
            "ipv4-addr:value" | "ipv6-addr:value" => Kind::Ip,
            "url:value" => Kind::Url,
            _ => return None,
        })
    }

    /// Canonical form used for lookup (case only matters for package names).
    fn norm(self, v: &str) -> String {
        let v = v.trim();
        match self {
            Kind::Package => v.to_string(),
            Kind::CertSha1 | Kind::CertSha256 => v.replace(':', "").to_ascii_uppercase(),
            _ => v.trim_end_matches('.').to_ascii_lowercase(),
        }
    }
}

/// A set of indicators, each mapped to the malware/campaign name it indicates.
#[derive(Default)]
pub struct IocSet {
    map: HashMap<Kind, HashMap<String, String>>,
    /// Indicator count per source file, for the report.
    pub sources: Vec<(String, usize)>,
    /// Comparisons whose object path we don't support (e.g. `email-addr`).
    pub unsupported: usize,
}

/// One indicator matched in the acquisition.
#[derive(Clone, Debug, PartialEq)]
pub struct Hit {
    pub kind: Kind,
    pub value: String,
    pub malware: String,
    /// Where it was seen (relative file path, or file + package).
    pub source: String,
}

impl IocSet {
    pub fn is_empty(&self) -> bool {
        self.map.values().all(|m| m.is_empty())
    }

    pub fn insert(&mut self, kind: Kind, value: &str, malware: &str) {
        let v = kind.norm(value);
        if !v.is_empty() {
            self.map.entry(kind).or_default().entry(v).or_insert_with(|| malware.to_string());
        }
    }

    pub fn get(&self, kind: Kind, value: &str) -> Option<&String> {
        self.map.get(&kind)?.get(&kind.norm(value))
    }

    /// Load one STIX2 bundle (JSON) and merge its indicators.
    pub fn load_stix2(&mut self, path: &Path) -> Result<usize, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let n = self.load_stix2_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        self.sources.push((path.display().to_string(), n));
        Ok(n)
    }

    pub fn load_stix2_str(&mut self, text: &str) -> Result<usize, String> {
        let doc: Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON: {e}"))?;
        let objects = doc
            .get("objects")
            .and_then(|o| o.as_array())
            .ok_or("no STIX `objects` array")?;

        let name_of = |o: &Value| o.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
        let mut names: HashMap<&str, String> = HashMap::new(); // malware/campaign id → name
        let mut indicates: HashMap<&str, &str> = HashMap::new(); // indicator id → target id
        for o in objects {
            let t = o.get("type").and_then(|v| v.as_str()).unwrap_or("");
            match t {
                "malware" | "campaign" | "intrusion-set" | "threat-actor" | "tool" => {
                    if let Some(id) = o.get("id").and_then(|v| v.as_str()) {
                        names.insert(id, name_of(o));
                    }
                }
                "relationship" => {
                    if let (Some(s), Some(d)) = (o.get("source_ref").and_then(|v| v.as_str()), o.get("target_ref").and_then(|v| v.as_str())) {
                        indicates.insert(s, d);
                    }
                }
                _ => {}
            }
        }

        // `object:path = 'value'` comparisons inside a pattern (any number, OR-ed).
        let re = Regex::new(r"([a-z0-9-]+:[A-Za-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'").unwrap();
        let mut added = 0;
        for o in objects {
            if o.get("type").and_then(|v| v.as_str()) != Some("indicator") {
                continue;
            }
            let id = o.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let malware = indicates
                .get(id)
                .and_then(|t| names.get(t))
                .filter(|n| !n.is_empty())
                .cloned()
                .unwrap_or_else(|| {
                    let n = name_of(o);
                    if n.is_empty() { "unnamed indicator".into() } else { n }
                });
            let pattern = o.get("pattern").and_then(|v| v.as_str()).unwrap_or("");
            for cap in re.captures_iter(pattern).flatten() {
                let (path, val) = (&cap[1], cap[2].replace("\\'", "'"));
                match Kind::from_stix(path) {
                    Some(k) => {
                        self.insert(k, &val, &malware);
                        added += 1;
                    }
                    None => self.unsupported += 1,
                }
            }
        }
        Ok(added)
    }

    /// Domains / IPs / URLs present in free text. Subdomains match their
    /// listed parent (`api.evil.com` hits `evil.com`).
    pub fn scan_text(&self, text: &str, source: &str, hits: &mut Vec<Hit>) {
        let domains = self.map.get(&Kind::Domain);
        let ips = self.map.get(&Kind::Ip);
        if domains.is_some() || ips.is_some() {
            for tok in text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == ':')) {
                let tok = tok.trim_matches(|c| c == '.' || c == '-' || c == ':');
                if tok.len() < 4 || !tok.contains(['.', ':']) {
                    continue;
                }
                let low = tok.to_ascii_lowercase();
                // host:port → host (a bare IPv6 keeps its colons: tried first)
                let host = low.split(':').next().unwrap_or("");
                if let Some((ip, m)) = ips.and_then(|s| s.get_key_value(&low).or_else(|| s.get_key_value(host))) {
                    push_hit(hits, Kind::Ip, ip, m, source);
                    continue;
                }
                if let Some(d) = domains {
                    let mut cur = host;
                    while cur.contains('.') {
                        if let Some(m) = d.get(cur) {
                            push_hit(hits, Kind::Domain, cur, m, source);
                            break;
                        }
                        cur = cur.split_once('.').map(|x| x.1).unwrap_or("");
                    }
                }
            }
        }
        if let Some(urls) = self.map.get(&Kind::Url) {
            let low = text.to_ascii_lowercase();
            for (u, m) in urls {
                if low.contains(u.as_str()) {
                    push_hit(hits, Kind::Url, u, m, source);
                }
            }
        }
    }

    /// Match everything in an acquisition / extraction directory:
    /// package lists, every APK (file hashes + signing certs), and all text
    /// files (plus the text entries of zips such as `bugreport.zip`).
    pub fn scan_dir(&self, root: &Path, packages: &[String]) -> Vec<Hit> {
        use md5::Md5;
        use sha1::Sha1;
        use sha2::{Digest, Sha256};

        let mut hits = Vec::new();
        for p in packages {
            if let Some(m) = self.get(Kind::Package, p) {
                push_hit(&mut hits, Kind::Package, p, m, "installed packages");
            }
        }
        let want_hashes = [Kind::Sha256, Kind::Sha1, Kind::Md5].iter().any(|k| self.map.contains_key(k));
        let want_certs = self.map.contains_key(&Kind::CertSha1) || self.map.contains_key(&Kind::CertSha256);

        for e in walkdir::WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            if !e.file_type().is_file() {
                continue;
            }
            let path = e.path();
            let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().into_owned();
            let ext = path.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
            // Pulled media and message attachments: hash-set matching.
            if want_hashes && ext != "apk" && (rel.starts_with("storage") || rel.starts_with("comms")) {
                if let Some(hs) = file_hashes(path) {
                    for (k, h) in [Kind::Sha256, Kind::Sha1, Kind::Md5].into_iter().zip(hs) {
                        if let Some(m) = self.get(k, &h) {
                            push_hit(&mut hits, k, &h, m, &rel);
                        }
                    }
                }
                continue;
            }
            match ext.as_str() {
                "apk" => {
                    if want_hashes {
                        if let Ok(bytes) = std::fs::read(path) {
                            let hex = |d: &[u8]| d.iter().map(|b| format!("{b:02x}")).collect::<String>();
                            for (k, h) in [
                                (Kind::Sha256, hex(&Sha256::digest(&bytes))),
                                (Kind::Sha1, hex(&Sha1::digest(&bytes))),
                                (Kind::Md5, hex(&Md5::digest(&bytes))),
                            ] {
                                if let Some(m) = self.get(k, &h) {
                                    push_hit(&mut hits, k, &h, m, &rel);
                                }
                            }
                        }
                    }
                    if want_certs {
                        for c in crate::cert_util::apk_signer_sha1s(path) {
                            if let Some(m) = self.get(Kind::CertSha1, &c) {
                                push_hit(&mut hits, Kind::CertSha1, &c, m, &rel);
                            }
                        }
                    }
                }
                "zip" => {
                    let Ok(f) = std::fs::File::open(path) else { continue };
                    let Ok(mut z) = zip::ZipArchive::new(f) else { continue };
                    for i in 0..z.len() {
                        let Ok(mut ent) = z.by_index(i) else { continue };
                        let name = ent.name().to_string();
                        if !name.ends_with(".txt") || ent.size() > 512 * 1024 * 1024 {
                            continue;
                        }
                        let mut buf = Vec::new();
                        if std::io::Read::read_to_end(&mut ent, &mut buf).is_ok() {
                            self.scan_text(&String::from_utf8_lossy(&buf), &format!("{rel}!{name}"), &mut hits);
                        }
                    }
                }
                "txt" | "json" | "jsonl" | "log" | "csv" | "xml" => {
                    if let Ok(bytes) = std::fs::read(path) {
                        self.scan_text(&String::from_utf8_lossy(&bytes), &rel, &mut hits);
                    }
                }
                _ => {}
            }
        }
        hits
    }
}

/// Streaming SHA-256, SHA-1, MD5 of a file.
pub fn file_hashes(p: &Path) -> Option<[String; 3]> {
    use md5::Md5;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(p).ok()?;
    let (mut a, mut b, mut c) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let k = std::io::Read::read(&mut f, &mut buf).ok()?;
        if k == 0 {
            break;
        }
        a.update(&buf[..k]);
        b.update(&buf[..k]);
        c.update(&buf[..k]);
    }
    Some([format!("{:x}", a.finalize()), format!("{:x}", b.finalize()), format!("{:x}", c.finalize())])
}

fn push_hit(hits: &mut Vec<Hit>, kind: Kind, value: &str, malware: &str, source: &str) {
    let h = Hit { kind, value: value.to_string(), malware: malware.to_string(), source: source.to_string() };
    if !hits.contains(&h) {
        hits.push(h);
    }
}

/// Group hits by (kind, value) → (malware, sources) for reporting.
pub fn group(hits: &[Hit]) -> BTreeMap<(Kind, String), (String, Vec<String>)> {
    let mut g: BTreeMap<(Kind, String), (String, Vec<String>)> = BTreeMap::new();
    for h in hits {
        let e = g.entry((h.kind, h.value.clone())).or_insert_with(|| (h.malware.clone(), Vec::new()));
        e.1.push(h.source.clone());
    }
    g
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = r#"{"type":"bundle","objects":[
      {"type":"malware","id":"malware--1","name":"EvilSpy"},
      {"type":"indicator","id":"indicator--a","pattern":"[domain-name:value='evil.com']"},
      {"type":"indicator","id":"indicator--b","pattern":"[app:id='com.evil.spy']"},
      {"type":"indicator","id":"indicator--c","pattern":"[app:cert.sha1='aa:bb']"},
      {"type":"indicator","id":"indicator--d","name":"loose","pattern":"[ipv4-addr:value = '6.6.6.6'] OR [email-addr:value='x@y.z']"},
      {"type":"relationship","source_ref":"indicator--a","target_ref":"malware--1"},
      {"type":"relationship","source_ref":"indicator--b","target_ref":"malware--1"}
    ]}"#;

    #[test]
    fn loads_patterns_and_names() {
        let mut s = IocSet::default();
        assert_eq!(s.load_stix2_str(BUNDLE).unwrap(), 4);
        assert_eq!(s.unsupported, 1);
        assert_eq!(s.get(Kind::Package, "com.evil.spy").unwrap(), "EvilSpy");
        assert_eq!(s.get(Kind::CertSha1, "AABB").unwrap(), "unnamed indicator");
        assert_eq!(s.get(Kind::Ip, "6.6.6.6").unwrap(), "loose");
    }

    #[test]
    fn text_matches_subdomains_ips_not_lookalikes() {
        let mut s = IocSet::default();
        s.load_stix2_str(BUNDLE).unwrap();
        let mut hits = Vec::new();
        s.scan_text("GET https://API.Evil.com/x from 6.6.6.6:443 notevil.com evil.community", "logcat.txt", &mut hits);
        let vals: Vec<_> = hits.iter().map(|h| h.value.as_str()).collect();
        assert_eq!(vals, vec!["evil.com", "6.6.6.6"]);
    }
}
