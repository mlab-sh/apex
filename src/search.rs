//! Cross-search of a whole case, and entity extraction.
//!
//! Sources: every text artifact of the case (device dumps, app dumps, exports),
//! the text entries of `bugreport.zip`, text files in shared storage, and the
//! communication records (`comms::load`, mandate only).
//!
//! Entities: phone numbers, e-mail addresses, IBANs (mod-97 checked), Bitcoin
//! addresses (Base58Check / Bech32 checked), Ethereum addresses, @handles.
//! Checksums keep the false positives of a blind regex out.

use crate::case::Case;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

/// One text source: (label, content).
pub fn sources(case: &Case) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for e in walkdir::WalkDir::new(&case.root).into_iter().flatten().filter(|e| e.file_type().is_file()) {
        let p = e.path();
        let rel = p.strip_prefix(&case.root).unwrap_or(p).to_string_lossy().into_owned();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("").to_ascii_lowercase();
        if rel.starts_with("comms/db/") {
            continue; // read through comms::load below
        }
        match ext.as_str() {
            "txt" | "json" | "jsonl" | "csv" | "xml" | "log" | "md" | "html" | "vcf" | "ics" => {
                if let Ok(b) = std::fs::read(p) {
                    out.push((rel, String::from_utf8_lossy(&b).into_owned()));
                }
            }
            "zip" if rel.ends_with("bugreport.zip") => {
                let Ok(f) = std::fs::File::open(p) else { continue };
                let Ok(mut z) = zip::ZipArchive::new(f) else { continue };
                for i in 0..z.len() {
                    let Ok(mut ent) = z.by_index(i) else { continue };
                    let name = ent.name().to_string();
                    if !name.ends_with(".txt") {
                        continue;
                    }
                    let mut b = Vec::new();
                    if ent.read_to_end(&mut b).is_ok() {
                        out.push((format!("{rel}!{name}"), String::from_utf8_lossy(&b).into_owned()));
                    }
                }
            }
            _ => {}
        }
    }
    let comms = crate::comms::load(case);
    if !comms.is_empty() {
        let text = comms
            .iter()
            .map(|c| {
                let when = case.local_from_epoch_ms(c.time_ms).unwrap_or_default();
                format!("{when} {} {} {} {} {}", c.kind, c.direction, c.peer, c.text.replace('\n', " "), c.extra)
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push(("communications".into(), text));
    }
    out
}

/// A search hit: source, line number, line (trimmed).
pub struct Hit {
    pub source: String,
    pub line: usize,
    pub text: String,
}

/// Lines matching any pattern (case-insensitive literal, or regex).
pub fn search(srcs: &[(String, String)], patterns: &[String], regex: bool) -> Result<Vec<Hit>, String> {
    let res: Vec<Regex> = patterns
        .iter()
        .map(|p| {
            let p = if regex { p.clone() } else { regex::escape(p) };
            Regex::new(&format!("(?i){p}")).map_err(|e| format!("bad pattern: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let hits = crate::par_map(srcs, |(label, text)| {
        text.lines()
            .enumerate()
            .filter(|(_, l)| res.iter().any(|r| r.is_match(l)))
            .map(|(i, l)| Hit { source: label.clone(), line: i + 1, text: l.trim().chars().take(400).collect() })
            .collect::<Vec<_>>()
    });
    Ok(hits.into_iter().flatten().collect())
}

// ---------------------------------------------------------------- entities

fn iban_ok(s: &str) -> bool {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return false;
    }
    let r = format!("{}{}", &s[4..], &s[..4]);
    let mut m: u32 = 0;
    for c in r.chars() {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        m = if v >= 10 { (m * 100 + v) % 97 } else { (m * 10 + v) % 97 };
    }
    m == 1
}

fn base58check_ok(s: &str) -> bool {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut n: Vec<u8> = vec![0];
    for c in s.bytes() {
        let Some(v) = A.iter().position(|x| *x == c) else { return false };
        let mut carry = v as u32;
        for d in n.iter_mut().rev() {
            carry += *d as u32 * 58;
            *d = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            n.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let lead = s.bytes().take_while(|b| *b == b'1').count();
    let n: Vec<u8> = n.into_iter().skip_while(|b| *b == 0).collect();
    let mut bytes = vec![0u8; lead];
    bytes.extend(n);
    if bytes.len() != 25 {
        return false;
    }
    let (data, ck) = bytes.split_at(21);
    Sha256::digest(Sha256::digest(data))[..4] == *ck
}

fn bech32_ok(s: &str) -> bool {
    const C: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let s = s.to_ascii_lowercase();
    let Some((hrp, data)) = s.rsplit_once('1') else { return false };
    let Some(vals) = data.bytes().map(|b| C.iter().position(|x| *x == b).map(|v| v as u32)).collect::<Option<Vec<u32>>>() else { return false };
    let mut chk: u32 = 1;
    let gen = [0x3b6a57b2u32, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut step = |v: u32| {
        let b = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (i, g) in gen.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    };
    for c in hrp.bytes() {
        step(c as u32 >> 5);
    }
    step(0);
    for c in hrp.bytes() {
        step(c as u32 & 31);
    }
    for v in vals {
        step(v);
    }
    // bech32 (segwit v0) or bech32m (v1+).
    chk == 1 || chk == 0x2bc830a3
}

/// (kind, normalized value) for every entity in `text`.
pub fn entities(text: &str, chat: bool) -> Vec<(&'static str, String)> {
    use std::sync::OnceLock;
    static RE: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    let res = RE.get_or_init(|| {
        vec![
            ("email", Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b").unwrap()),
            ("phone", Regex::new(r"(?:^|[^\w+])(\+[1-9]\d{7,14})\b").unwrap()),
            // National format: only in messages and documents, logs are full of 10-digit numbers.
            ("phone_national", Regex::new(r"(?:^|[^\w+])(0[1-9](?:[ .-]?\d{2}){4})\b").unwrap()),
            ("iban", Regex::new(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b").unwrap()),
            ("bitcoin", Regex::new(r"\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,71})\b").unwrap()),
            ("ethereum", Regex::new(r"\b0x[0-9a-fA-F]{40}\b").unwrap()),
            ("handle", Regex::new(r"(?:^|[\s(])@([A-Za-z0-9_.]{3,30})\b").unwrap()),
        ]
    });
    let mut out = Vec::new();
    for (kind, re) in res {
        // Handles only mean something in messages; elsewhere `@` is code and annotations.
        if (*kind == "handle" || *kind == "phone_national") && !chat {
            continue;
        }
        for c in re.captures_iter(text) {
            let raw = c.get(1).unwrap_or_else(|| c.get(0).unwrap()).as_str();
            let v = match *kind {
                // A WhatsApp JID is a phone number, not a mailbox.
                "email" if raw.to_lowercase().ends_with("@s.whatsapp.net") => {
                    out.push(("phone", format!("+{}", raw.split('@').next().unwrap_or(""))));
                    continue;
                }
                "email" if raw.to_lowercase().ends_with("@g.us") => continue,
                "email" => {
                    // HAL / library names look like addresses: `android.hardware.x@1.0.so`.
                    const FILE_EXT: &[&str] = &["so", "apex", "db", "xml", "json", "png", "jpg", "jpeg", "gif", "webp", "txt", "rc", "bin", "conf", "log", "ini", "zip", "apk", "odex", "vdex", "oat", "prop", "impl", "service", "multihal", "hal", "jar", "dex"];
                    let low = raw.to_lowercase();
                    let domain = low.rsplit('@').next().unwrap_or("");
                    let tld = domain.rsplit('.').next().unwrap_or("");
                    // Google's public calendars (holidays, birthdays, weather) are calendar IDs, not people.
                    if domain.starts_with(|c: char| c.is_ascii_digit()) || FILE_EXT.contains(&tld) || low.starts_with("android.") || low.starts_with("vendor.") || domain.starts_with("com.android.") || domain == "group.v.calendar.google.com" {
                        continue;
                    }
                    low
                }
                "phone" | "phone_national" => {
                    out.push(("phone", raw.chars().filter(|c| c.is_ascii_digit() || *c == '+').collect()));
                    continue;
                }
                "iban" if iban_ok(raw) => raw.replace(' ', ""),
                "bitcoin" if (raw.starts_with("bc1") && bech32_ok(raw)) || (!raw.starts_with("bc1") && base58check_ok(raw)) => raw.to_string(),
                "ethereum" => raw.to_lowercase(),
                "handle" => format!("@{raw}"),
                _ => continue,
            };
            out.push((*kind, v));
        }
    }
    out
}

/// kind → value → (count, sources).
pub type Entities = BTreeMap<&'static str, BTreeMap<String, (usize, Vec<String>)>>;

pub fn extract(srcs: &[(String, String)]) -> Entities {
    let per = crate::par_map(srcs, |(label, text)| (label.clone(), entities(text, label == "communications" || label.starts_with("storage/"))));
    let mut m: Entities = BTreeMap::new();
    for (label, ents) in per {
        for (k, v) in ents {
            let e = m.entry(k).or_default().entry(v).or_default();
            e.0 += 1;
            if !e.1.contains(&label) {
                e.1.push(label.clone());
            }
        }
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        assert!(iban_ok("FR76 3000 6000 0112 3456 7890 189"));
        assert!(!iban_ok("FR76 3000 6000 0112 3456 7890 188"));
        assert!(base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(!base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
        assert!(bech32_ok("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(!bech32_ok("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdx"));
    }

    #[test]
    fn extract_entities() {
        let t = "Vire sur FR76 3000 6000 0112 3456 7890 189 ou en BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa, appelle le 06 12 34 56 78 ou +33612345679, mail Dede@Example.com, insta @dede_77. Faux: FR76 3000 6000 0112 3456 7890 188";
        let e = entities(t, true);
        let has = |k: &str, v: &str| e.iter().any(|(a, b)| *a == k && b == v);
        assert!(has("iban", "FR7630006000011234567890189"));
        assert!(!e.iter().any(|(a, b)| *a == "iban" && b.ends_with("188")));
        assert!(has("bitcoin", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(has("phone", "0612345678"));
        assert!(has("phone", "+33612345679"));
        assert!(has("email", "dede@example.com"));
        assert!(has("handle", "@dede_77"));
        // Not in a chat: no handles.
        assert!(!entities("@Override", false).iter().any(|(k, _)| *k == "handle"));
    }
}
