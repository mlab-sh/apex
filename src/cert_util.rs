//! X.509 / PKCS#7 certificate extraction helpers (RustCrypto cms + x509-cert).

use der::{Decode, Encode};

pub struct CertData {
    pub der: Vec<u8>,
    pub subject: String,
    pub issuer: String,
    pub serial_dec: String,
    pub not_before: String,
    pub not_after: String,
    pub not_after_unix: Option<i64>,
    pub sig_algo_name: String,
    pub hash_algo: String,
    pub key_algo: String,
    pub key_bits: usize,
}

/// Parse a PKCS#7 (CMS SignedData) blob and return the embedded X.509 certs.
pub fn parse_pkcs7(raw: &[u8]) -> Vec<CertData> {
    let mut out = Vec::new();
    let ci = match cms::content_info::ContentInfo::from_der(raw) {
        Ok(ci) => ci,
        Err(_) => return out,
    };
    let sd = match ci.content.decode_as::<cms::signed_data::SignedData>() {
        Ok(sd) => sd,
        Err(_) => return out,
    };
    let certs = match sd.certificates {
        Some(c) => c,
        None => return out,
    };
    for choice in certs.0.iter() {
        if let cms::cert::CertificateChoices::Certificate(cert) = choice {
            if let Some(cd) = build_cert_data(cert) {
                out.push(cd);
            }
        }
    }
    out
}

fn build_cert_data(cert: &x509_cert::Certificate) -> Option<CertData> {
    let der = cert.to_der().ok()?;
    let tbs = &cert.tbs_certificate;

    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let serial_dec = bytes_to_decimal(tbs.serial_number.as_bytes());

    let not_before_unix = time_to_unix(&tbs.validity.not_before);
    let not_after_unix = time_to_unix(&tbs.validity.not_after);
    let not_before = not_before_unix.map(iso).unwrap_or_else(|| "unknown".into());
    let not_after = not_after_unix.map(iso).unwrap_or_else(|| "unknown".into());

    let sig_oid = tbs.signature.oid.to_string();
    let (sig_algo_name, hash_algo) = sig_algo_info(&sig_oid);

    let spki = &tbs.subject_public_key_info;
    let key_oid = spki.algorithm.oid.to_string();
    let (key_algo, key_bits) = key_info(&key_oid, spki);

    Some(CertData {
        der,
        subject,
        issuer,
        serial_dec,
        not_before,
        not_after,
        not_after_unix,
        sig_algo_name,
        hash_algo,
        key_algo,
        key_bits,
    })
}

fn sig_algo_info(oid: &str) -> (String, String) {
    let (name, hash) = match oid {
        "1.2.840.113549.1.1.2" => ("md2_rsa", "md2"),
        "1.2.840.113549.1.1.4" => ("md5_rsa", "md5"),
        "1.2.840.113549.1.1.5" => ("sha1_rsa", "sha1"),
        "1.2.840.113549.1.1.11" => ("sha256_rsa", "sha256"),
        "1.2.840.113549.1.1.12" => ("sha384_rsa", "sha384"),
        "1.2.840.113549.1.1.13" => ("sha512_rsa", "sha512"),
        "1.2.840.113549.1.1.14" => ("sha224_rsa", "sha224"),
        "1.2.840.10045.4.1" => ("sha1_ecdsa", "sha1"),
        "1.2.840.10045.4.3.1" => ("sha224_ecdsa", "sha224"),
        "1.2.840.10045.4.3.2" => ("sha256_ecdsa", "sha256"),
        "1.2.840.10045.4.3.3" => ("sha384_ecdsa", "sha384"),
        "1.2.840.10045.4.3.4" => ("sha512_ecdsa", "sha512"),
        "1.2.840.10040.4.3" => ("sha1_dsa", "sha1"),
        "2.16.840.1.101.3.4.3.1" => ("sha224_dsa", "sha224"),
        "2.16.840.1.101.3.4.3.2" => ("sha256_dsa", "sha256"),
        other => return (other.to_string(), String::new()),
    };
    (name.to_string(), hash.to_string())
}

fn key_info(oid: &str, spki: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> (String, usize) {
    match oid {
        "1.2.840.113549.1.1.1" => {
            // RSA: BIT STRING content is DER RSAPublicKey { modulus, exponent }
            let bits = rsa_modulus_bits(spki.subject_public_key.raw_bytes()).unwrap_or(0);
            ("rsa".to_string(), bits)
        }
        "1.2.840.10045.2.1" => {
            // EC: parameters carry the named curve OID.
            let bits = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .map(|c| ec_curve_bits(&c.to_string()))
                .unwrap_or(0);
            ("ec".to_string(), bits)
        }
        "1.2.840.10040.4.1" => ("dsa".to_string(), 0),
        _ => ("unknown".to_string(), 0),
    }
}

fn ec_curve_bits(oid: &str) -> usize {
    match oid {
        "1.2.840.10045.3.1.1" => 192,
        "1.3.132.0.33" => 224,
        "1.2.840.10045.3.1.7" => 256,
        "1.3.132.0.10" => 256,
        "1.3.132.0.34" => 384,
        "1.3.132.0.35" => 521,
        _ => 0,
    }
}

/// Extract the modulus bit length from a DER-encoded RSAPublicKey.
fn rsa_modulus_bits(der_bytes: &[u8]) -> Option<usize> {
    // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let mut r = der::SliceReader::new(der_bytes).ok()?;
    let seq_header = der::Header::decode(&mut r).ok()?;
    let _ = seq_header;
    // Read the modulus INTEGER as raw bytes.
    let modulus = der::asn1::UintRef::decode(&mut r).ok()?;
    let bytes = modulus.as_bytes();
    if bytes.is_empty() {
        return Some(0);
    }
    let top = bytes[0];
    let bits = (bytes.len() - 1) * 8 + (8 - top.leading_zeros() as usize);
    Some(bits)
}

fn time_to_unix(t: &x509_cert::time::Time) -> Option<i64> {
    let secs = t.to_unix_duration().as_secs();
    Some(secs as i64)
}

fn iso(unix: i64) -> String {
    use chrono::TimeZone;
    match chrono::Utc.timestamp_opt(unix, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%dT%H:%M:%S+00:00").to_string(),
        _ => "unknown".to_string(),
    }
}

fn bytes_to_decimal(bytes: &[u8]) -> String {
    // Skip leading sign/zero bytes but keep at least one digit.
    let mut digits: Vec<u8> = vec![0];
    for &b in bytes {
        // digits = digits * 256 + b
        let mut carry = b as u32;
        for d in digits.iter_mut() {
            let val = (*d as u32) * 256 + carry;
            *d = (val % 10) as u8;
            carry = val / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let s: String = digits.iter().rev().map(|d| (b'0' + d) as char).collect();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Uppercase-hex SHA-1 of every signing certificate of an APK (the digest
/// `apksigner verify --print-certs` shows, and what Echap's IOCs use).
/// Reads v1 (`META-INF/*.RSA|DSA|EC`) and the v2/v3 APK Signing Block, so
/// v2/v3-only APKs (most modern apps) are covered too.
pub fn apk_signer_sha1s(apk: &std::path::Path) -> Vec<String> {
    use sha1::{Digest, Sha1};
    let data = match std::fs::read(apk) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut ders: Vec<Vec<u8>> = signing_block_certs(&data);
    if let Ok(mut zip) = zip::ZipArchive::new(std::io::Cursor::new(&data)) {
        for i in 0..zip.len() {
            let Ok(mut f) = zip.by_index(i) else { continue };
            let name = f.name().to_ascii_uppercase();
            if name.starts_with("META-INF/")
                && (name.ends_with(".RSA") || name.ends_with(".DSA") || name.ends_with(".EC"))
            {
                let mut raw = Vec::new();
                if std::io::Read::read_to_end(&mut f, &mut raw).is_ok() {
                    ders.extend(parse_pkcs7(&raw).into_iter().map(|c| c.der));
                }
            }
        }
    }
    let mut out: Vec<String> = ders
        .iter()
        .map(|d| Sha1::digest(d).iter().map(|b| format!("{b:02X}")).collect())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// DER certificates from the v2/v3/v3.1 signers in the APK Signing Block.
fn signing_block_certs(data: &[u8]) -> Vec<Vec<u8>> {
    const IDS: [u32; 3] = [0x7109_871a, 0xf053_68c0, 0x1b93_ad61];
    let u32_at = |o: usize| data.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    let u64_at = |o: usize| data.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()) as usize);
    let mut out = Vec::new();
    // EOCD → central directory offset → "APK Sig Block 42" just before it.
    let Some(eocd) = data.windows(4).rposition(|w| w == [0x50, 0x4b, 0x05, 0x06]) else { return out };
    let Some(cd) = u32_at(eocd + 16) else { return out };
    if cd < 24 || data.get(cd - 16..cd) != Some(b"APK Sig Block 42") {
        return out;
    }
    let Some(size) = u64_at(cd - 24) else { return out };
    let Some(start) = cd.checked_sub(size).and_then(|v| v.checked_sub(8)) else { return out };
    let (mut pos, end) = (start + 8, cd - 24);
    while pos + 12 <= end {
        let (Some(len), Some(id)) = (u64_at(pos), u32_at(pos + 8)) else { break };
        let Some(next) = pos.checked_add(8 + len) else { break };
        if IDS.contains(&(id as u32)) {
            if let Some(v) = data.get(pos + 12..next.min(end)) {
                // signers (lp) → signer (lp) → signed data (lp) → digests (lp), certificates (lp) → cert (lp)
                for signer in lp_items(v.get(4..).unwrap_or_default()) {
                    let Some(signed) = lp_items(signer).into_iter().next() else { continue };
                    let mut parts = lp_items(signed).into_iter();
                    let _digests = parts.next();
                    if let Some(certs) = parts.next() {
                        // Keep only blobs that really decode as X.509 (guards against misparse).
                        out.extend(
                            lp_items(certs)
                                .into_iter()
                                .filter(|c| x509_cert::Certificate::from_der(c).is_ok())
                                .map(|c| c.to_vec()),
                        );
                    }
                }
            }
        }
        pos = next;
    }
    out
}

/// Split a buffer of u32-LE-length-prefixed items. Stops at the first malformed item.
fn lp_items(mut buf: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while buf.len() >= 4 {
        let n = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let Some(item) = buf.get(4..4 + n) else { break };
        out.push(item);
        buf = &buf[4 + n..];
    }
    out
}

