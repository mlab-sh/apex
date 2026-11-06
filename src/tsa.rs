//! RFC 3161 trusted timestamp of a case manifest (`apex seal`).
//!
//! The SHA-256 of `manifest.json` (which itself hashes every file of the case)
//! is sent to a Time-Stamping Authority; only that hash leaves the machine.
//! The signed token (`manifest.json.tsr`) proves the case existed, unchanged,
//! at the TSA's time. APEX checks the token's imprint and its signature (RSA,
//! ECDSA P-256 / P-384) against the signer certificate inside the token; the certificate chain
//! to a trusted root is left to `openssl ts -verify` (command printed).

use der::{Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::path::Path;

const SHA256_OID: &[u8] = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 128 {
        v.push(n as u8);
    } else {
        let b = n.to_be_bytes();
        let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
        v.push(0x80 | b.len() as u8);
        v.extend(b);
    }
    v.extend(body);
    v
}

/// DER `TimeStampReq` for a SHA-256 imprint, with a nonce and certReq = TRUE.
pub fn request(imprint: &[u8; 32], nonce: u64) -> Vec<u8> {
    let alg = tlv(0x30, &[SHA256_OID, &[0x05, 0x00]].concat());
    let mi = tlv(0x30, &[alg, tlv(0x04, imprint)].concat());
    // Minimal DER INTEGER: no leading zeros, one 0x00 only if the top bit is set.
    let mut nb: Vec<u8> = nonce.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
    if nb.first().is_none_or(|b| b & 0x80 != 0) {
        nb.insert(0, 0);
    }
    tlv(0x30, &[tlv(0x02, &[1]), mi, tlv(0x02, &nb), vec![0x01, 0x01, 0xff]].concat())
}

/// Read one DER element: (tag, content, rest).
fn read(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let l0 = *b.get(1)? as usize;
    let (len, off) = if l0 < 0x80 {
        (l0, 2)
    } else {
        let n = l0 & 0x7f;
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    Some((tag, b.get(off..off + len)?, b.get(off + len..)?))
}

fn children(mut b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut v = Vec::new();
    while let Some((t, c, r)) = read(b) {
        v.push((t, c));
        b = r;
    }
    v
}

pub struct Token {
    pub gen_time: String,
    pub imprint: Vec<u8>,
    pub tsa: String,
    /// Some(true) verified, Some(false) bad, None not checked (non-RSA key).
    pub signature_ok: Option<bool>,
}

/// Parse a `TimeStampResp` (or a bare token) and check its signature.
pub fn parse(resp: &[u8]) -> Result<Token, String> {
    let (_, body, _) = read(resp).ok_or("TSA reply: not DER")?;
    let parts = children(body);
    // TimeStampResp = { status, token }; a bare ContentInfo starts with an OID.
    let token_der: Vec<u8> = match parts.first() {
        Some((0x30, status)) => {
            let st = children(status).first().map(|(_, v)| v.last().copied().unwrap_or(9)).unwrap_or(9);
            if st > 1 {
                return Err(format!("TSA refused the request (status {st})"));
            }
            let (_, tok) = parts.get(1).ok_or("TSA reply has no token")?;
            tlv(0x30, tok)
        }
        _ => resp.to_vec(),
    };
    let ci = cms::content_info::ContentInfo::from_der(&token_der).map_err(|e| format!("token: {e}"))?;
    let sd = ci.content.decode_as::<cms::signed_data::SignedData>().map_err(|e| format!("token: {e}"))?;
    let econtent = sd.encap_content_info.econtent.as_ref().ok_or("token has no TSTInfo")?;
    let tst = econtent.value().to_vec();
    // econtent is an OCTET STRING holding the TSTInfo.
    let tst = match read(&tst) {
        Some((0x04, inner, _)) => inner.to_vec(),
        _ => tst,
    };
    let (_, tbody, _) = read(&tst).ok_or("bad TSTInfo")?;
    let f = children(tbody);
    // version, policy, messageImprint, serialNumber, genTime
    let imprint = f.get(2).and_then(|(_, mi)| children(mi).get(1).map(|(_, h)| h.to_vec())).ok_or("bad TSTInfo imprint")?;
    let gt = f.get(4).map(|(_, g)| String::from_utf8_lossy(g).into_owned()).ok_or("bad TSTInfo time")?;
    let gen_time = chrono::NaiveDateTime::parse_from_str(gt.trim_end_matches('Z').split('.').next().unwrap_or(""), "%Y%m%d%H%M%S")
        .map(|t| format!("{}Z", t.format("%Y-%m-%dT%H:%M:%S")))
        .unwrap_or(gt);

    let certs: Vec<x509_cert::Certificate> = sd
        .certificates
        .iter()
        .flat_map(|cs| cs.0.iter())
        .filter_map(|c| match c {
            cms::cert::CertificateChoices::Certificate(c) => Some(c.clone()),
            _ => None,
        })
        .collect();
    let mut tsa = certs.first().map(|c| c.tbs_certificate.subject.to_string()).unwrap_or_default();
    let mut signature_ok = None;
    if let Some(si) = sd.signer_infos.0.iter().next() {
        let hash = |alg: &str, data: &[u8]| -> Option<Vec<u8>> {
            Some(match alg {
                "2.16.840.1.101.3.4.2.1" => Sha256::digest(data).to_vec(),
                "2.16.840.1.101.3.4.2.2" => Sha384::digest(data).to_vec(),
                "2.16.840.1.101.3.4.2.3" => Sha512::digest(data).to_vec(),
                _ => return None,
            })
        };
        let alg = si.digest_alg.oid.to_string();
        if let (Some(attrs), Some(ec_hash)) = (&si.signed_attrs, hash(&alg, &tst)) {
            // messageDigest attribute must match the TSTInfo.
            let md_ok = attrs.iter().any(|a| a.oid.to_string() == "1.2.840.113549.1.9.4" && a.values.iter().any(|v| v.value() == ec_hash.as_slice()));
            let signed = attrs.to_der().map_err(|e| e.to_string())?;
            // The signer is named by issuer + serial (or key id): only its key counts.
            let signer = certs.iter().find(|c| match &si.sid {
                cms::signed_data::SignerIdentifier::IssuerAndSerialNumber(i) => i.serial_number == c.tbs_certificate.serial_number && i.issuer == c.tbs_certificate.issuer,
                cms::signed_data::SignerIdentifier::SubjectKeyIdentifier(k) => c
                    .tbs_certificate
                    .extensions
                    .iter()
                    .flatten()
                    .any(|e| e.extn_id.to_string() == "2.5.29.14" && e.extn_value.as_bytes().ends_with(k.0.as_bytes())),
            });
            if let Some(c) = signer {
                tsa = c.tbs_certificate.subject.to_string();
            }
            for c in signer.iter() {
                let spki = &c.tbs_certificate.subject_public_key_info;
                if spki.algorithm.oid.to_string() == "1.2.840.10045.2.1" {
                    // ECDSA: signature is DER (r, s) over the signed-attributes hash.
                    use p256::ecdsa::signature::hazmat::PrehashVerifier;
                    let (Some(h), Some(point)) = (hash(&alg, &signed), spki.subject_public_key.as_bytes()) else { continue };
                    let sig = si.signature.as_bytes();
                    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok()).map(|o| o.to_string());
                    let ok = match curve.as_deref() {
                        Some("1.2.840.10045.3.1.7") => p256::ecdsa::VerifyingKey::from_sec1_bytes(point).ok().zip(p256::ecdsa::Signature::from_der(sig).ok()).map(|(k, s)| k.verify_prehash(&h, &s).is_ok()),
                        Some("1.3.132.0.34") => p384::ecdsa::VerifyingKey::from_sec1_bytes(point).ok().zip(p384::ecdsa::Signature::from_der(sig).ok()).map(|(k, s)| k.verify_prehash(&h, &s).is_ok()),
                        _ => None,
                    };
                    signature_ok = ok.map(|o| o && md_ok);
                    continue;
                }
                if spki.algorithm.oid.to_string() != "1.2.840.113549.1.1.1" {
                    continue;
                }
                use rsa::pkcs8::DecodePublicKey;
                let Ok(der) = spki.to_der() else { continue };
                let Ok(key) = rsa::RsaPublicKey::from_public_key_der(&der) else { continue };
                let Some(h) = hash(&alg, &signed) else { continue };
                let scheme = match alg.as_str() {
                    "2.16.840.1.101.3.4.2.2" => rsa::Pkcs1v15Sign::new::<Sha384>(),
                    "2.16.840.1.101.3.4.2.3" => rsa::Pkcs1v15Sign::new::<Sha512>(),
                    _ => rsa::Pkcs1v15Sign::new::<Sha256>(),
                };
                let ok = md_ok && key.verify(scheme, &h, si.signature.as_bytes()).is_ok();
                signature_ok = Some(ok);
                if ok {
                    tsa = c.tbs_certificate.subject.to_string();
                    break;
                }
            }
        }
    }
    // Short name: the CN of the signer.
    let tsa = tsa.split(',').find_map(|p| p.trim().strip_prefix("CN=")).map(String::from).unwrap_or(tsa);
    Ok(Token { gen_time, imprint, tsa, signature_ok })
}

/// Timestamp `<case>/manifest.json` at `url`; writes `.tsq` and `.tsr`.
pub fn seal(case: &Path, url: &str) -> Result<Token, String> {
    let manifest = std::fs::read(case.join("manifest.json")).map_err(|e| format!("manifest.json: {e}"))?;
    let imprint: [u8; 32] = Sha256::digest(&manifest).into();
    let nonce = u64::from_le_bytes(Sha256::digest(chrono::Utc::now().to_rfc3339().as_bytes())[..8].try_into().unwrap());
    let req = request(&imprint, nonce);
    let resp = ureq::post(url)
        .set("Content-Type", "application/timestamp-query")
        .send_bytes(&req)
        .map_err(|e| format!("TSA {url}: {e}"))?;
    let mut body = Vec::new();
    std::io::Read::read_to_end(&mut resp.into_reader(), &mut body).map_err(|e| e.to_string())?;
    let tok = parse(&body)?;
    if tok.imprint != imprint {
        return Err("the TSA signed another hash than the manifest's".into());
    }
    std::fs::write(case.join("manifest.json.tsq"), &req).map_err(|e| e.to_string())?;
    std::fs::write(case.join("manifest.json.tsr"), &body).map_err(|e| e.to_string())?;
    Ok(tok)
}

/// Check an existing timestamp against the current manifest.
pub fn check(case: &Path) -> Option<Result<Token, String>> {
    let tsr = std::fs::read(case.join("manifest.json.tsr")).ok()?;
    Some((|| {
        let tok = parse(&tsr)?;
        let manifest = std::fs::read(case.join("manifest.json")).map_err(|e| e.to_string())?;
        if tok.imprint != Sha256::digest(&manifest).as_slice() {
            return Err(format!("timestamp of {} does NOT match the current manifest.json", tok.gen_time));
        }
        Ok(tok)
    })())
}

/// One line for reports (French, used in the PV).
pub fn describe(case: &Path) -> Option<String> {
    Some(match check(case)? {
        Ok(t) => format!(
            "{} (UTC) par {}, empreinte conforme au manifeste, signature {}",
            t.gen_time,
            t.tsa,
            match t.signature_ok {
                Some(true) => "vérifiée",
                Some(false) => "INVALIDE",
                None => "non vérifiée par APEX (algorithme non pris en charge)",
            }
        ),
        Err(e) => format!("ÉCHEC : {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_der() {
        let r = request(&[0xab; 32], 0x0102030405060708);
        // SEQUENCE { INTEGER 1, SEQUENCE { SEQUENCE { sha256, NULL }, OCTET STRING(32) }, INTEGER nonce, BOOLEAN TRUE }
        let (t, body, rest) = read(&r).unwrap();
        assert_eq!((t, rest.len()), (0x30, 0));
        let c = children(body);
        assert_eq!(c.len(), 4);
        assert_eq!(c[0], (0x02, &[1u8][..]));
        assert_eq!(children(c[1].1)[1], (0x04, &[0xab; 32][..]));
        assert_eq!(c[2].1, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let r = request(&[0; 32], 0x80);
        assert_eq!(children(read(&r).unwrap().1)[2].1, &[0, 0x80]);
        assert_eq!(c[3], (0x01, &[0xff][..]));
    }
}
