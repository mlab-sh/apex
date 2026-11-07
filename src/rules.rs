//! Text lists behind the cyber findings: small built-in lists, extended (or
//! replaced) by the examiner's own rules file, TOML:
//!
//! - `$APEX_RULES` if set, else `~/.config/apex/rules.toml` if it exists.
//! - Every list in the file is added to the built-in one; `replace = true` in
//!   a section uses only the file's lists for that section.
//!
//! The format and an example are on the wiki page "Rules file".

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Brand {
    pub name: String,
    /// Official domains (and their subdomains).
    pub domains: Vec<String>,
    /// Words that tie a message to this brand.
    pub keywords: Vec<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Smishing {
    pub replace: bool,
    pub brands: Vec<Brand>,
    pub shorteners: Vec<String>,
    /// Lure words (parcel, fine, refund…).
    pub keywords: Vec<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Root {
    pub replace: bool,
    pub packages: Vec<String>,
    pub processes: Vec<String>,
    /// Listening TCP ports of instrumentation servers.
    pub ports: Vec<u16>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Apps {
    pub replace: bool,
    /// Exact package names.
    pub packages: Vec<String>,
    /// Substrings of package names.
    pub keywords: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Signature {
    pub name: String,
    pub strings: Vec<String>,
    /// "any", "all", or a number: how many strings must be present.
    pub condition: String,
    /// info, low, medium, high, critical.
    pub severity: String,
    pub description: String,
}

impl Default for Signature {
    fn default() -> Self {
        Signature { name: String::new(), strings: Vec::new(), condition: "all".into(), severity: "medium".into(), description: String::new() }
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Signatures {
    pub replace: bool,
    pub rule: Vec<Signature>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Endpoints {
    pub replace: bool,
    /// Domains never reported as an app endpoint (and their subdomains).
    pub ignore_domains: Vec<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Spyware {
    pub replace: bool,
    /// Processes whose native crashes are listed (exploitation attempts often crash them).
    pub crash_processes: Vec<String>,
    /// Indicator process names, file paths, domains (e.g. from published reports).
    pub processes: Vec<String>,
    pub paths: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Uploads {
    /// Minimum share of the measured periods with a background upload, in %.
    pub min_share_pct: u32,
    /// Minimum number of periods with an upload.
    pub min_periods: u32,
    /// Ignore periods under this many KB sent.
    pub min_kb: u64,
}

impl Default for Uploads {
    fn default() -> Self {
        Uploads { min_share_pct: 70, min_periods: 12, min_kb: 50 }
    }
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Seeds {
    /// bip39 languages to try: english, french, spanish, italian.
    pub languages: Vec<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Rules {
    pub smishing: Smishing,
    pub root: Root,
    pub vault: Apps,
    pub anti_forensics: Apps,
    pub signatures: Signatures,
    pub endpoints: Endpoints,
    pub spyware: Spyware,
    pub uploads: Uploads,
    pub seeds: Seeds,
    /// Stores whose installs count as "from a store".
    pub stores: Apps,
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// The built-in lists: deliberately short, the common cases only.
pub fn builtin() -> Rules {
    let brand = |name: &str, domains: &[&str], keywords: &[&str]| Brand { name: name.into(), domains: s(domains), keywords: s(keywords) };
    let sig = |name: &str, strings: &[&str], condition: &str, severity: &str, description: &str| Signature { name: name.into(), strings: s(strings), condition: condition.into(), severity: severity.into(), description: description.into() };
    Rules {
        smishing: Smishing {
            replace: false,
            brands: vec![
                brand("La Poste / Colissimo", &["laposte.fr", "laposte.net", "colissimo.fr", "labanquepostale.fr"], &["la poste", "colissimo", "colis"]),
                brand("Chronopost", &["chronopost.fr"], &["chronopost"]),
                brand("Mondial Relay", &["mondialrelay.fr"], &["mondial relay"]),
                brand("Ameli / Assurance maladie", &["ameli.fr"], &["ameli", "carte vitale", "assurance maladie"]),
                brand("ANTAI (amendes)", &["antai.gouv.fr"], &["antai", "amende", "avis de contravention"]),
                brand("Impôts", &["impots.gouv.fr"], &["impots", "impôts", "remboursement d'impôt"]),
                brand("CPF", &["moncompteformation.gouv.fr"], &["cpf", "compte formation"]),
                brand("Crit'Air", &["certificat-air.gouv.fr"], &["crit'air", "vignette"]),
            ],
            shorteners: s(&["bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "tiny.cc", "ow.ly", "s.id"]),
            keywords: s(&["colis", "livraison", "amende", "remboursement", "suspendu", "bloqué", "vérifiez", "frais de port", "dernier rappel"]),
        },
        root: Root {
            replace: false,
            packages: s(&["com.topjohnwu.magisk", "io.github.huskydg.magisk", "me.weishu.kernelsu", "me.bmax.apatch", "org.lsposed.manager", "de.robv.android.xposed.installer", "org.meowcat.edxposed.manager", "eu.chainfire.supersu"]),
            processes: s(&["frida-server", "frida", "gum-js-loop", "magiskd", "ksud", "lspd"]),
            ports: vec![27042, 27043],
        },
        vault: Apps { replace: false, packages: Vec::new(), keywords: s(&["vault", "applock", "app.lock", "hideapp", "hide.app", "privategallery", "secretgallery", "calculator.lock", "calculatorvault", "photolocker"]) },
        anti_forensics: Apps { replace: false, packages: Vec::new(), keywords: s(&["shredder", "shred", "eraser", "securedelete", "secure.delete", "wiper", "datawipe"]) },
        signatures: Signatures {
            replace: false,
            rule: vec![
                sig("Telegram bot API", &["api.telegram.org/bot"], "any", "medium", "Code talks to a Telegram bot: a common exfiltration channel for spyware and banking trojans."),
                sig("Discord webhook", &["discord.com/api/webhooks", "discordapp.com/api/webhooks"], "any", "medium", "Code posts to a Discord webhook: a common exfiltration channel."),
                sig("Tunnel / dynamic host", &[".ngrok.io", ".ngrok-free.app", ".trycloudflare.com", ".duckdns.org", ".no-ip.org", ".serveo.net"], "any", "medium", "Code references a tunnel or dynamic-DNS host, often used for remote-access servers."),
                sig("SMS interception and forwarding", &["android.provider.Telephony.SMS_RECEIVED", "sendTextMessage"], "all", "medium", "Receives SMS and can send SMS: forwarding of one-time codes."),
                sig("Remote lock or wipe", &["lockNow", "wipeData"], "all", "low", "Device-admin calls to lock or wipe the phone."),
                sig("Screen recording", &["createScreenCaptureIntent", "createVirtualDisplay"], "all", "low", "Captures the screen."),
            ],
        },
        endpoints: Endpoints {
            replace: false,
            ignore_domains: s(&[
                "android.com", "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "google-analytics.com", "googlesyndication.com", "doubleclick.net", "w3.org", "schemas.android.com",
                "apache.org", "xmlpull.org", "xml.org", "example.com", "example.org", "github.com", "facebook.com", "fb.com", "instagram.com", "whatsapp.net", "crashlytics.com", "firebase.com", "ietf.org",
                "mozilla.org", "jquery.com", "json.org", "unicode.org", "openssl.org", "bouncycastle.org", "adobe.com", "ns.adobe.com", "purl.org", "microsoft.com", "apple.com",
            ]),
        },
        spyware: Spyware {
            replace: false,
            crash_processes: s(&["mediaserver", "media.extractor", "media.codec", "media.swcodec", "com.android.phone", "com.google.android.apps.messaging", "com.android.mms", "com.samsung.android.messaging", "com.whatsapp", "system_server", "com.android.bluetooth", "com.android.nfc"]),
            processes: Vec::new(),
            paths: Vec::new(),
            domains: Vec::new(),
        },
        uploads: Uploads::default(),
        seeds: Seeds { languages: s(&["english", "french"]) },
        stores: Apps {
            replace: false,
            packages: s(&["com.android.vending", "com.amazon.venezia", "com.sec.android.app.samsungapps", "com.huawei.appmarket", "com.xiaomi.market", "com.xiaomi.discover", "com.heytap.market", "com.oppo.market", "com.vivo.appstore", "org.fdroid.fdroid"]),
            keywords: Vec::new(),
        },
    }
}

fn merge<T: Clone>(base: &mut Vec<T>, add: &[T], replace: bool) {
    if replace {
        *base = add.to_vec();
    } else {
        base.extend_from_slice(add);
    }
}

/// Built-in lists merged with a user file.
pub fn merged(user: &Rules) -> Rules {
    let mut r = builtin();
    let u = user;
    merge(&mut r.smishing.brands, &u.smishing.brands, u.smishing.replace);
    merge(&mut r.smishing.shorteners, &u.smishing.shorteners, u.smishing.replace);
    merge(&mut r.smishing.keywords, &u.smishing.keywords, u.smishing.replace);
    merge(&mut r.root.packages, &u.root.packages, u.root.replace);
    merge(&mut r.root.processes, &u.root.processes, u.root.replace);
    merge(&mut r.root.ports, &u.root.ports, u.root.replace);
    for (b, ub) in [(&mut r.vault, &u.vault), (&mut r.anti_forensics, &u.anti_forensics), (&mut r.stores, &u.stores)] {
        merge(&mut b.packages, &ub.packages, ub.replace);
        merge(&mut b.keywords, &ub.keywords, ub.replace);
    }
    merge(&mut r.signatures.rule, &u.signatures.rule, u.signatures.replace);
    merge(&mut r.endpoints.ignore_domains, &u.endpoints.ignore_domains, u.endpoints.replace);
    merge(&mut r.spyware.crash_processes, &u.spyware.crash_processes, u.spyware.replace);
    merge(&mut r.spyware.processes, &u.spyware.processes, u.spyware.replace);
    merge(&mut r.spyware.paths, &u.spyware.paths, u.spyware.replace);
    merge(&mut r.spyware.domains, &u.spyware.domains, u.spyware.replace);
    r.uploads = u.uploads.clone();
    if !u.seeds.languages.is_empty() {
        r.seeds.languages = u.seeds.languages.clone();
    }
    r
}

/// Where the user rules file is looked for.
pub fn path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("APEX_RULES") {
        return Some(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")?;
    let p = PathBuf::from(home).join(".config/apex/rules.toml");
    p.is_file().then_some(p)
}

/// The rules in force, and the user file used if any (loaded once).
pub fn get() -> &'static (Rules, Option<PathBuf>) {
    static R: OnceLock<(Rules, Option<PathBuf>)> = OnceLock::new();
    R.get_or_init(|| match path() {
        Some(p) => match std::fs::read_to_string(&p).map_err(|e| e.to_string()).and_then(|t| toml::from_str::<Rules>(&t).map_err(|e| e.to_string())) {
            Ok(u) => {
                eprintln!("\x1b[2mRules: built-in + {}\x1b[0m", p.display());
                (merged(&u), Some(p))
            }
            Err(e) => {
                eprintln!("\x1b[31mRules file {}: {e} (built-in rules used)\x1b[0m", p.display());
                (builtin(), None)
            }
        },
        None => (builtin(), None),
    })
}

pub fn r() -> &'static Rules {
    &get().0
}

/// `domain` is `base` or one of its subdomains.
pub fn domain_in(domain: &str, base: &str) -> bool {
    let (d, b) = (domain.to_ascii_lowercase(), base.to_ascii_lowercase());
    d == b || d.ends_with(&format!(".{b}"))
}

/// Package matches an exact name or contains a keyword.
pub fn app_matches(apps: &Apps, pkg: &str) -> bool {
    let p = pkg.to_ascii_lowercase();
    apps.packages.iter().any(|x| x == pkg) || apps.keywords.iter().any(|k| p.contains(&k.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiki_example_is_valid() {
        let page = include_str!("../wiki/Rules-File.md");
        let toml_block = page.split("```toml").nth(1).and_then(|b| b.split("```").next()).unwrap();
        let u: Rules = toml::from_str(toml_block).unwrap();
        let r = merged(&u);
        assert!(r.smishing.brands.iter().any(|b| b.name == "Vinted"));
        assert_eq!(r.uploads.min_periods, 8);
        assert!(r.signatures.rule.iter().any(|x| x.severity == "critical"));
    }

    #[test]
    fn user_file_extends_or_replaces() {
        let u: Rules = toml::from_str(
            r#"
[smishing]
shorteners = ["lnk.to"]
[[smishing.brands]]
name = "Ma Banque"
domains = ["mabanque.fr"]
keywords = ["ma banque"]

[vault]
replace = true
packages = ["com.x.vault"]

[[signatures.rule]]
name = "Custom"
strings = ["evil.example"]
condition = "any"
severity = "high"

[uploads]
min_share_pct = 50
min_periods = 6
min_kb = 10
"#,
        )
        .unwrap();
        let r = merged(&u);
        assert!(r.smishing.shorteners.contains(&"bit.ly".to_string()) && r.smishing.shorteners.contains(&"lnk.to".to_string()));
        assert!(r.smishing.brands.iter().any(|b| b.name == "Ma Banque") && r.smishing.brands.iter().any(|b| b.name.starts_with("La Poste")));
        assert_eq!((r.vault.packages.clone(), r.vault.keywords.len()), (vec!["com.x.vault".to_string()], 0));
        assert!(r.signatures.rule.iter().any(|x| x.name == "Custom") && r.signatures.rule.len() > 1);
        assert_eq!(r.uploads.min_periods, 6);
        assert!(domain_in("suivi.laposte.fr", "laposte.fr") && !domain_in("laposte-colis.fr", "laposte.fr"));
    }
}
