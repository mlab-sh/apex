# Rules file

The text-based [cyber findings](Findings#cyber) use **short built-in lists**:
the common cases only, so that APEX works out of the box without drowning
the examiner. Your service will know more: phishing domains seen this month,
a local bank's real domains, a vault app spotted in another case, a spyware
indicator from a published report. Put them in a rules file; APEX adds them to
its own lists.

## Where APEX looks

1. The file named by the `APEX_RULES` environment variable, if set.
2. Otherwise `~/.config/apex/rules.toml`, if it exists.

When a file is used, every command that computes findings prints
`Rules: built-in + <path>`, and each cyber finding records the file in its
metadata (`rules_file`), so a report always says which lists produced it. A
file with a syntax error is reported and ignored (built-in lists only).

```sh
mkdir -p ~/.config/apex && $EDITOR ~/.config/apex/rules.toml
APEX_RULES=./affaire-42-rules.toml apex db ./case-42     # one file per case
```

## Extend or replace

Every list in the file is **added** to the built-in one. Put `replace = true`
in a section to use **only** your lists for that section.

## Format

TOML. Every section and every key is optional.

| Section | Keys | Used by |
|---|---|---|
| `[smishing]` | `brands` (list of `{ name, domains, keywords }`), `shorteners`, `keywords` (lure words), `replace` | `CASE_SMISHING`: a message naming a brand but linking elsewhere, a URL shortener, lure words |
| `[root]` | `packages`, `processes`, `ports` (TCP ports of instrumentation servers), `replace` | `CASE_ROOT_OR_INSTRUMENTATION` |
| `[vault]` | `packages` (exact), `keywords` (substrings of package names), `replace` | `CASE_VAULT_APP` |
| `[anti_forensics]` | `packages`, `keywords`, `replace` | `CASE_ANTI_FORENSICS` (data-wiping apps) |
| `[stores]` | `packages`, `keywords`, `replace` | what counts as "installed from a store" (everything else is sideloaded) |
| `[[signatures.rule]]` | `name`, `strings`, `condition` (`"any"`, `"all"` or a number), `severity` (`info` … `critical`), `description`; `[signatures] replace` | `CASE_SIGNATURE_MATCH`: strings in the code of apps not from a store, hidden or privileged |
| `[endpoints]` | `ignore_domains`, `replace` | `CASE_APP_ENDPOINTS`: domains never reported (and their subdomains) |
| `[spyware]` | `crash_processes`, `processes`, `paths`, `domains`, `replace` | `CASE_SYSTEM_CRASHES`, `CASE_SPYWARE_INDICATOR` |
| `[uploads]` | `min_share_pct` (70), `min_periods` (12), `min_kb` (50) | `CASE_PERIODIC_UPLOAD` thresholds |
| `[seeds]` | `languages` (`english`, `french`, `spanish`, `italian`) | `CASE_CRYPTO_SEED`: BIP39 word lists to try |

Domains match themselves and their subdomains (`laposte.fr` covers
`suivi.laposte.fr`, not `laposte-suivi.fr`). Package keywords are
case-insensitive substrings.

## Example

```toml
# ~/.config/apex/rules.toml: rules of the cyber unit, 2026-11

[smishing]
shorteners = ["lnk.to", "l.ead.me"]
keywords = ["PayLib", "conseiller bancaire"]

[[smishing.brands]]
name = "Banque Populaire"
domains = ["banquepopulaire.fr"]
keywords = ["banque populaire", "cyberplus"]

[[smishing.brands]]
name = "Vinted"
domains = ["vinted.fr", "vinted.com"]
keywords = ["vinted"]

[vault]
packages = ["com.xlab.hidevault", "com.example.calculatorlock"]
keywords = ["coffre"]

[anti_forensics]
keywords = ["cleanmaster"]

[root]
processes = ["frida-agent"]

[[signatures.rule]]
name = "Panel of the 2026 'Colis' campaign"
strings = ["gate.php", "/api/sms/upload"]
condition = "all"
severity = "high"
description = "Upload endpoint of the APK sent in the fake parcel SMS campaign (case 2026-0311)."

[[signatures.rule]]
name = "Known C2 domains"
strings = ["cdn-update-check.xyz", "secure-sync-mobile.top"]
condition = "any"
severity = "critical"
description = "Server seen in two previous cases."

[endpoints]
ignore_domains = ["mon-employeur.fr"]

[spyware]
# From a published report: process names and files.
processes = ["com.android.sysupd"]
paths = ["/data/local/tmp/.sysupd"]
domains = ["telemetry-cdn.example"]

[uploads]
min_share_pct = 60
min_periods = 8
min_kb = 20

[seeds]
languages = ["english", "french", "spanish"]
```

## Built-in lists

To see exactly what is built in, read [`src/rules.rs`](https://github.com/mlab-sh/apex/blob/main/src/rules.rs)
(`fn builtin`). In short:

- **smishing**: La Poste / Colissimo, Chronopost, Mondial Relay, Ameli,
  ANTAI, Impôts, CPF, Crit'Air with their official domains; ten URL
  shorteners; French lure words (colis, amende, remboursement…);
- **root**: Magisk, KernelSU, APatch, LSPosed, Xposed, EdXposed, SuperSU;
  Frida and Magisk processes; Frida ports 27042-27043;
- **vault / anti-forensics**: package-name keywords (vault, applock, hideapp,
  calculator.lock… / shredder, eraser, wiper…);
- **signatures**: Telegram bot API, Discord webhook, tunnels and dynamic DNS,
  SMS interception, remote lock / wipe, screen recording;
- **endpoints**: Google, Android, Meta, standard XML namespaces and common
  library domains are ignored;
- **spyware**: media, telephony, messaging, Bluetooth and NFC processes for
  crash listing; no built-in indicators (load published STIX2 files with
  `--iocs`, or list them here);
- **stores**: Google Play, Amazon, Samsung, Huawei, Xiaomi, OPPO / OnePlus,
  vivo, F-Droid.
