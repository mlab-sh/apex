# Indicators and hash sets

## Built in

The Echap stalkerware package names and signing-certificate SHA-1s are
compiled into APEX (`src/stalkerware_iocs.rs`, refreshed with
`scripts/update-iocs.sh`). No option needed.

## STIX2 indicators (`--iocs`)

Commands: [`analyze`](Analyze), [`report`](Report), [`diff`](Diff), [`pv`](PV).
Repeat the option for several files.

Any STIX 2.x bundle: Echap's
[`generated/stalkerware.stix2`](https://github.com/AssoEchap/stalkerware-indicators/tree/master/generated),
MVT / Amnesty indicator files, your own.

| Pattern | Matched against |
|---|---|
| `app:id` | installed package names |
| `app:cert.sha1`, `app:cert.sha256` | APK signing certificates |
| `file:hashes.sha256`, `sha1`, `md5` | APKs, and files in storage and communications |
| `domain-name:value`, `ipv4-addr:value`, `ipv6-addr:value`, `url:value` | collected text, the bugreport, live sockets |

Other pattern types are counted and reported, never silently dropped.

## Alert hash sets (`--hashes`)

Commands: [`media`](Media), [`analyze`](Analyze), [`report`](Report), [`pv`](PV).
A match raises `HASH_SET_MATCH` with the file path.

| Format | Recognized by |
|---|---|
| Project VIC / CAID VICS JSON | any JSON with `MD5`, `SHA1` or `SHA256` keys; the `Category` of the media entry is kept |
| NSRL | `NSRLFile.txt` (legacy) or RDSv3 SQLite |
| plain list | one MD5, SHA-1 or SHA-256 per line |

## Known-file hash sets (`--known`)

Command: [`media`](Media). Files matching are set aside (operating system,
common apps). NSRL or a plain list.

No network call is made at analysis time: all sets are local files.
