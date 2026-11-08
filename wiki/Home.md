# APEX

**Android phone investigation and app security analysis, in one self-contained binary.**

APEX collects a phone's state over USB, without root, into a hashed case
directory, in under a minute with `--quick`. A small agent app is installed
for a few seconds to read what ADB cannot, then removed, and every change it
makes is recorded. It finds stalkerware and spyware,
rebuilds install / uninstall and traffic history, lists the identifiers needed
for legal requests, and, under a legal mandate, extracts communications, with
deleted records recovered where the databases allow it. It writes a timeline,
an HTML report and a French procès-verbal, and every case can be re-verified
and timestamped.

APEX does not bypass a lock screen, does not root the phone and does not
exploit anything. The reference scenario is a search where the phone is
unlocked by its owner's code. For a locked, broken or switched-off phone, a lab
tool makes a full file-system extraction under legal authority, and
[`apex import`](Import) reads it.

---

## Start here

| If you need to… | Read |
|---|---|
| Install APEX | [Installation](Installation) |
| Get a phone talking to APEX | [Connecting a phone](Connecting-a-Phone) |
| Run an examination during a search, step by step | [Field procedure](Field-Procedure) |
| Check what each command needs before running it | [Prerequisites](Prerequisites) |
| Fix a connection or command error | [Troubleshooting](Troubleshooting) |

## The commands

| Command | What it does | Needs a phone |
|---|---|---|
| [`device listen`](Device) | Wait for a phone, print the serials of the connected ones | yes |
| [`device list`](Device) | List the third-party apps installed | yes |
| [`device posture`](Device) | The phone's own security posture (boot, root signs, encryption, admins…) | yes |
| [`device scan`](Device) | Pull and analyze every third-party app | yes |
| [`device dump`](Device) | Pull the third-party APKs only | yes |
| [`device shell`](Device) | Run one raw shell command (debugging) | yes |
| [`device acquire`](Device-Acquire) | Forensic acquisition into a case directory, triage mode, mandate mode | yes |
| [`device capture`](Device-Capture) | Capture the conversation on screen: text of every screen, screenshots, transcript (under mandate) | yes |
| [`import`](Import) | Turn a lab's full file-system extraction into an APEX case | no |
| [`db`](Db) | One SQLite database with everything in a case, for SQL queries | no |
| [`export`](Export) | Lay a case out like a file-system extraction, for other tools | no |
| [`link`](Link) | What several exhibits have in common: numbers, accounts, wallets, Wi-Fi, apps | no |
| [`analyze`](Analyze) | Findings on a case or any directory of packages; STIX2 and hash sets | no |
| [`identifiers`](Identifiers) | IMEI, IMSI, ICCID, line, MACs, accounts, operators to request | no |
| [`comms`](Comms) | Export communications collected under mandate (SQLite, CSV, JSON, KML), decrypt WhatsApp and Signal backups | no |
| [`media`](Media) | Hash, EXIF / GPS, hash-set matching of shared storage | no |
| [`search`](Search) | Keyword / regex search over a whole case, entity extraction | no |
| [`timeline`](Timeline) | One chronological CSV / JSONL (Timesketch) | no |
| [`diff`](Diff) | What changed between two acquisitions of the same phone | no |
| [`report`](Report) | Self-contained HTML case report | no |
| [`pv`](PV) | French procès-verbal de constatations, one or several exhibits | no |
| [`seal`](Seal) | RFC 3161 trusted timestamp of a case (network) | no |
| [`verify`](Verify) | Re-hash a case and check its integrity and timestamp | no |
| [`scan`](Scan) | Static security analysis of one `.apk` / `.aab` / `.xapk` / `.ipa` | no |

## Key concepts

- **[Case directory](Case-Directory)**: what an acquisition or import writes, file by file.
- **[APEX agent](Agent)**: the small app installed for the acquisition, what it reads, and per-maker prerequisites.
- **[Evidence and integrity](Evidence-and-Integrity)**: audit log, manifest, `verify`, RFC 3161.
- **[Legal scope](Legal-Scope)**: what is collected by default, what needs `--mandate`, what is never collected.
- **[Communications and app data](Communications-and-App-Data)**: every source, live and from an extraction, and the keys they need.
- **[Deleted records](Deleted-Records)**: how SQLite write-ahead logs and free pages are carved.
- **[Findings](Findings)**: every finding ID and what it means, cyber findings included.
- **[Rules file](Rules-File)**: extend the built-in lists (phishing brands, vault apps, signatures…) with your own.
- **[Indicators and hash sets](Indicators-and-Hash-Sets)**: STIX2, Project VIC / CAID, NSRL.
- **[Accuracy and limits](Limits)**: what a finding proves and what it does not.

APEX makes no network call except [`seal`](Seal), which sends only a SHA-256.
