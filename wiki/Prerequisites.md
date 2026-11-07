# Prerequisites per command

What must be true before each command can run, and what it produces. A
"case" is a directory written by [`device acquire`](Device-Acquire) or
[`import`](Import).

## Commands that need the phone

All of them need: the phone **connected over USB** (or `--tcp`), **USB
debugging on**, the computer **authorized** on the phone, no `adb` server
running on the computer. See [Connecting a phone](Connecting-a-Phone).

| Command | Phone unlocked | Mandate | Other requirement | Writes |
|---|---|---|---|---|
| `device listen` | for the first authorization | no | — | nothing |
| `device list` | recommended | no | — | nothing (terminal) |
| `device posture` | recommended | no | — | terminal; JSON with `--json -o`; bundle with `--evidence` |
| `device scan` | recommended | no | — | terminal; JSON per app with `--json`; bundle with `--evidence` |
| `device dump` | recommended | no | — | `./apex_dump/` (APKs + device info) |
| `device shell` | recommended | no | — | terminal |
| `device acquire` | **yes, for the whole run** | for `--mandate`, `--notification-content` | free disk space: ~1–2 GB, more with `--storage`; `--backup`: someone to confirm on the phone | case directory (`./apex_acquire` by default) |
| `device acquire --triage` | yes | no | — | case directory, ≈ 10 s |
| `device acquire --quick` | yes | as above | the [agent](Agent): Xiaomi needs *Install via USB* + *USB debugging (Security settings)* | case directory, ≈ 40–60 s |
| `device capture` | **yes**, conversation open on screen | **required** | simulated touches allowed (Xiaomi: *USB debugging (Security settings)*); nobody touches the phone | capture directory (`./apex_capture`): screenshots, `transcript.txt`, `capture.db` |

## Commands that work offline

No phone, no network (except `seal`).

| Command | Input | Requirement on the input | Writes (default) |
|---|---|---|---|
| `import` | extraction: directory, `.zip`, `.tar`, `.tar.gz` | must contain `data/system/packages.xml`; app data needs an **after-first-unlock** extraction; `--mandate` to copy communications and app data, `--storage` for `data/media/0` | case directory (`-o` required) |
| `analyze` | case, any directory of packages, or one package | — | terminal; `--json -o`; `--evidence <dir>` |
| `db` | case (+ capture directories) | — (agent tables filled only if the agent ran) | `<case>.db` |
| `identifiers` | case | best with a full or triage acquisition (telephony identifiers come from `iphonesubinfo`) | terminal; `--json -o` |
| `comms` | case | acquired or imported **with `--mandate`**; keys for Signal / WhatsApp backups, see [Communications and app data](Communications-and-App-Data#keys) | `<case>_comms/`: `comms.db`, `comms.csv`, `comms.json`, `locations.kml`, `signal_files/` |
| `media` | case | acquired or imported **with `--storage`** | `<case>_media/` |
| `search` | case | — (communications are searched only if collected under mandate) | terminal; `<case>_search/` |
| `timeline` | case | — | `<case>/timeline.csv` (use `-o` outside the case) |
| `diff` | two cases | the same phone (a different serial is reported) | terminal; `--json -o` |
| `report` | case | — | `<case>/report.html` (use `-o` outside the case) |
| `pv` | one or more cases | — | `./pv.html` |
| `seal` | case | **the computer online**, a Time-Stamping Authority URL | `manifest.json.tsq`, `manifest.json.tsr` in the case |
| `verify` | case or bundle | `manifest.json` and `manifest.json.sha256` present | terminal; exit 0 = verified, 1 = not |
| `scan` | `.apk`, `.aab`, `.xapk`, `.ipa` | — | terminal; `--json -o` |

## Optional inputs

| Option | Commands | File |
|---|---|---|
| `--iocs <file>` (repeatable) | `analyze`, `report`, `diff`, `pv` | STIX 2.x bundle |
| `--hashes <file>` (repeatable) | `analyze`, `media`, `report`, `pv` | VICS JSON, NSRL, or one hash per line |
| `--known <file>` (repeatable) | `media` | NSRL or one hash per line |
| `--packages <file>` | `analyze` | newline-separated package names |
| `--signal-key <hex>` | `comms` | Signal database secret (from a lab) |
| `--wa-key <hex>` | `comms` | WhatsApp 64-digit end-to-end backup key |
| `--signal-passphrase <digits>` | `comms` | the 30 digits Signal shows when chat backups are turned on |
| `--phone-change <text>` (repeatable) | `device acquire`, `device capture`, `device posture`, `device scan`, `import`, `analyze` | a change you made to the phone, with its time; goes in the manifest and the PV |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | error, nothing to do (`comms` without communications), `verify` failed, `listen --timeout` expired, or `--fail-on` threshold reached |
