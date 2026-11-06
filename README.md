# APEX (Rust)

> ⚠️ **Beta software.** APEX is under active development. Findings, the JSON
> schema, CLI flags, and the on-device (ADB) features may change without notice,
> and false positives/negatives are expected. Do not rely on it as your sole
> security gate yet. Feedback and bug reports welcome.

<p align="center">
  <img src=".github/banner.png" alt="APEX" width="100%">
</p>

Static analysis for Android/iOS packages (`.apk`, `.aab`, `.xapk`, `.ipa`) 
Extracts the package, runs 15 analyzers, and reports security findings with a weighted score.

## Install

### Homebrew (macOS & Linux)

```sh
brew tap mlab-sh/apex https://github.com/mlab-sh/apex.git
brew install apex
```

### Prebuilt binaries

Grab a tarball for your platform from the
[latest release](https://github.com/mlab-sh/apex/releases/latest) — available
for macOS (x86_64, arm64) and Linux (x86_64, arm64) — then:

```sh
tar -xzf apex-*-<target>.tar.gz && sudo mv apex-*/apex /usr/local/bin/
```

### From source

```sh
cargo build --release   # binary at target/release/apex
```

Requires a Rust toolchain and a C compiler (libusb is vendored & statically
linked for the ADB features, so the binary is self-contained).

## Usage

```sh
apex scan path/to/app.apk            # formatted terminal report (default)
apex scan path/to/app.apk --json     # also print JSON and write <stem>_report.json
apex scan path/to/app.apk --json -o report.json
apex scan path/to/app.apk --fail-on high   # exit 1 if any finding >= high (CI/CD)
apex --version
```

Flags:

- `--show` — formatted terminal output (implied when no other output flag).
- `--json` — emit the JSON report (and write it to a file).
- `-o, --output <PATH>` — JSON output path (default `<stem>_report.json`).
- `--detail` — print the proof/evidence (description + metadata) under each finding.
- `--fail-on <critical|high|medium|low|info>` — non-zero exit for CI when a
  finding at that severity or above is present.

## Analyze an existing extraction (offline, no device)

Seized phones usually have USB debugging **off** and a locked screen, so live
ADB isn't an option — investigators work from an extraction that already exists.
`apex analyze` runs the full static pipeline over a directory tree of package
files, no device required:

```sh
apex analyze ./extraction                    # recurse, scan every .apk/.aab/.xapk/.ipa
apex analyze ./extraction --detail
apex analyze ./extraction --evidence ./case  # + hashed, chain-of-custody manifest
apex analyze ./extraction --packages installed.txt   # also match an app list vs stalkerware
apex analyze ./extraction --json -o reports/ --fail-on high
apex analyze ./case-42 --iocs stalkerware.stix2 --iocs pegasus.stix2   # STIX2 IOC matching
```

Every APK is also checked against the bundled **stalkerware signing
certificates** (Echap), which catches renamed or repackaged builds that the
package-name match misses.

### Investigating a `device acquire` case

When the path is a case directory written by `apex device acquire`, `analyze`
adds an **Investigation** section built from the collected artifacts:

- **Stalkerware capability profile** per user-installed app: accessibility
  service, device admin, notification listener, no launcher icon, installed
  outside a known store, sensitive permissions actually used. Combined into a
  score, so a renamed stalkerware still stands out.
- **Hidden apps**: user-installed apps without a launcher icon.
- **Sensitive permission use**: when each app last used the microphone,
  camera, location, SMS, call log, contacts, screen capture… (from
  `dumpsys appops`, device-local time).
- **IOC matches** (`--iocs`, STIX 2.x, repeatable): package names, APK
  SHA-256/SHA-1/MD5, signing-certificate SHA-1, and domains / IPs / URLs found
  anywhere in the collected text, including inside `bugreport.zip`. Subdomains
  match their listed parent. Works with Echap's
  [`generated/stalkerware.stix2`](https://github.com/AssoEchap/stalkerware-indicators/tree/master/generated)
  and MVT-style IOC files.
- **Clock skew** between the phone and the examiner's machine.

`--json` / `--evidence` also write `case_report.json`.

### Timeline (`apex timeline`)

```sh
apex timeline ./case-42                     # → ./case-42/timeline.csv
apex timeline ./case-42 -o timeline.jsonl   # JSONL instead of CSV
```

Merges app install/update times, app-op accesses (mic, camera, location…),
usage-stats events and logcat into one chronologically sorted file with the
Timesketch columns (`datetime,timestamp_desc,source,package,message`). Times
carry the device's UTC offset read at acquisition (`device/clock.txt`). Writing
the timeline inside the case adds a file that `apex verify` will list as
unlisted; pass `-o` elsewhere to keep the bundle untouched.

It prints a per-package report, an **extraction-wide severity summary**, a
**top-risk triage table** (worst packages first, stalkerware flagged), and the
list of stalkerware/spyware indicator matches (by declared package name, and
from an optional `--packages` installed-apps list). With `--evidence` it writes
an offline bundle whose `manifest.json` hashes every input file and every report
(see *Forensic evidence bundle* below). It reads a directory tree of package
files — unpack a proprietary container (e.g. Cellebrite UFDR) first.

## Scan a phone over USB (ADB)

Connect an Android phone in USB-debugging mode (authorize the RSA prompt), then:

```sh
apex device list                       # list installed third-party (non-system) apps
apex device posture                    # assess the device's own security posture
apex device scan                       # pull + scan every third-party app
apex device scan --package com.foo.bar # scan a single package
apex device scan --json -o reports/    # write <package>_report.json per app
apex device scan --detail --fail-on high
apex device shell "getprop ro.build.version.sdk"   # raw shell passthrough (power-user)
```

Uses `adb_client`'s `ADBUSBDevice` for a direct USB connection (no `adb`
server required). `pm list packages -3` enumerates non-system packages,
`pm path` resolves each base APK, which is pulled to a temp dir and run through
the same analyzers as `apex scan`. Options: `--adb-key <PATH>` for a custom ADB
private key (default `~/.android/adbkey`, created on first use so the phone
only asks to authorize once; tick "Always allow"), plus `--json`/`-o`/`--detail`/`--fail-on`.

Everything on-device runs over a **non-root** ADB shell; the few checks that
benefit from root degrade gracefully when the data is unreadable.

### `device acquire` — forensic acquisition

Collects a structured, hashed extraction for offline analysis (feed it back to
`apex analyze`). Non-root and read-only; every artifact is recorded in the
evidence bundle.

```sh
apex device acquire -o ./case-42
apex device acquire --package com.foo.bar -o ./case-42
apex device acquire --no-logcat --no-usagestats -o ./case-42   # skip the large captures
apex device acquire --no-bugreport -o ./case-42   # skip the full bugreport (1-5 min)
```

Output layout:

```
case-42/
  device/   clock.txt (device time + UTC offset), getprop, identifiers.json
            (serial, android_id, fingerprint, ABI…), packages.txt (pm list -f -i -u),
            usagestats.txt (app-usage timeline), appops.txt (permission-use history),
            launcher_activities.txt (to spot hidden apps), settings_{secure,global,system}.txt,
            accounts.txt, wifi.txt, bluetooth.txt, device_policy.txt, logcat.txt,
            bugreport.zip (full dumpstate: every dumpsys, tombstones/ANRs, battery history)
  apps/<pkg>/  base.apk + every split_config.*.apk, dumpsys_package.txt
  manifest.json / manifest.json.sha256 / audit.jsonl
```

Deliberately **out of scope** (do not improvise these): SMS/MMS, call logs and
contacts (privacy-sensitive, legally governed), and app-private data under
`/data/data` (requires root). Use a validated, warrant-appropriate acquisition
tool for those.

### `device posture` — device hardening & privacy

Where `scan` inspects *apps*, `posture` inspects the *device*: it flags weak
device configuration and abuse vectors, scored with the same weighted model as
a package scan. Checks include Verified Boot / bootloader lock state, SELinux
mode, root indicators, storage encryption, **security-patch age**, developer
options / ADB / mock-location, a global HTTP proxy (AiTM interception point),
enabled accessibility services and notification listeners (the most-abused
capabilities), active device-administrator apps, and installed **stalkerware**
(exact package-name match against the
[Echap indicator set](https://github.com/AssoEchap/stalkerware-indicators)).
Property-based signals (verified boot, root) are best-effort — they can be
spoofed — so they are reported as indicators, not attestation. Supports
`--json`/`-o`/`--detail`/`--fail-on`.

### Forensic evidence bundle (`--evidence <dir>`)

`device posture` and `device scan` accept `--evidence <dir>` to write a
tamper-evident record alongside the report, for investigative / chain-of-custody
use:

- `audit.jsonl` — every ADB action taken, in order, each with a **UTC
  timestamp**, the **SHA-256** of its raw output, byte count and duration.
- `manifest.json` — tool name/version, session start/end (UTC), device
  identifiers (model, serial, build fingerprint), the SHA-256 of every acquired
  artifact (pulled APKs) and of every report, and an explicit **methodology /
  alteration statement** describing what a live ADB acquisition touches.
- `manifest.json.sha256` — detached hash so the whole bundle is verifiable.

```sh
apex device posture --evidence ./case-42
apex device scan --evidence ./case-42
```

This documents and hashes exactly what APEX did; it is **not** a forensic image
and captures no app-private data, deleted content, or physical/file-system dump —
use a validated acquisition tool for evidential imaging.

### Verify a bundle (`apex verify`)

Re-checks an evidence bundle (from `device posture/scan/acquire` or offline
`analyze`) and confirms nothing changed since acquisition — recomputes the
manifest's own hash and re-hashes every file, matching by hash so it survives
the bundle being moved:

```sh
apex verify ./case-42            # exit 0 = VERIFIED, exit 1 = tampered/incomplete
```

It reports matched artifacts, any **recorded-but-missing/altered** files
(integrity failure), extra files not in the manifest, and — for offline bundles
— the external source inputs it can't re-check from the bundle alone.

### Runtime enrichment in `device scan`

Static analysis reports what an app *requests*; on device, `scan` additionally
reports what is *actually granted / active* — parsed from `dumpsys package` and
`appops`: permissions **granted** (not merely requested), install source
(sideloaded vs a known store), the `DEBUGGABLE`/`TEST_ONLY` runtime flags, and
high-risk app-ops (draw-over-other-apps overlay, all-files access, silent
install). A scanned package that matches the stalkerware set is flagged
`critical`. These findings carry the `runtime` category and fold into the app's
score alongside the static ones; pass `--no-runtime` to disable.

## Analyzers

`manifest`, `certificate`, `network`, `sast`, `api`, `permissions`, `binary`
(ELF checksec), `secrets` (+ entropy), `jar_aar`, `dataflow`, `cloud`,
`privacy`, `binary_advanced`, `platform`, `supply_chain`.

Binary manifests are decoded with `axmldecoder`, native libraries with
`goblin`, and APK signatures / X.509 certificates with the RustCrypto `cms` /
`x509-cert` stack. Output (findings, security score, JSON schema) matches the
Python reference implementation, with one additive enrichment: findings whose
detected capability maps to an adversary technique also carry a `mitre` field
(**MITRE ATT&CK for Mobile** technique id, e.g. `T1430`, `T1636.003`,
`T1638`) so SOCs can pivot straight into ATT&CK. The mapping lives in one
auditable table (`default_mitre` in [src/models.rs](src/models.rs)); control
weaknesses with no clean technique equivalent are left untagged rather than
force-mapped. Shown next to CWE/MASVS under `--detail`.

The `privacy` analyzer classifies detected third-party trackers with the
**Exodus Privacy** taxonomy (analytics / advertising / identification /
profiling / crash-reporting / push). The advertising, identification
(cross-app attribution) and profiling (session-replay) classes are surfaced as
`high_risk` in the `PRIV_TRACKERS` metadata — that's where the GDPR/CCPA
exposure sits — and the presence of a session-replay tracker escalates the
finding to `high`. The on-device / offline stalkerware check matches installed packages against a
bundled indicator set (exact package name) sourced from the
[Echap `stalkerware-indicators`](https://github.com/AssoEchap/stalkerware-indicators)
project; refresh it with `scripts/update-iocs.sh` as the upstream list evolves.

Classifications are a bundled, offline table (no network
call at scan time) covering the SDKs APEX fingerprints; extending it to the
full Exodus corpus (network signatures, ~450 trackers) is the natural next
step. Static analysis reports which ad/tracking SDKs are *embedded* — proving
which are actually *contacted at runtime* needs dynamic analysis.

## Releasing / building for all platforms

Prebuilt binaries are produced by the `Release` GitHub Actions workflow
([.github/workflows/release.yml](.github/workflows/release.yml)), triggered
manually (`workflow_dispatch`). It:

1. runs `cargo test` as a gate,
2. builds a matrix of **macOS (x86_64, arm64)** and **Linux (x86_64, arm64)**,
3. packages each as `apex-<version>-<target>.tar.gz` (binary + LICENSE + README),
4. computes sha256, regenerates [`Formula/apex.rb`](Formula/apex.rb), commits it,
   and publishes a GitHub Release with the tarballs.

To build/package locally (mirrors the CI):

```sh
scripts/build-release.sh            # host target
scripts/build-release.sh --all      # all four release targets (needs toolchains)
```

libusb is compiled from vendored C sources and statically linked, so the
resulting binaries have no external libusb/udev dependency.
