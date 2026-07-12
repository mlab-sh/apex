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

## Scan a phone over USB (ADB)

Connect an Android phone in USB-debugging mode (authorize the RSA prompt), then:

```sh
apex device list                       # list installed third-party (non-system) apps
apex device scan                       # pull + scan every third-party app
apex device scan --package com.foo.bar # scan a single package
apex device scan --json -o reports/    # write <package>_report.json per app
apex device scan --detail --fail-on high
```

Uses `adb_client`'s `ADBUSBDevice` for a direct USB connection (no `adb`
server required). `pm list packages -3` enumerates non-system packages,
`pm path` resolves each base APK, which is pulled to a temp dir and run through
the same analyzers as `apex scan`. Options: `--adb-key <PATH>` for a custom ADB
private key (default `~/.android/adbkey`), plus `--json`/`-o`/`--detail`/`--fail-on`.

## Analyzers

`manifest`, `certificate`, `network`, `sast`, `api`, `permissions`, `binary`
(ELF checksec), `secrets` (+ entropy), `jar_aar`, `dataflow`, `cloud`,
`privacy`, `binary_advanced`, `platform`, `supply_chain`.

Binary manifests are decoded with `axmldecoder`, native libraries with
`goblin`, and APK signatures / X.509 certificates with the RustCrypto `cms` /
`x509-cert` stack. Output (findings, security score, JSON schema) matches the
Python reference implementation.

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
