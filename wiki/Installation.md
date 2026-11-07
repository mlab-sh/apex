# Installation

APEX is one binary. It needs neither `adb`, the Android SDK, nor a system USB
library: it talks to the phone directly over USB (libusb is vendored and
statically linked).

## Homebrew (macOS and Linux)

```sh
brew tap mlab-sh/apex https://github.com/mlab-sh/apex.git
brew install apex
```

## Prebuilt binaries

Download the tarball for your platform from the
[latest release](https://github.com/mlab-sh/apex/releases/latest)
(macOS x86_64 / arm64, Linux x86_64 / arm64):

```sh
tar -xzf apex-*-<target>.tar.gz && sudo mv apex-*/apex /usr/local/bin/
apex --version
```

## From source

**Prerequisites**

| Tool | Why |
|---|---|
| Rust toolchain (stable, `cargo`) | builds APEX |
| A C compiler (Xcode Command Line Tools on macOS, `build-essential` on Debian / Ubuntu) | libusb, SQLite / SQLCipher |
| `perl` and `make` | build the vendored OpenSSL that SQLCipher uses (Signal databases) |

```sh
git clone https://github.com/mlab-sh/apex.git && cd apex
cargo build --release          # binary at target/release/apex
cargo test --release           # optional
```

The first build compiles OpenSSL and takes a few minutes; later builds are
incremental.

## Check which `apex` runs

An older `apex` installed elsewhere (another Homebrew tap, `~/.cargo/bin`) can
shadow the one you just built:

```sh
which -a apex       # every apex on the PATH, first one wins
apex --version      # must print the version you expect
```

Use the full path (`./target/release/apex`) or remove the old binary.

## Platform notes

**macOS.** Nothing else to install. Stop any running `adb` server before
using APEX (`adb kill-server`): it holds the phone's USB interface.

**Linux.** A normal user cannot open USB devices without a udev rule. Install
your distribution's Android rules (`android-udev-rules` on Arch / Debian /
Ubuntu, or `android-tools` on Fedora), add yourself to the group they use
(`plugdev` or `adbusers`), then log out and back in. Without them APEX finds
no phone, or the connection fails with a permission error. Stop any running
`adb` server too.

**Windows.** Not built or tested.

## Optional data

| Data | Used by | Where to get it |
|---|---|---|
| STIX2 indicator bundles | `analyze`, `report`, `diff`, `pv` (`--iocs`) | Echap's [`generated/stalkerware.stix2`](https://github.com/AssoEchap/stalkerware-indicators/tree/master/generated), MVT / Amnesty indicator files, your own |
| Alert hash sets | `media`, `analyze`, `report`, `pv` (`--hashes`) | Project VIC / CAID (VICS JSON), via your agency |
| Known-file hash sets | `media` (`--known`) | NSRL (`NSRLFile.txt` or RDSv3 SQLite) |

The Echap stalkerware package names and certificates are already built in.
See [Indicators and hash sets](Indicators-and-Hash-Sets).
