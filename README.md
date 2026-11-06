# APEX

<p align="center">
  <img src=".github/banner.png" alt="APEX" width="100%">
</p>

Android security analysis and phone investigation, in one self-contained binary.

- **Static analysis** of app packages (`.apk`, `.aab`, `.xapk`): 15 analyzers,
  weighted security score, CWE / MASVS / MITRE ATT&CK for Mobile tags, JSON
  output and a CI gate.
- **Phone investigation** over USB or the network, no root: hashed forensic
  acquisition, stalkerware and spyware detection, STIX2 indicator matching,
  install / uninstall and traffic history, a unified timeline, a diff between
  two acquisitions, an HTML case report, and a verifiable chain-of-custody
  bundle.
- **Seized phones**: remote-wipe alert on connection, an identifiers sheet for
  legal requests (IMEI, IMSI, ICCID, line number, MACs, accounts), and import
  of full file-system extractions made by lab tools, so phones APEX cannot
  connect to (locked, broken) get the same analysis.

## Install

### Homebrew (macOS & Linux)

```sh
brew tap mlab-sh/apex https://github.com/mlab-sh/apex.git
brew install apex
```

### Prebuilt binaries

Grab a tarball for your platform from the
[latest release](https://github.com/mlab-sh/apex/releases/latest) (macOS
x86_64/arm64, Linux x86_64/arm64), then:

```sh
tar -xzf apex-*-<target>.tar.gz && sudo mv apex-*/apex /usr/local/bin/
```

### From source

```sh
cargo build --release   # binary at target/release/apex
```

Requires a Rust toolchain and a C compiler. libusb is vendored and statically
linked, so the binary needs neither `adb` nor any system USB library.

## Investigate a phone in five commands

```sh
apex device acquire -o ./case-42 --case-id 2026-042 --examiner "J. Doe"  # 1. collect (USB, ~5-7 min)
apex analyze ./case-42 --iocs stalkerware.stix2 --detail # 2. findings
apex timeline ./case-42 -o ./case-42-timeline.csv        # 3. timeline (Timesketch)
apex report ./case-42 --iocs stalkerware.stix2 -o case-42.html   # 4. HTML report
apex verify ./case-42                                    # 5. integrity check
```

`stalkerware.stix2` is Echap's
[`generated/stalkerware.stix2`](https://github.com/AssoEchap/stalkerware-indicators/tree/master/generated);
any STIX 2.x indicator bundle works (MVT / Amnesty, your own).

## Seized phones

**Remote wipe.** `device acquire`, `posture` and `scan` check first, before
anything slow, whether the phone can be erased remotely: a find-my-device
service with its account signed in (Google, Xiaomi, Samsung, Huawei, OPPO /
OnePlus), an MDM device or profile owner, an active device admin. They print a
red alert and say whether the phone is online, so it can be isolated
(airplane mode, Faraday bag) at once. The same check is a finding,
`CASE_REMOTE_WIPE`, in offline analysis.

**Identifiers for legal requests.**

```sh
apex identifiers ./case-42          # terminal sheet
apex identifiers ./case-42 --json -o identifiers.json
```

Device (manufacturer, model, name, serial, Android ID, build), telephony
(IMEI, IMSI, ICCID, line number, SIM and network operator), network (factory
Wi-Fi MAC, Bluetooth MAC and name), and every account on the phone with the
service a request goes to (Google, WhatsApp, Instagram / Threads user IDs,
Telegram, Samsung, Xiaomi…). Telephony identifiers come from the read-only
getters of `service call iphonesubinfo`, classified host-side (Luhn check for
IMEI, SIM MCC/MNC prefix for IMSI). The sheet is also in the HTML report.

**Full file-system extractions.** A locked, broken or switched-off phone is
extracted with a lab tool under the appropriate legal authority; APEX does not
bypass locks. `apex import` turns that extraction into an APEX case:

```sh
apex import ./extraction.zip -o ./case-42 --case-id 2026-042 --examiner "J. Doe"
apex analyze ./case-42 && apex timeline ./case-42 && apex report ./case-42
```

It accepts a directory, `.zip`, `.tar` or `.tar.gz`, finds the Android root
(`data/system/packages.xml`) whatever the prefix, and reads system XML in
text or binary form (ABX, Android 12+). From the extraction it rebuilds:
packages with installer, install / update times and system flag; users, work
profile and per-user apps; settings; accounts (`accounts_ce.db` /
`accounts_de.db`); device admins and owners; the package manager log
(uninstalls and who did them); saved Wi-Fi networks (names and security, never
passwords); Bluetooth adapter and paired devices; time zone and build
properties; file listings of `/data/local/tmp` and shared storage; and every
APK under `data/app`. The extraction is only read; each source file used is
hashed into the manifest, and each file produced too, so `apex verify` works.

Not read from an extraction yet: app-ops and usage-stats history (binary
formats), network statistics, and communications databases. Accounts need an
after-first-unlock extraction (they are credential-encrypted).

## Connecting a phone

1. On the phone: enable **Developer options**, then **USB debugging**.
2. Plug it in and run any `apex device` command.
3. Unlock the phone and accept **Allow USB debugging?**, ticking **Always
   allow**. APEX creates its key at `~/.android/adbkey` on first use (the same
   path as `adb`), so the prompt appears only once. If the phone has not
   answered after a few seconds, APEX says it is waiting for it.

APEX talks to the phone directly over USB (`adb_client`); no `adb` server is
needed. Everything runs as the non-root `shell` user.

Several phones plugged in: `apex device listen` prints their serials; pick one
with `--serial <SERIAL>`. Over the network: after `adb tcpip 5555` on the
phone, use `--tcp 192.168.1.20` (port 5555 by default). This is the legacy,
unencrypted ADB-over-TCP: use it on a network you control. Android 11+
"Wireless debugging" (TLS pairing) is not supported.

```sh
apex device listen                     # wait until a phone is plugged in
apex device list                       # installed third-party apps
apex device posture                    # the phone's own security posture
apex device scan                       # pull + scan every third-party app
apex device scan --package com.foo.bar
apex device acquire -o ./case-42       # forensic acquisition (below)
apex device dump -o ./apks             # just pull the third-party APKs
apex device shell "getprop ro.build.version.sdk"   # raw shell, for debugging
```

Common options: `--adb-key <PATH>`, `--serial <SERIAL>`, `--tcp <HOST[:PORT]>`,
`--json`, `-o`, `--detail`, `--fail-on <severity>`, `--evidence <dir>`.

Case metadata (`posture`, `scan`, `acquire`, and `analyze`): `--case-id`,
`--examiner`, `--case-notes`. They go into the evidence manifest and the HTML
report.

### `device posture`

Inspects the device rather than its apps: Verified Boot and bootloader lock,
SELinux mode, root indicators, storage encryption, security-patch age,
developer options / ADB / mock location, global HTTP proxy, enabled
accessibility services and notification listeners, device-admin apps, and
known stalkerware. Root and verified-boot signals come from system properties,
which a determined attacker can spoof: they are indicators, not attestation.

### `device scan`

Pulls each third-party APK, runs the static analyzers, and adds what is
actually active on the phone: permissions **granted** (not only requested),
install source, `DEBUGGABLE` / `TEST_ONLY` flags, and risky app-ops (overlay,
all-files access, installing other apps). `--no-runtime` turns this off.

### `device acquire`

Collects everything below into a case directory, hashes every file, and writes
the evidence bundle (`manifest.json`, `manifest.json.sha256`, `audit.jsonl`).

```sh
apex device acquire -o ./case-42
apex device acquire --package com.foo.bar -o ./case-42   # one app only
apex device acquire --no-bugreport --no-logcat --no-usagestats -o ./case-42   # fast
apex device acquire --no-screenshot -o ./case-42
apex device acquire --notification-content -o ./case-42  # unredacted notifications
```

```
case-42/
  device/
    clock.txt              device time + UTC offset (read first, for clock skew)
    processes.txt          ps -A
    proc_exe.txt           real executable of each shell-user process (/proc/PID/exe)
    net_sockets.txt        /proc/net/{tcp,tcp6,udp,udp6}
    local_tmp.txt          ls -laR /data/local/tmp
    screen.png             screenshot at acquisition time
    accounts.txt, device_policy.txt, connectivity.txt   read first, for the remote-wipe alert
    iphonesubinfo.txt      IMEI / IMSI / ICCID / line number (read-only getters)
    getprop.txt, identifiers.json
    packages.txt           pm list packages -f -i -u (path, installer)
    packages_{3,system,uid}.txt
    users.txt              pm list users (work profile, secondary users, clone space)
    packages_3_user<N>.txt third-party apps of each other user
    package_messages.txt   package manager log: first boot, uninstalls and who did them
    appops.txt             permission use history
    launcher_activities.txt
    settings_{secure,global,system}.txt
    usagestats.txt, logcat.txt
    netstats.txt           per-app traffic history (weeks), dumpsys netstats --full --uid
    activity_{services,recents,broadcasts}.txt, dbinfo.txt,
    notification.txt, jobscheduler.txt, alarm.txt, role.txt, input_method.txt,
    connectivity.txt, vpn_management.txt, camera.txt, audio.txt, location.txt,
    wifi.txt, wifi_networks.txt, bluetooth.txt
    sdcard_listing.txt     ls -laR of shared storage (metadata only)
    bugreport.zip          full dumpstate: every dumpsys, tombstones, ANRs, battery history
  apps/<pkg>/              base.apk + every split APK, dumpsys_package.txt
                           (apps only installed in another user are acquired too)
  manifest.json, manifest.json.sha256, audit.jsonl
```

**What acquisition changes on the phone.** It is a live acquisition: the shell
session itself creates processes and log lines. Beyond that, APEX writes in
two places only. `bugreportz` leaves its zip in the shell user's bugreports
directory. The screenshot is written to `/data/local/tmp/apex_screen.png`,
pulled, then deleted. Both show in `audit.jsonl` and in the manifest's
methodology statement; `--no-bugreport` and `--no-screenshot` avoid them.

**Out of scope, on purpose.** SMS/MMS, call logs, contacts and notification
*content* are legally sensitive: notifications are captured redacted unless
you pass `--notification-content` under an appropriate mandate. App-private
data (`/data/data`) and user-installed CA certificates need root and are not
collected. This is not a forensic image: use a validated imaging tool for
deleted content or full file systems.

## Analyze offline

`apex analyze` works without a device, on an acquisition or on any directory of
packages (for example an extraction made with another tool; unpack proprietary
containers such as Cellebrite UFDR first).

```sh
apex analyze ./case-42                                   # acquisition dir
apex analyze ./extraction                                # any dir of packages
apex analyze ./case-42 --iocs stalkerware.stix2 --iocs pegasus.stix2
apex analyze ./extraction --packages installed.txt       # match an app list vs stalkerware
apex analyze ./case-42 --json -o reports/ --evidence ./case-42-report --fail-on high
```

It scans every package in parallel, prints a report per package, then an
**Investigation** section (for acquisitions) or **IOC matching** section, a
severity summary, and a top-risk table. `--json` and `--evidence` also write
`case_report.json`; `--evidence` writes an offline bundle hashing every input
and report.

### Investigation findings

| ID | What it means |
|---|---|
| `DEV_STALKERWARE`, `PKG_STALKERWARE` | Package name matches the Echap stalkerware set |
| `PKG_STALKERWARE_CERT` | APK signed with a known stalkerware certificate (catches renamed builds) |
| `IOC_MATCH` | A STIX2 indicator matched: package, APK hash, signing cert, or a domain / IP / URL in collected text, `bugreport.zip` or live sockets |
| `CASE_STALKERWARE_PROFILE` | An app combines accessibility, device admin, notification access, no icon, sideload, sensitive permission use |
| `CASE_HIDDEN_APP` | Third-party app with no launcher icon |
| `CASE_SENSITIVE_USE` | When each app last used the mic, camera, location, SMS, call log, contacts, screen capture… |
| `CASE_SYSTEM_IMPERSONATION` | Sideloaded app using a platform / OEM package name |
| `CASE_UNINSTALLED_DATA_KEPT` | Apps removed with their data kept (`pm uninstall -k`) |
| `CASE_ROLE_HOLDER` | Third-party app is the SMS / phone / call-screening / assistant / browser / launcher app |
| `CASE_THIRD_PARTY_KEYBOARD` | Third-party keyboard enabled (sees everything typed) |
| `CASE_ALWAYS_ON_VPN`, `CASE_VPN_ACTIVE`, `CASE_PRIVATE_DNS` | Something can see or redirect all traffic |
| `CASE_NET_CONNECTIONS`, `CASE_APP_LISTENING` | Open sockets per app; user apps reachable from the network |
| `CASE_STAGING_PROCESS` | Process running from `/data/local/tmp` or shared storage, or from a binary deleted after launch. Uses the real executable (`/proc/PID/exe`), so a disguised `argv` does not hide it |
| `CASE_LOCAL_TMP_FILES` | Files left in `/data/local/tmp`, where adb-pushed tools are staged |
| `CASE_APK_ON_STORAGE` | APK files on shared storage (sideloading traces) |
| `CASE_WIFI_SAVED`, `CASE_BT_BONDED`, `CASE_BT_TRACKER` | Saved networks, paired devices, item trackers |
| `CASE_CLOCK_SKEW` | Phone clock differs from the examiner's clock |
| `CASE_USER_PROFILE` | Another user exists: work profile (its admin sees the profile's apps and traffic), secondary user, guest, clone space |
| `CASE_PROFILE_ONLY_APP` | App installed only in another user, so absent from the owner's app list |
| `CASE_STALKERWARE_REMOVED` | A known stalkerware package was installed, then uninstalled (date and who removed it) |
| `CASE_UNINSTALL_BY_UNUSUAL_CALLER` | An app was removed over adb or by another user app, not by the launcher, settings or a store |
| `CASE_APPS_REMOVED` | Every app uninstalled and no longer on the phone, with date and caller |
| `CASE_FIRST_BOOT` | When the phone was set up or last factory reset: nothing older survives |
| `CASE_NET_USAGE` | Traffic per user app (received / sent) over the period the system keeps |
| `CASE_REMOTE_WIPE` | A find-my-device service, an MDM or a device admin can erase the phone remotely |
| `CASE_BACKGROUND_UPLOAD` | A user app sent more than 20 MB in the background, more than it received |

Install and uninstall history comes from the package manager log
(`package_messages.txt`) and the battery history inside `bugreport.zip`, which
go back weeks to months, far beyond logcat.

"Sideloaded" means installed through a package-installer UI, by another user
app, or over adb. Preloads installed by system or OEM components are not.

## Timeline

```sh
apex timeline ./case-42                     # → ./case-42/timeline.csv
apex timeline ./case-42 -o timeline.jsonl   # JSONL
```

One chronologically sorted file with the Timesketch columns
(`datetime,timestamp_desc,source,package,message`), built from app install /
update times, installs and uninstalls (package manager log, battery history),
uploads over 1 MB per app and period (netstats), app-op accesses, usage
events, logcat, camera service events, post times of the notifications active
at acquisition, and file modification times. Each timestamp carries
the UTC offset in force at that moment in the phone's time zone, so summer
and winter times are both right. Writing the timeline inside the case adds a
file `apex verify` reports as unlisted; use `-o` elsewhere to leave the bundle
untouched.

## Diff between two acquisitions

```sh
apex diff ./case-42 ./case-57                 # what changed on the phone
apex diff ./case-42 ./case-57 --json -o diff.json
```

Compares two acquisitions of the same phone, for example before and after it
was out of the owner's hands, or a periodic check:

- device identity (a different serial means a different phone), Android
  version and security patch;
- third-party apps added and removed; per app, installer and version changes,
  and a **signing certificate change** (the same package rebuilt and signed
  by someone else);
- users and profiles; apps gaining or losing accessibility, device admin or
  notification access;
- sensitive settings (ADB, developer options, unknown sources, Play Protect,
  private DNS, proxy, always-on VPN, keyboard);
- investigation findings that appeared or disappeared.

When one case lacks artifacts the other has (an acquisition made with
`--no-bugreport`, say), `diff` says so: findings based on them are not
comparable.

## HTML report

```sh
apex report ./case-42 --iocs stalkerware.stix2           # → ./case-42/report.html
apex report ./case-42 -o case-42.html
```

One self-contained HTML file (no external resources; prints cleanly) for a
case file or a non-technical reader: case and examiner, device, acquisition
times, clock skew, transport, integrity check result, investigation findings
by severity with their evidence, user-installed apps (installer, sideloaded,
hidden, privileges, users, traffic), users and profiles, and the methodology
statement. Writing it inside the case adds a file that `apex verify` reports
as unlisted; use `-o` elsewhere to leave the bundle untouched.

## Evidence bundle and verification

Every device command and offline `analyze --evidence` writes:

- `audit.jsonl`: every ADB action in order, with UTC timestamp, SHA-256 of its
  raw output, byte count and duration;
- `manifest.json`: tool version, case metadata (`--case-id`, `--examiner`,
  `--case-notes`), session start/end and transport, device identifiers, the
  SHA-256 of every artifact and report, and a methodology statement describing
  what the acquisition touched;
- `manifest.json.sha256`: detached hash of the manifest.

```sh
apex verify ./case-42      # exit 0 = VERIFIED, 1 = altered or incomplete
```

`verify` recomputes the manifest hash and re-hashes every file (matching by
hash, so moving the bundle is fine), and lists missing, altered and unlisted
files.

## Static analysis

```sh
apex scan app.apk                       # terminal report
apex scan app.apk --json -o report.json
apex scan app.apk --detail              # evidence under each finding
apex scan app.apk --fail-on high        # exit 1 for CI/CD
```

Analyzers: `manifest`, `certificate`, `network`, `sast`, `api`, `permissions`,
`binary` (ELF checksec), `secrets` (+ entropy), `jar_aar`, `dataflow`,
`cloud`, `privacy`, `binary_advanced`, `platform`, `supply_chain`.

Findings carry CWE and OWASP MASVS references and, where the capability maps
to an adversary technique, a **MITRE ATT&CK for Mobile** id (`T1430`,
`T1636.003`…). The mapping is one auditable table (`default_mitre` in
[src/models.rs](src/models.rs)); weaknesses without a clean technique stay
untagged. The `privacy` analyzer classifies embedded trackers with the
**Exodus Privacy** taxonomy and escalates session-replay SDKs.

`.ipa` files are accepted, but only `secrets`, `privacy` and `cloud` run on
them: the other analyzers are Android-specific.

## Indicator data

- **Bundled**: Echap stalkerware package names and signing-certificate SHA-1s
  ([src/stalkerware_iocs.rs](src/stalkerware_iocs.rs)). Refresh with
  `scripts/update-iocs.sh`.
- **At analysis time**: any STIX 2.x bundle via `--iocs`. Supported patterns:
  `app:id`, `app:cert.sha1|sha256`, `file:hashes.sha256|sha1|md5`,
  `domain-name:value`, `ipv4-addr:value`, `ipv6-addr:value`, `url:value`.
  Other pattern types are counted and reported, never silently dropped.

No network call is made at scan or analysis time.

## Accuracy and limits

- Findings are **indicators, not proof**. Legitimate apps (MDM, accessibility
  tools, password managers) can match a stalkerware profile; confirm with the
  phone's owner before acting, and do not remove an app abruptly where abuse
  is suspected.
- `dumpsys` formats vary across Android versions and phone makers. Parsers are
  best-effort: an unrecognised artifact produces no finding rather than an
  error. Validated on Android 13 (Xiaomi / MIUI).
- Static analysis shows what an app embeds and requests; what it actually
  contacts at runtime needs dynamic analysis.

## Releasing

Prebuilt binaries come from the `Release` GitHub Actions workflow
([.github/workflows/release.yml](.github/workflows/release.yml)), run manually.
It tests, builds macOS and Linux (x86_64, arm64), packages
`apex-<version>-<target>.tar.gz`, regenerates [`Formula/apex.rb`](Formula/apex.rb)
and publishes the GitHub Release.

```sh
scripts/build-release.sh            # host target
scripts/build-release.sh --all      # all four release targets
```
