# device listen, list, posture, scan, dump, shell

The quick device commands. For the forensic acquisition, see
[device acquire](Device-Acquire).

## Prerequisites (all of them)

- Phone connected, **USB debugging on**, this computer **authorized** on the
  phone. See [Connecting a phone](Connecting-a-Phone).
- No `adb` server running on the computer (`adb kill-server`).
- The phone unlocked: required for the first authorization, recommended after.

## Connection options (all of them)

| Option | Meaning |
|---|---|
| `--serial <SERIAL>` | the phone to use when several are plugged in (`device listen` prints the serials) |
| `--tcp <HOST[:PORT]>` | legacy ADB over TCP instead of USB, after `adb tcpip 5555`; port 5555 by default |
| `--adb-key <PATH>` | another ADB private key (default `~/.android/adbkey`, created on first use) |

`device listen` takes none of them.

## Case metadata (`posture`, `scan`)

`--case-id`, `--examiner`, `--case-notes`, `--seal`: recorded in the evidence
bundle written by `--evidence <dir>`.

---

## `device listen`

Waits until an ADB phone is connected over USB, prints its serial, exits.

```sh
apex device listen                         # wait forever
apex device listen --timeout 60            # exit 1 after 60 s without a phone
apex device listen --interval 2            # poll every 2 s (default 1)
```

Use it to check the cable, the USB mode and the debugging prompt before a
long command.

## `device list`

Third-party (user-installed) packages.

```sh
apex device list
```

## `device posture`

The phone's own security posture, not its apps: Verified Boot and bootloader
lock, SELinux mode, root indicators, storage encryption, security-patch age,
developer options / ADB / mock location, global HTTP proxy, accessibility
services and notification listeners enabled, device-admin apps, known
stalkerware, and the **remote-wipe check** (printed first).

```sh
apex device posture
apex device posture --detail                          # evidence under each finding
apex device posture --json -o posture.json
apex device posture --evidence ./posture-bundle --case-id 2026-0142
apex device posture --fail-on high                    # exit 1 if a High or Critical finding
```

Root and verified-boot signals come from system properties, which can be
spoofed: they are indicators, not attestation.

## `device scan`

Pulls each third-party APK, runs the [static analyzers](Scan), and adds what is
active on the phone: permissions **granted** (not only requested), install
source, `DEBUGGABLE` / `TEST_ONLY` flags, risky app-ops (overlay, all-files
access, installing other apps).

```sh
apex device scan                                  # every third-party app
apex device scan --package com.foo.bar            # one app
apex device scan --json -o reports/               # one JSON per app
apex device scan --no-runtime                     # static analysis only
apex device scan --evidence ./scan-bundle --fail-on high
```

Takes a few seconds per app (APK size dominates).

## `device dump`

Pulls the third-party APKs (all splits) and basic device info, nothing else.

```sh
apex device dump -o ./apks                        # default ./apex_dump
apex device dump --package com.foo.bar -o ./apks
```

Then analyze them offline with [`apex analyze ./apks`](Analyze).

## `device shell`

Runs one shell command as the `shell` user and prints its output. For
debugging and checks; nothing is recorded in a case.

```sh
apex device shell "getprop ro.build.version.release"
apex device shell "ls -la /sdcard/Download"
```

Anything you run here changes nothing in a case's evidence, but it is still an
action on the phone: note it if it is part of an examination.
