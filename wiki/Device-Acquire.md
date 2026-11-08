# device acquire

Forensic acquisition of a live phone into a [case directory](Case-Directory):
volatile state, system state and history, every third-party APK, optionally
communications (under mandate) and shared storage, with an
[evidence bundle](Evidence-and-Integrity) hashing every file.

## Prerequisites

| Requirement | Why |
|---|---|
| Phone connected, USB debugging on, computer authorized | see [Connecting a phone](Connecting-a-Phone) |
| Phone **unlocked and awake for the whole run** | the phone refuses some reads while locked; set the screen timeout to the maximum |
| Battery charged or on charge | a full acquisition takes 5–10 min, more with `--storage` |
| Disk space: ~1–2 GB (most of it APKs), plus the size of shared storage with `--storage` | the case is written to disk as it goes |
| A mandate reference for `--mandate` and `--notification-content` | see [Legal scope](Legal-Scope) |
| Someone at the phone for `--backup` | the backup must be confirmed on its screen, with an empty password |
| No root | the [agent](Agent) is installed for a few seconds and removed; on Xiaomi it needs *Install via USB* and *USB debugging (Security settings)* (Mi account), otherwise APEX goes on without it |

## Usage

```sh
apex device acquire -o ./case-42 --case-id 2026-0142 --examiner "J. Doe" --seal "SCELLÉ N°1"
apex device acquire --triage -o ./case-42-triage           # volatile state only, ≈ 10 s
apex device acquire --mandate "JIRS-2026-17" --storage -o ./case-42
apex device acquire --package com.foo.bar -o ./case-42     # one app only
apex device acquire --no-bugreport --no-logcat --no-usagestats -o ./case-42   # fast
```

| Option | Effect |
|---|---|
| `-o, --output <DIR>` | case directory (default `./apex_acquire`) |
| `--case-id`, `--examiner`, `--case-notes`, `--seal` | case metadata, recorded in the manifest, the report and the PV |
| `--phone-change <TEXT>` | a change you made to the phone, with its time (repeatable): recorded and listed in the PV |
| `--triage` | volatile state, remote-wipe check and identifiers only (< 1 min); no apps, no history |
| `--mandate <REF>` | also collect SMS, MMS (+ attachments), call log, calendar, contacts if the phone allows it, and WhatsApp and Signal backups from shared storage; the reference is recorded |
| `--notification-content` | notifications unredacted (titles, message previews); only under mandate |
| `--storage` | pull shared storage (`/sdcard`: photos, videos, downloads, messaging media), without `Android/data` and `Android/obb` |
| `--backup` | Android backup (`bu backup -all -noapk`) of the apps that allow it; confirm on the phone with an **empty** password |
| `--quick` | **shortest time plugged in**: APKs hashed on the phone (`sha256sum`) instead of pulled, **except the apps worth a static analysis**, which are pulled: not installed from a store, without a launcher icon, or holding accessibility, device admin or notification access. No bugreport, logcat or usage-stats dump (the [agent](Agent) gives usage events and signing certificates). ≈ 40–60 s |
| `--no-agent` | do not install the [APEX agent](Agent) |
| `--full` | **everything a phone gives without root**: `--storage`, `--backup`, every APK, bugreport, logcat, usage stats, the agent, and the **SHA-256 of every file of the system partitions** (`/system`, `/system_ext`, `/product`, `/vendor`, `/odm`). 10–30 min. Add `--mandate` for communications. Confirm the backup on the phone |
| `--package <PKG>` | acquire only this app (device state is still collected) |
| `--no-bugreport` | skip the bugreport (1–5 min, 10–100 MB); loses battery history and some install history |
| `--no-logcat`, `--no-usagestats`, `--no-screenshot` | skip those artifacts |
| `--serial`, `--tcp`, `--adb-key` | see [Device](Device#connection-options-all-of-them) |

## What is collected, in order

1. **Clock and battery**: the phone's time against the computer's (clock skew),
   battery level and charging state at reception.
2. **Remote-wipe check**: accounts, device policy, connectivity. A red banner if
   a find-my-device service, an MDM or a device admin can erase the phone, and
   whether it is online. See [Field procedure](Field-Procedure#3-triage-first--10-s).
3. **Volatile state**: processes with their real executables, network sockets,
   `/data/local/tmp`, a screenshot.
4. **Identity**: system properties, package lists, users and profiles,
   telephony identifiers (IMEI, IMSI, ICCID, line number) through read-only
   getters, settings.
5. **APEX agent** (unless `--no-agent`): installed, read, uninstalled, ≈ 8 s.
   See [APEX agent](Agent).
6. **History and state** (not in triage): Wi-Fi, Bluetooth, app-ops (permission
   use), launcher, ~25 `dumpsys` services including per-app network traffic and
   the package manager log, shared-storage file listing, usage stats, logcat,
   bugreport.
7. **Under `--mandate`**: SMS, MMS and their attachments, call log, contacts,
   calendar, WhatsApp backups (`.crypt14` / `.crypt15`) and Signal backups
   (`signal-*.backup`) from shared storage.
8. **`--backup`, `--storage`** if asked.
9. **Every third-party APK** (all splits) with its `dumpsys package`,
   including apps installed only in another user or profile; with `--quick`,
   their SHA-256 computed on the phone (`apps/<pkg>/apk_sha256.txt`) instead.
10. **Evidence bundle**: `identifiers.json`, `manifest.json`,
   `manifest.json.sha256`, `audit.jsonl`.

The layout is on [Case directory](Case-Directory).

## What it changes on the phone

A live acquisition runs commands, so the phone logs them. Beyond that, APEX
writes in three places, all listed in `audit.jsonl` and in the manifest's
methodology statement:

- the screenshot, written to `/data/local/tmp/apex_screen.png`, pulled, deleted
  (`--no-screenshot` avoids it);
- the bugreport zip, left in the shell user's bugreports directory
  (`--no-bugreport` avoids it);
- with `--backup`, `/data/local/tmp/apex_backup.ab`, pulled, deleted;
- the [APEX agent](Agent): installed, read, uninstalled. Its steps are listed
  in the manifest's `phone_changes` and in the PV.

Enabling developer options and USB debugging before the acquisition are your
changes: declare them with `--phone-change`.

## Durations (Android 13, ~20 user apps)

| Mode | Time |
|---|---|
| `--triage` | ≈ 6–10 s |
| `--quick` (agent included) | ≈ 40–60 s |
| `--full` | 10–30 min (storage size, backup confirmation) |
| full, `--no-bugreport` | ≈ 1–5 min (APK count and size) |
| full | + 1–5 min for the bugreport |
| `--storage` | + ≈ 1 min per few hundred MB |

## Not collected from a live phone

App-private data (`/data/data`: WhatsApp, Signal, Telegram databases…) is not
readable without root. It comes from a lab extraction through
[`apex import`](Import). See [Communications and app data](Communications-and-App-Data)
for what is reachable live and what needs an extraction.

## With `--full`

The dump to keep and work on, once the phone has gone back or to the lab:
everything readable without root, in one run. Besides the usual
acquisition, `device/system_hashes.txt` lists the SHA-256 of every readable
file of the system partitions: [`apex diff`](Diff) between two `--full`
acquisitions shows any system file added, removed or changed (a firmware
update changes many; a handful without an update is suspicious).
[`apex export`](Export) then lays the case out like a file-system
extraction for other tools.

## With `--quick`

The suspicious apps (not from a store, hidden, privileged) are pulled and get
the full static analysis; the line of each app says why it was pulled. For the
others, indicator matching still works: APK hashes from the phone, signing
certificates from the agent. Run [`device scan`](Device) or a full
acquisition later if you need every APK.

## Next

```sh
apex verify ./case-42
apex analyze ./case-42 --iocs stalkerware.stix2
apex identifiers ./case-42
apex db ./case-42            # everything in one SQLite file
```
