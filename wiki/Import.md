# import

Turns a **full file-system extraction** made by a lab tool into an APEX case,
so that every analysis command works on it. This is the path for a locked,
broken or switched-off phone, and the only path to app-private data
(WhatsApp, Signal, Telegram databases, keys).

## Prerequisites

| Requirement | Why |
|---|---|
| A full file-system extraction (FFS), as a directory, `.zip`, `.tar` or `.tar.gz` | APEX reads files; it does not read physical images or proprietary containers (unpack a Cellebrite UFDR, GrayKey or Magnet export to its file tree first) |
| `data/system/packages.xml` inside it, at any depth | that is how APEX finds the Android root; without it nothing is imported |
| An **after-first-unlock** (AFU) extraction for accounts and app data | before the first unlock, credential-encrypted storage (`/data/data`, `/data/system_ce`) is unreadable |
| `--mandate <ref>` to copy communications and app data | see [Legal scope](Legal-Scope) |
| Disk space for the case | APKs, plus app data and storage when asked |

No phone, no network.

## Usage

```sh
apex import ./extraction.zip -o ./case-42 --case-id 2026-0142 --examiner "J. Doe" --seal "SCELLÉ N°2"
apex import ./extraction.tar.gz -o ./case-42 --mandate "JIRS-2026-17" --storage
apex import ./extraction_dir/ -o ./case-42
```

| Option | Effect |
|---|---|
| `-o, --output <DIR>` | case directory to create (required) |
| `--mandate <REF>` | also copy communication databases and app data (below); the reference is recorded |
| `--storage` | also copy shared storage (`data/media/0`, without `Android/data` and `Android/obb`) |
| `--case-id`, `--examiner`, `--case-notes`, `--seal` | case metadata |

## What it rebuilds

From system files, always:

- packages with installer, install / update times, system flag, per-user
  install state; every APK under `data/app`;
- users, work profile and clone space, apps per user;
- settings (secure, global, system), build properties, **time zone** (every
  timestamp depends on it: without it times are UTC, and APEX says so);
- accounts (`accounts_ce.db`, `accounts_de.db`);
- device admins, device and profile owners;
- the package manager log: uninstalls and who did them;
- saved Wi-Fi networks (names and security, **never passwords**), Bluetooth
  adapter and paired devices;
- file listings of `/data/local/tmp` and shared storage.

System XML is read in text or binary form (ABX, Android 12+).

With `--mandate`, the communication databases (with their WAL, for
[deleted records](Deleted-Records)) and the app data of Signal, WhatsApp
(keys and backups), Google Maps, Messenger, Instagram, Snapchat, Gboard, Gmail
and crypto wallets. Full list: [Communications and app data](Communications-and-App-Data).

## Integrity

The extraction is only read. Each source file used is hashed into the
manifest as an input, each file produced too, so [`apex verify`](Verify) works
on the imported case like on an acquisition.

## Not read from an extraction yet

App-ops and usage-stats history (binary formats), network statistics.

## Next

```sh
apex analyze ./case-42 && apex identifiers ./case-42
apex comms ./case-42           # with --mandate
apex timeline ./case-42 -o ./case-42-timeline.csv
```
