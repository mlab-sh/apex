# export

Lays a case out like a full file-system extraction, so that tools built for
extractions can read it: ALEAPP, a lab suite, your own scripts. The case
itself is not modified, and you keep working with APEX on the case.

## Prerequisites

- A case from [`device acquire`](Device-Acquire) (ideally `--full`) or
  [`import`](Import).
- Disk space: on APFS (macOS), btrfs or XFS the files are copy-on-write
  clones (instant, no extra space); elsewhere, the size of the case.

No phone, no network.

## Usage

```sh
apex export ./case-42 -o ./case-42-ffs
```

## Layout

| In the case | In the export |
|---|---|
| `storage/…` (shared storage) | `data/media/0/…` |
| `apps/<pkg>/*.apk` | `data/app/~~apex==/<pkg>-apex==/*.apk` |
| `comms/db/mmssms.db`, `msgstore.db`… | their real paths (`data/user_de/0/com.android.providers.telephony/databases/mmssms.db`, `data/data/com.whatsapp/databases/msgstore.db`…) |
| `comms/mms_parts/…` | `data/user_de/0/com.android.providers.telephony/app_parts/…` |
| `comms/app/<pkg>/…` (app data from an extraction) | `data/data/<pkg>/…` |
| WhatsApp / Signal backups | `data/media/0/Android/media/com.whatsapp/WhatsApp/Databases/…`, `data/media/0/Signal/Backups/…` |
| `backup/apps/<pkg>/…` (Android backup) | `data/data/<pkg>/databases|files|shared_prefs/…` |
| everything else (manifest, audit log, `device/` dumps, agent output) | `apex/…`, unchanged |

`export_manifest.json` lists every file with its source in the case and its
SHA-256, checked after the copy.

## What it is not

A logical acquisition laid out as an extraction is not an extraction: the
system databases and app private data of a live phone are not there (they
need root; see [Legal scope](Legal-Scope)). Tools reading the export find the
media, the APKs, the messages collected under mandate, the app backups, and
nothing more.

Never hard links: a tool opening an exported database read-write must not
change the evidence.
