# comms

Exports every communication record of a case into one list: SMS, MMS, calls,
contacts, calendar, WhatsApp (and its backups), Signal, Telegram, Messenger,
Instagram, Snapchat, e-mail, browser history, locations, clipboard and typed
text, crypto wallet addresses. Deleted records recovered are flagged.

## Prerequisites

| Requirement | Why |
|---|---|
| A case acquired or imported **with `--mandate <ref>`** | without it no communication was collected; `comms` exits with code 1 and says so |
| For app data (WhatsApp databases, Signal, Messenger…): a case from [`import`](Import) of an after-first-unlock extraction | a live phone without root gives SMS, MMS, calls, calendar and WhatsApp backup files only |
| For **Signal**: its database secret, found automatically in older versions; otherwise `--signal-key <hex>` from the lab | newer Signal versions protect it with the Android Keystore |
| For **WhatsApp backups**: `files/key` or `files/encrypted_backup.key` in the extraction, or the 64-digit end-to-end key (`--wa-key`) | on a live phone without root these key files are out of reach |

No phone, no network. Details per source: [Communications and app data](Communications-and-App-Data).

## Usage

```sh
apex comms ./case-42                                  # → ./case-42_comms/
apex comms ./case-42 -o ./case-42-comms
apex comms ./case-42 --signal-key 9f8e7d…             # Signal secret recovered by the lab
apex comms ./case-42 --wa-key 3a1f…                   # WhatsApp 64-digit end-to-end key, no spaces
```

| Option | Effect |
|---|---|
| `-o, --output <DIR>` | output directory (default `<case>_comms`) |
| `--signal-key <HEX>` | Signal database secret |
| `--wa-key <HEX>` | WhatsApp 64-digit end-to-end backup key (type it without the spaces WhatsApp shows) |

Prefer typing keys yourself in a terminal over pasting them into shared notes:
they unlock everything the backup holds.

## Output

The terminal shows the count per kind and how many were recovered from
deleted records, and a **⚠ line for every source it could not open**, with
the reason (missing key, encrypted database…).

| File | Content |
|---|---|
| `comms.csv` | `time, kind, direction, peer, text, extra, source, recovered` |
| `comms.json` | the same, as JSON |
| `locations.kml` | Google Maps destinations and saved places, when present |

`time` is the phone's local time with its UTC offset. `recovered = true`
marks a record deleted from the database and carved back, or a WhatsApp
backup message no longer in the live database. See [Deleted records](Deleted-Records).

Everything also goes into the [timeline](Timeline) and [search](Search); the
[report](Report) and [PV](PV) show counts only.
