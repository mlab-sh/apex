# db

One SQLite file with everything APEX knows about a case, for SQL queries by
an examiner, a script or an AI agent.

## Prerequisites

- A case from [`device acquire`](Device-Acquire) or [`import`](Import). With
  the [agent](Agent), the database has its extra tables filled (usage,
  contacts, media, SIMs).
- Optional: [`device capture`](Device-Capture) directories (`--capture`),
  STIX2 bundles (`--iocs`), alert hash sets (`--hashes`).

No phone, no network. Built from the case files in about a second; rebuild it
whenever you like (it is overwritten).

## Usage

```sh
apex db ./case-42                                   # → ./case-42.db
apex db ./case-42 --capture ./case-42_capture_dede --iocs stalkerware.stix2 -o ./case-42.db
```

| Option | Effect |
|---|---|
| `--capture <DIR>` | include a screen capture (repeatable) |
| `--iocs <FILE>` | STIX2 indicators for the findings (repeatable) |
| `--hashes <FILE>` | alert hash sets for the findings and media (repeatable) |
| `-o, --output <FILE>` | output file (default `<case>.db`, next to the case, so `verify` stays clean) |

## Tables

| Table | Rows |
|---|---|
| `meta` | case ID, examiner, seal, mandate, changes made to the phone, operation, manifest SHA-256, session times, whether the agent ran |
| `identifiers` | `section, key, value`: device, telephony (IMEI, IMSI, ICCID, line), network |
| `accounts` | `service, type, name, source` (dumpsys and agent) |
| `sims` | per SIM: slot, carrier, number, ICCID, MCC, MNC (agent) |
| `packages` | package, label, version, system, enabled, installer, initiator, first install, last update, UID, target SDK, APK path, certificate SHA-256 / SHA-1, `of_interest` (operator to request) |
| `permissions` | `package, permission, granted` (agent) |
| `findings` | every [finding](Findings): id, severity, title, description, category, metadata (JSON) |
| `events` | the [timeline](Timeline): time, kind, source, package, message |
| `usage` | usage events (agent): time, `app_resumed` / `app_paused` / `screen_on` / `screen_off` / `keyguard_hidden (unlocked)` / boot…, package |
| `comms` | every communication record, as in [`comms`](Comms#commsdb); view `messages` keeps only messages and calls |
| `contacts` | name, kind (phone, email, name, address…), value, account, starred, last update (agent, under mandate) |
| `media` | path, size, MIME, date taken, modified, **app that wrote it**, latitude, longitude, make, model, SHA-256, hash-set match; `source` = `agent (MediaStore)` or `storage` |
| `bluetooth` | paired devices (agent) |
| `entities` | phones, e-mails, IBANs, crypto addresses, handles, with counts and sources (as [`search --entities`](Search)) |
| `captures` | screen captures: capture, label, app, reading order, screen, side, text |

Times are the phone's local time, ISO 8601 with UTC offset; `time_ms`
columns are epoch milliseconds.

## Queries

```sql
-- When was the phone unlocked, the last days?
SELECT time FROM usage WHERE event LIKE 'keyguard_hidden%' ORDER BY time_ms DESC;

-- Which app was in front just before a given time?
SELECT time, package FROM usage WHERE event = 'app_resumed' AND time < '2026-11-06T22:00' ORDER BY time DESC LIMIT 5;

-- Everything exchanged with one number, every app.
SELECT time, kind, direction, text FROM comms WHERE peer LIKE '%612345678%' ORDER BY time_ms;

-- Sideloaded user apps.
SELECT package, installer, first_install FROM packages WHERE system = 0 AND (installer IS NULL OR installer NOT IN ('com.android.vending'));

-- Photos with a position, and the app that saved them.
SELECT path, taken, latitude, longitude, owner_package FROM media WHERE latitude IS NOT NULL;

-- Findings worth a look.
SELECT severity, id, title FROM findings WHERE severity IN ('critical', 'high', 'medium');
```
