# Communications and app data

Every source [`comms`](Comms) reads, where it comes from, and what it needs.
All of them require the case to be acquired or imported with
`--mandate <reference>` (see [Legal scope](Legal-Scope)).

## Live phone or extraction

A live phone without root only lets the `shell` user read what Android's
content providers and shared storage expose. App-private data (`/data/data`)
needs a full file-system extraction made by a lab, read with
[`import --mandate`](Import).

| Source | Live phone (`device acquire --mandate`) | Extraction (`import --mandate`) |
|---|---|---|
| SMS | yes | `mmssms.db` |
| MMS text and attachments | yes | `mmssms.db` + `app_parts/` |
| Call log | yes | `calllog.db` / `contacts2.db` |
| Contacts | usually refused to the shell | `contacts2.db` (with contacts flagged deleted) |
| Calendar | yes | `calendar.db` (with events flagged deleted) |
| WhatsApp messages, media paths, contact names | no | `msgstore.db` (current and legacy schema), `wa.db` |
| WhatsApp backups `.crypt14` / `.crypt15` | **files collected**, decrypted only with the 64-digit key | collected and decrypted with the keys in the extraction |
| Signal | no | `signal.db` (SQLCipher), see keys below |
| Telegram | no | `cache4.db` |
| Messenger | no | `msys_database_*`, `threads_db2` |
| Instagram direct messages | no | `direct.db`, `msys_database_*` |
| Snapchat | no | `arroyo.db` + `main.db` (best effort) |
| Gmail | no | `mailstore.*.db`; `bigTopDataDB.*` (best effort) |
| Chrome history and downloads | no | `History` |
| Google Maps: navigation destinations, saved places | no | `da_destination_history`, `gmm_myplaces.db` → `locations.kml` |
| Gboard: clipboard, typed-text cache | no | `gboard_clipboard.db`, `trainingcache*.db` (best effort) |
| Crypto wallets: Bitcoin / Ethereum addresses | no | settings, databases and files of ~20 wallet and exchange apps |
| Notification texts | `--notification-content` | — |
| Apps that allow Android backup | `--backup` (confirm on the phone) | — |

"Best effort" means the format is undocumented and changes often: text is
taken from protobuf strings and the source column says so.

## Keys

| Source | Key | Where it comes from |
|---|---|---|
| WhatsApp `.crypt14` (local backup) | `files/key` | extraction only |
| WhatsApp `.crypt15` (end-to-end backup) | `files/encrypted_backup.key`, or the 64-digit key | extraction, or `apex comms --wa-key <64 hex digits>` |
| Signal `signal.db` | database secret | older Signal: in the app settings, read automatically; newer Signal: protected by the Android Keystore, recovered by the lab, given with `apex comms --signal-key <hex>` |

The 64-digit WhatsApp key is shown **once**, when end-to-end backup is turned
on with the "64-digit key" option. If the owner chose a password instead,
there is no displayable key and the backup needs the extraction's
`encrypted_backup.key`.

`comms` prints a ⚠ line for every source it found but could not open, with
the reason.

## Deleted messages

- Databases are copied with their write-ahead log; deleted rows are recovered
  from it and from free pages (see [Deleted records](Deleted-Records)).
- WhatsApp: a message in a backup but no longer in the live `msgstore.db` is
  reported as recovered (deleted after the backup).
- Signal: deleted rows are **not** recovered; the free pages of an encrypted
  database stay encrypted.

## Requests to operators

What is not on the phone is often at the operator's: cloud backups, trips,
payments, account metadata. [`identifiers`](Identifiers) lists the accounts
and the installed apps whose operator holds data (finding
`CASE_APPS_OF_INTEREST`).
