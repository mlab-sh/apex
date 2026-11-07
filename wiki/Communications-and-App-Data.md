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
| Signal backups `signal-*.backup` | **files collected**, decrypted with the 30-digit passphrase | collected from shared storage, same passphrase |
| Any app, as displayed | [`device capture`](Device-Capture) (text of every screen + screenshots) | — |
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
| Signal `signal-*.backup` | 30-digit passphrase | shown once when chat backups are turned on: `apex comms --signal-passphrase "<digits>"` |

The 64-digit WhatsApp key is shown **once**, when end-to-end backup is turned
on with the "64-digit key" option. If the owner chose a password instead,
there is no displayable key and the backup needs the extraction's
`encrypted_backup.key`.

`comms` prints a ⚠ line for every source it found but could not open, with
the reason.

## Getting conversations from an unlocked phone

Without root, ADB cannot read an app's private storage: no tool gets
WhatsApp's or Signal's databases from a live phone that way. What an unlocked
phone does allow, cleanest first:

1. **The app's own backup, with a key the app shows on screen.** Complete
   history, attachments, decrypted offline, and the app's real timestamps and
   senders.
   - **Signal**: Settings → Chats → Chat backups → turn on, pick a folder.
     Signal shows a **30-digit passphrase**: write it down. Tap "Create
     backup". Works offline. Then `device acquire --mandate …` collects the
     `.backup` file and `apex comms --signal-passphrase "…"` decrypts it.
   - **WhatsApp**: Settings → Chats → Chat backup → End-to-end encrypted
     backup → turn on with **"Use 64-digit encryption key instead"**:
     WhatsApp shows the key, write it down. Set "Back up to Google Account"
     to **Never**, then "Back up". Turning on end-to-end backup **needs the
     network** (WhatsApp registers the key with its servers). Then
     `device acquire --mandate …` collects the `.crypt15` and
     `apex comms --wa-key …` decrypts it.
2. **The app's export of one conversation** (WhatsApp: conversation → ⋮ →
   More → Export chat → without or with media → save to Downloads). A text
   file and media; `device acquire --storage` collects them. Per conversation,
   and the format has no message IDs.
3. **[`device capture`](Device-Capture)**: what the app displays, screen by
   screen, for apps without a backup or export (Telegram, Instagram,
   Messenger, Snapchat…).

Not offered by APEX: linking a new device (WhatsApp Web, Telegram Desktop)
or the apps' "Download your information" requests. They pull data from the
operator's servers, which is a different legal act: ask the magistrate, or
send a request to the operator.

Every setting changed for 1 and 2 is a change to the phone: record each one
with `--phone-change "HH:MM what"` so it appears in the manifest and the PV.

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
