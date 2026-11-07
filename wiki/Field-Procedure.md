# Field procedure

The reference scenario: a search, the phone's owner gives the **unlock code
and nothing else**. No root, no exploit. Everything below uses only what an
unlocked phone allows over USB debugging.

Times are those measured on an Android 13 phone with about 20 user apps.

## 0. Before leaving

- [ ] A computer with APEX installed; `apex --version` prints the expected
      version (see [Installation](Installation#check-which-apex-runs)).
- [ ] A **data** USB cable (USB-C and micro-USB), a charger or power bank.
- [ ] Linux: udev rules installed; macOS / Linux: no `adb` server running.
- [ ] A Faraday bag if the phone must stay off the network.
- [ ] The case reference, your name, the seal numbers, the mandate reference
      if communications are covered.

## 1. Reception of the phone

1. Note the time, the phone's state (on / off, locked, battery, damage),
   photograph it.
2. **Do not** put it in airplane mode yet if you need to know whether it can be
   wiped remotely: step 3 checks it in seconds. If the risk is obvious
   (the owner tries to reach it remotely), isolate it at once and note it.
3. Have the owner unlock it, or unlock it with the code given.

## 2. Enable USB debugging

On the phone: **Developer options** (tap *Build number* 7 times), then
**USB debugging**. See [Connecting a phone](Connecting-a-Phone).

These are changes to the phone: write them down, with the time. The
procès-verbal must mention them.

```sh
apex device listen --timeout 120      # plug in, accept "Allow USB debugging?" on the phone
```

## 3. Triage first (≈ 10 s)

Volatile state before anything else: clock, **remote-wipe check**, accounts,
running processes, network sockets, screenshot, telephony identifiers,
properties, apps, users, settings.

```sh
apex device acquire --triage \
  --case-id "2026-0142" --examiner "Brigadier X" --seal "SCELLÉ N°1" \
  -o ./2026-0142_s1_triage
```

If APEX prints a **red remote-wipe alert** (find-my-device signed in, MDM,
device admin) and says the phone is online: put it in **airplane mode** now
(and Wi-Fi off), note the time. The acquisitions after this show the change.

## 4. Acquisition

**Shortest time plugged in (≈ 1 min):**

```sh
apex device acquire --quick --mandate "JIRS-2026-17" \
  --case-id "2026-0142" --examiner "Brigadier X" --seal "SCELLÉ N°1" \
  -o ./2026-0142_s1
```

APKs are hashed on the phone instead of pulled, no bugreport; the
[APEX agent](Agent) is installed for ≈ 8 s (confirm the install prompt on
Xiaomi) and gives packages with certificates, usage and unlock history,
contacts, SIMs and media. Unplug, and do the rest at the office.

**Full acquisition (≈ 5–10 min, more with `--storage`)**, when the phone can
stay plugged in: also the APKs themselves (static analysis) and the bugreport
(battery and install history).

Without a mandate, APEX collects the phone's state, apps and history, but no
communication content (see [Legal scope](Legal-Scope)):

```sh
apex device acquire \
  --case-id "2026-0142" --examiner "Brigadier X" --seal "SCELLÉ N°1" \
  -o ./2026-0142_s1
```

With a mandate covering communications, add its reference (recorded in the
manifest), and `--storage` for photos, videos and downloads:

```sh
apex device acquire --mandate "JIRS-2026-17" --storage \
  --case-id "2026-0142" --examiner "Brigadier X" --seal "SCELLÉ N°1" \
  -o ./2026-0142_s1
```

Keep the phone **unlocked and awake** throughout. Options:

| Option | Effect | Cost |
|---|---|---|
| `--storage` | pulls shared storage (photos, videos, downloads, WhatsApp media) | ~1 min per few hundred MB |
| `--mandate <ref>` | SMS, MMS and attachments, call log, calendar, WhatsApp backups on storage | seconds |
| `--notification-content` | notification texts unredacted (message previews); only under mandate | none |
| `--backup` | Android backup of the apps that allow it; **confirm on the phone with an empty password** | minutes, little data on recent apps |
| `--no-bugreport` | skips the bugreport (1–5 min, 10–100 MB); loses battery and install history | saves time |
| `--no-logcat`, `--no-usagestats`, `--no-screenshot` | skip those artifacts | saves time |

Details: [device acquire](Device-Acquire).

Record each change you made to the phone so it appears in the manifest and
the procès-verbal:

```sh
apex device acquire --mandate "JIRS-2026-17" \
  --phone-change "10:41 Options pour les développeurs activées" \
  --phone-change "10:42 Débogage USB activé" \
  --phone-change "10:44 Mode avion activé" \
  -o ./2026-0142_s1
```

## 4b. Messaging apps (under mandate)

A live phone does not give app databases. In order of preference (details:
[Getting conversations from an unlocked phone](Communications-and-App-Data#getting-conversations-from-an-unlocked-phone)):

1. **Signal**: turn on chat backups, note the 30-digit passphrase, create a
   backup. **WhatsApp**: turn on end-to-end backup with the 64-digit key (needs
   the network), Google backup on "Never", back up. Then run the acquisition
   above (it collects the backup files) and decrypt:
   ```sh
   apex comms ./2026-0142_s1 --signal-passphrase "…" --wa-key …
   ```
2. **Other apps**: open each conversation and capture it, one directory per
   conversation:
   ```sh
   apex device capture --mandate "JIRS-2026-17" --label "Telegram — X" -o ./2026-0142_s1_capture_x
   ```
   On Xiaomi, this needs *USB debugging (Security settings)*: record it.

## 5. Integrity

Right after the acquisition, on the computer:

```sh
apex verify ./2026-0142_s1                       # must print VERIFIED
apex seal ./2026-0142_s1 --tsa https://freetsa.org/tsr   # needs the computer online; sends only a hash
apex verify ./2026-0142_s1                       # now also checks the timestamp
```

Copy the case directory to its storage medium; `verify` works wherever it is
(files are matched by hash).

## 6. Analysis (back at the office, no phone needed)

```sh
apex db ./2026-0142_s1                           # everything in ./2026-0142_s1.db, for SQL
apex analyze ./2026-0142_s1 --iocs stalkerware.stix2 --detail
apex identifiers ./2026-0142_s1                  # legal requests: IMEI, IMSI, line, accounts, operators
apex comms ./2026-0142_s1                        # under mandate: comms.csv / comms.json
apex media ./2026-0142_s1 --hashes vics.json     # with --storage: hashes, GPS, KML
apex search ./2026-0142_s1 --entities            # phones, e-mails, IBANs, crypto addresses
apex timeline ./2026-0142_s1 -o ./2026-0142_s1_timeline.csv
apex report ./2026-0142_s1 -o ./2026-0142_s1.html
apex pv ./2026-0142_s1 --service "Brigade de …" --place "…" -o ./pv_2026-0142.html
```

Write outputs **outside** the case directory (`-o`), or `verify` reports them
as unlisted files.

## 7. What goes in the procès-verbal

`apex pv` drafts it from the case files: device, state at reception, operations
with times, commands issued, integrity and timestamp, findings, communication
counts. Add by hand what APEX cannot know:

- who unlocked the phone, and how the code was obtained;
- the settings you changed (developer options, USB debugging, airplane mode)
  and when;
- anything done on the phone outside APEX.

## A locked, broken or switched-off phone

APEX does not unlock phones. Send it to a lab for a full file-system
extraction, then read the result with [`apex import`](Import): every analysis
command above works on the imported case, with app databases and keys that a
live phone does not give.
