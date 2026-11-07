# device capture

Captures the conversation open on the phone's screen: the text of every screen
(read from Android's UI tree, not by OCR), a screenshot of every screen, and a
merged transcript, scrolling up until the oldest message.

It is the last resort, for apps with no backup or export to read (Telegram,
Instagram, Snapchat, Messenger…). When the app has a backup with a key shown
on screen, prefer it: see [Getting conversations from an unlocked phone](Communications-and-App-Data#getting-conversations-from-an-unlocked-phone).

## Prerequisites

| Requirement | Why |
|---|---|
| Phone connected, USB debugging on, computer authorized | see [Connecting a phone](Connecting-a-Phone) |
| A mandate reference (`--mandate`, required) | a capture reads message content; the reference is recorded |
| Phone **unlocked**, the conversation **open on screen** | APEX captures what is in front, from where it is |
| **Simulated touches allowed** | scrolling uses `input swipe`. Xiaomi / Redmi / POCO (MIUI, HyperOS) refuse it unless **Developer options → USB debugging (Security settings)** is on, which needs a Mi account. APEX checks this first and stops with that message |
| Nobody touches the phone during the capture | a touch changes the screen being read |

Turning on "USB debugging (Security settings)" is a change to the phone:
record it with `--phone-change`.

## Usage

```sh
apex device capture --mandate "JIRS-2026-17" \
  --label "WhatsApp — conversation with Dédé" \
  --case-id 2026-0142 --examiner "Brigadier X" --seal "SCELLÉ N°1" \
  --phone-change "11:52 Débogage USB (paramètres de sécurité) activé" \
  -o ./2026-0142_s1_capture_dede
```

One output directory per conversation.

| Option | Effect |
|---|---|
| `--mandate <REF>` | required, recorded in the manifest |
| `-o, --output <DIR>` | output directory (default `./apex_capture`) |
| `--label <TEXT>` | what is captured (app, conversation), recorded in the manifest and the PV |
| `--max-pages <N>` | stop after N screens (default 300) |
| `--settle-ms <MS>` | wait after each swipe for older messages to load (default 900); raise it on a slow phone or a long media-heavy conversation |
| `--phone-change <TEXT>` | a change you made to the phone, with its time (repeatable) |
| `--case-id`, `--examiner`, `--case-notes`, `--seal` | case metadata |
| `--serial`, `--tcp`, `--adb-key` | see [Device](Device#connection-options-all-of-them) |

## How it works

For each screen: `uiautomator dump` (every text and description shown, with
its position), `screencap`, then a swipe toward older messages. It stops when
two screens in a row are identical (the top of the conversation) or after
`--max-pages`. Screens are then merged oldest first, without the overlap
between consecutive screens. Only the elements of the app in front are kept
(no status bar, keyboard or system UI). The two scratch files on the phone
(`/data/local/tmp/apex_ui.xml`, `apex_cap.png`) are deleted at the end.

About 1–2 s per screen.

## Output

| File | Content |
|---|---|
| `pages/0001.png`, `pages/0001.xml` … | every screen as captured (screenshot and UI tree), hashed; 0001 is the first screen captured, the newest content |
| `transcript.txt` | the conversation, oldest first: `[screen] side | text` |
| `capture.db` | SQLite, for queries (below) |
| `manifest.json`, `manifest.json.sha256`, `audit.jsonl` | evidence bundle; check it with [`verify`](Verify) |

`side` is `left`, `right` or `center` from the element's position: in chat
apps, **right is usually the phone's owner**. A `*` (or `described = 1`)
marks a description rather than a text: an image, a voice note, an icon.

### `capture.db`

| Table | Rows |
|---|---|
| `lines` | the merged conversation: `seq` (reading order), `screen`, `side`, `text`, `described`, position, `resource_id`, `class` |
| `screens` | one per screen: capture time (UTC), PNG and XML paths |
| `screen_lines` | every element of every screen, before merging |
| `meta` | package, label, screen width, screen count |

```sh
sqlite3 capture.db "SELECT seq, side, text FROM lines WHERE text LIKE '%rdv%'"
```

## Limits

- Only what the app displays: no deleted messages, no hidden metadata (exact
  timestamps are those the app prints).
- Apps that set FLAG_SECURE (Telegram secret chats, some banking apps) give
  black screenshots; their text is still in the UI tree.
- Very long conversations: hundreds of screens. Raise `--max-pages` if the
  top is not reached; the terminal shows the screen count.
- If the app loads older messages slowly, identical screens can stop the
  capture early: raise `--settle-ms` and run again.
