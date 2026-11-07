# APEX agent

A 17 KB Android app with no screen, embedded in the `apex` binary. During
[`device acquire`](Device-Acquire) it is installed over USB, given only the
permissions the legal scope allows, read once, then uninstalled: about 8
seconds. It reads what the ADB shell user cannot.

On by default; `--no-agent` skips it.

## What it adds

| Section | Content | Needs |
|---|---|---|
| packages | every package with label, version, install source (installer, initiator), first install and last update, **signing certificate SHA-256 / SHA-1**, requested and **granted** permissions, APK paths | — |
| accounts | accounts visible to apps | — |
| telephony | each SIM: slot, carrier, **line number**, ICCID when allowed, MCC/MNC, eSIM | — |
| bluetooth | paired devices | — |
| usage | usage events the system keeps (often weeks): app in front, **screen on / off, unlock**, foreground services, boot / shutdown | — |
| media | every MediaStore row: path, size, dates, MIME type, **the app that wrote the file** | — |
| contacts | every column of every contact data row (names, numbers, e-mails, accounts, starred, last update) | `--mandate` |
| calllog, calendar | every column (more than the shell gets) | `--mandate` |
| media GPS | photo EXIF position, date, make, model; video position | `--mandate` |
| sms | every column | `--mandate`, full build |
| notifications | active notifications with the **messages** messaging apps keep in them | `--mandate --notification-content`, full build |

The output is `agent/agent.json` in the case, hashed in the manifest. It
feeds the [timeline](Timeline) (unlocks, app in front), the [report](Report)
and the [PV](PV) (phone use), [`identifiers`](Identifiers) (SIMs, full
account names), [`comms`](Comms) (contacts, names on numbers),
[`apex db`](Db) and the findings: with `--quick`, signing certificates
read by the agent are matched against stalkerware certificates and STIX2
`app:cert.*` indicators, so APKs need not be pulled.

## Two builds

- **full**: everything above.
- **lite**: without SMS and notification access.

APEX installs the full build over ADB. If the phone refuses it, it installs
the lite build. When the phone's own installer is used (Xiaomi without
*Install via USB*, see below), it uses the lite build directly: Google Play
Protect blocks sideloaded apps that ask for SMS or notification access.
SMS and notification content still come from the shell in every case
(`--mandate`, `--notification-content`).

## What it changes on the phone

Every step is in `audit.jsonl` and listed in the manifest's `phone_changes`,
so it appears in the [procès-verbal](PV):

```
11:28:06 UTC APEX agent, full build (sh.mlab.apex.agent, sha256 …), installed
11:28:07 UTC APEX agent permissions granted: GET_ACCOUNTS, READ_PHONE_STATE, …
11:28:07 UTC APEX agent notification access allowed
11:28:14 UTC APEX agent uninstalled (Success)
```

The permissions listed are those the phone **actually** granted, read back
from the system after `pm grant`; refused ones are listed too. The package
manager log keeps a trace of the install and uninstall: it shows in the
timeline, not in the findings.

No network permission: the agent cannot send anything.

## Prerequisites per maker

| Phone | What to do |
|---|---|
| Most makers (Samsung, Pixel, Motorola, OPPO…) | nothing: ADB installs and grants work |
| Xiaomi / Redmi / POCO (MIUI, HyperOS) | Developer options → **Install via USB** (confirm the install prompt on the phone) and **USB debugging (Security settings)** (without it, permissions are silently refused). Both need a signed-in Mi account. Record both with `--phone-change` |

On Xiaomi without those options, APEX copies the lite build to `Download`
and asks you to install it from the phone; if nobody does within 3 minutes,
it removes the file and goes on without the agent. Every case works without
the agent; you lose what the table above lists.

## Rebuilding the agent

Only to change it. Needs a JDK and the Android SDK (`platforms;android-34`,
`build-tools;34.0.0`):

```sh
scripts/build-agent.sh      # → agent/apex-agent.apk, agent/apex-agent-lite.apk
cargo build --release       # embeds them
```

Source: `agent/` (Java, no Gradle). The signing key `agent/apex-agent.keystore`
is created on first build and is not in the repository.
