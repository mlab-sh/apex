# pv

Drafts a French **procès-verbal de constatations** (HTML, printable) for one
or several exhibits, from their case files.

## Prerequisites

- One case per exhibit (seal), from [`device acquire`](Device-Acquire) or
  [`import`](Import). Give `--seal`, `--case-id` and `--examiner` at
  acquisition so the PV can name them.
- Optional: [`seal`](Seal) the cases first; the PV then states the RFC 3161
  timestamp.
- Optional: STIX2 bundles (`--iocs`) and alert hash sets (`--hashes`).

No phone, no network.

## Usage

```sh
apex pv ./case-42 -o ./pv.html
apex pv ./case-42 ./case-43 --service "Brigade de recherches de …" --officer "Brigadier X" --place "Paris" -o ./pv.html
```

| Option | Effect |
|---|---|
| `<CASES>…` | one case directory per exhibit |
| `--service <TEXT>` | service or unit |
| `--officer <TEXT>` | officer writing the PV (default: the examiner of the first case) |
| `--place <TEXT>` | place of the operations |
| `--iocs <FILE>`, `--hashes <FILE>` | indicators and hash sets (repeatable) |
| `-o, --output <FILE>` | output file (default `./pv.html`) |

## Content, per exhibit

- Device: make, model, serial, IMEI, line number, SIM.
- State at reception: clock and skew, battery, airplane mode, Wi-Fi,
  Bluetooth, network, remote-wipe risk.
- Operations: nature (acquisition, triage, import, screen capture), start and
  end, link (USB / TCP), commands issued, mandate, captured app, tool version.
- Changes made to the phone by the examiner, from `--phone-change`; if none
  was declared, the PV says so and asks you to complete it.
- Integrity: manifest SHA-256, verification result, RFC 3161 timestamp.
- Findings of medium severity and above (titles in English).
- Phone use (with the [agent](Agent)): period, number of unlocks and the
  latest ones, apps opened most.
- Communication counts under mandate.
- Method, then a signature block.

Every statement comes from the hashed case files.

## What you must add

APEX cannot know who unlocked the phone and how the code was obtained, or
anything done on the phone outside APEX. Declare the settings you changed
(developer options, USB debugging, airplane mode, backups) with
`--phone-change` at acquisition so they appear in the PV; complete the rest
before signing it.
