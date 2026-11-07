# diff

What changed between two acquisitions of the same phone: for example before
and after it left its owner's hands, or between two periodic checks.

## Prerequisites

- Two cases of the **same phone** (a different serial is reported: it is
  another phone). Each from [`device acquire`](Device-Acquire) or
  [`import`](Import).
- Comparable acquisitions: if one was made with `--no-bugreport` or
  `--triage`, findings based on the missing artifacts cannot be compared, and
  `diff` says so.

No phone, no network.

## Usage

```sh
apex diff ./case-42 ./case-57                       # older first, newer second
apex diff ./case-42 ./case-57 --iocs stalkerware.stix2
apex diff ./case-42 ./case-57 --json -o diff.json
```

| Option | Effect |
|---|---|
| `--iocs <FILE>` | STIX2 indicators matched in both cases (repeatable) |
| `--json` | the diff as JSON (to `-o`, or the terminal) |
| `-o, --output <FILE>` | JSON output file |

## What it compares

- Device identity, Android version, security patch.
- Third-party apps added and removed; per app, installer and version changes,
  and a **signing certificate change** (the same package rebuilt and signed by
  someone else).
- Users and profiles.
- Apps gaining or losing accessibility, device admin or notification access.
- Sensitive settings: ADB, developer options, unknown sources, Play Protect,
  private DNS, proxy, always-on VPN, keyboard.
- Findings that appeared (`+`) or disappeared (`-`).
- Artifacts present in only one of the two cases.
