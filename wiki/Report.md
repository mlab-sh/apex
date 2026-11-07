# report

One self-contained HTML file for a case: readable by a non-technical reader,
printable, no external resources.

## Prerequisites

- A case from [`device acquire`](Device-Acquire) or [`import`](Import).
- Optional: STIX2 bundles (`--iocs`) and alert hash sets (`--hashes`), as for
  [`analyze`](Analyze).

No phone, no network.

## Usage

```sh
apex report ./case-42 -o ./case-42.html
apex report ./case-42 --iocs stalkerware.stix2 --hashes vics.json -o ./case-42.html
apex report ./case-42                          # → ./case-42/report.html
```

Write it **outside** the case (`-o`): a file added inside the case shows as
unlisted in [`verify`](Verify).

## Sections

1. Case and acquisition: case ID, examiner, seal, mandate, acquired or
   imported, times, clock skew, transport, integrity check result.
2. Identifiers for legal requests (the [`identifiers`](Identifiers) sheet,
   including the apps whose operator holds data).
3. Findings by severity, with their evidence.
4. Communications: counts per kind and recovered records only. Content is
   exported with [`comms`](Comms).
5. Media with a location, with map links.
6. User-installed apps: installer, sideloaded, hidden, privileges, users,
   traffic.
7. Phone use (with the [agent](Agent)): period covered, number of unlocks and
   the latest ones, apps opened most.
8. Users and profiles.
9. Method and limits.
