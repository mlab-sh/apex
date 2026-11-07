# analyze

Findings on a case, offline: every package through the static analyzers, plus
the **investigation** findings (stalkerware, hidden apps, uninstall history,
remote wipe, traffic, communications…) and indicator matching.

## Prerequisites

- An input: a case ([`device acquire`](Device-Acquire) or [`import`](Import)),
  any directory of packages (for example APKs from another tool), or a single
  package file.
- Investigation findings need a case; a plain directory of APKs gets the
  static analysis and indicator matching only.
- Optional: STIX2 bundles (`--iocs`), alert hash sets (`--hashes`). See
  [Indicators and hash sets](Indicators-and-Hash-Sets).

No phone, no network.

## Usage

```sh
apex analyze ./case-42
apex analyze ./case-42 --iocs stalkerware.stix2 --iocs pegasus.stix2 --detail
apex analyze ./case-42 --hashes vics.json             # files on storage matching an alert hash set
apex analyze ./apks                                   # any directory of packages
apex analyze ./extraction --packages installed.txt    # match an app list against stalkerware
apex analyze ./case-42 --json -o reports/ --evidence ./case-42-analysis --fail-on high
```

| Option | Effect |
|---|---|
| `--iocs <FILE>` | STIX 2.x indicators to match (repeatable) |
| `--hashes <FILE>` | alert hash set: VICS JSON, NSRL, or one hash per line (repeatable) |
| `--packages <FILE>` | newline-separated package names to match against the stalkerware indicators |
| `--detail` | print the evidence under each finding |
| `--json`, `-o <DIR>` | one JSON report per package, plus `case_report.json`, in `<DIR>` (default: current directory) |
| `--evidence <DIR>` | offline evidence bundle hashing every input and report |
| `--fail-on <SEVERITY>` | exit 1 if a finding at this severity or above (`critical`, `high`, `medium`, `low`, `info`) |
| `--case-id`, `--examiner`, `--case-notes`, `--seal` | metadata for the evidence bundle |

## Output

A report per package, then an **Investigation** section (cases) or an **IOC
matching** section, a severity summary and a top-risk table. Every finding ID
is explained on [Findings](Findings).

Packages are scanned in parallel; a 20-app case takes about 30 s, mostly the
largest APKs.
