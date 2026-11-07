# scan

Static security analysis of one app package.

## Prerequisites

- A package file: `.apk`, `.aab`, `.xapk` or `.ipa`. On a phone, get APKs with
  [`device dump`](Device#device-dump), or analyze them in place with
  [`device scan`](Device#device-scan).

No phone, no network.

## Usage

```sh
apex scan app.apk                       # terminal report
apex scan app.apk --detail              # evidence under each finding
apex scan app.apk --json -o report.json
apex scan app.apk --fail-on high        # exit 1 if a High or Critical finding (CI/CD)
```

| Option | Effect |
|---|---|
| `--show` | formatted terminal output (default) |
| `--json` | JSON output (to `-o`, or the terminal) |
| `-o, --output <FILE>` | JSON output file |
| `--detail` | evidence and metadata under each finding |
| `--fail-on <SEVERITY>` | exit 1 if a finding at this severity or above |

## Analyzers

`manifest`, `certificate`, `network`, `sast`, `api`, `permissions`, `binary`
(ELF checksec), `secrets` (with entropy), `jar_aar`, `dataflow`, `cloud`,
`privacy`, `binary_advanced`, `platform`, `supply_chain`.

Findings carry CWE and OWASP MASVS references and, where the capability maps
to an adversary technique, a MITRE ATT&CK for Mobile ID. The `privacy`
analyzer classifies embedded trackers with the Exodus Privacy taxonomy.

On `.ipa` files only `secrets`, `privacy` and `cloud` run: the others are
Android-specific.

The result is a weighted security score and findings by severity. Static
analysis shows what an app embeds and requests; what it contacts at runtime
needs dynamic analysis.
