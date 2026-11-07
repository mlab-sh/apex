# verify

Re-hashes a case or evidence bundle and checks it against its manifest, and
the RFC 3161 timestamp if there is one.

## Prerequisites

- A directory with `manifest.json` and `manifest.json.sha256` (an acquisition,
  an import, an `--evidence` bundle), or the path to its `manifest.json`.

No phone, no network.

## Usage

```sh
apex verify ./case-42
apex verify ./case-42/manifest.json
```

Exit code **0** = `VERIFIED`, **1** = altered or incomplete.

## Checks

- The manifest's own hash matches `manifest.json.sha256`.
- Every artifact listed in the manifest is present with the recorded SHA-256.
  Files are matched by hash, so a moved or copied bundle verifies.
- Missing, altered and **unlisted** files are listed. Outputs written inside
  the case after acquisition (`timeline.csv`, `report.html`) show as unlisted:
  write them elsewhere with `-o`.
- External inputs (an imported extraction's source files) are counted as
  recorded, not re-hashed.
- With a timestamp ([`seal`](Seal)): the token's signature, and that it covers
  the current `manifest.json`.

See [Evidence and integrity](Evidence-and-Integrity).
