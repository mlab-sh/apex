# Evidence and integrity

Every acquisition, import and `analyze --evidence` writes an evidence bundle.

## The bundle

| File | Content |
|---|---|
| `audit.jsonl` | every ADB action in order: UTC timestamp, command, success, SHA-256 of its raw output, byte count, duration |
| `manifest.json` | tool version; case metadata (case ID, examiner, notes, seal, mandate); operation (acquisition, triage, import, offline analysis); session start and end; transport (USB serial or TCP address) and ADB key path; device identifiers; the SHA-256 of every artifact and report; for imports, the hash of every source file read; a methodology statement of what was touched |
| `manifest.json.sha256` | detached hash of the manifest |

Reports and artifacts are listed by path relative to the case, so the case
can be moved.

## Checking it

```sh
apex verify ./case-42
```

See [verify](Verify). A tampered file fails; an edited manifest with a
recomputed `.sha256` passes the hash check but fails against an RFC 3161
timestamp.

## Timestamping it

```sh
apex seal ./case-42 --tsa https://freetsa.org/tsr
```

See [seal](Seal). Seal right after acquisition.

## Good practice

- Verify and seal before any analysis.
- Write analysis outputs outside the case (`-o`).
- Keep a copy on write-once media; `verify` works on any copy.
- Databases are always opened from temporary copies: analysis never changes
  the evidence.
