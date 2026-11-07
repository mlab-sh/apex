# seal

An **RFC 3161 trusted timestamp** of a case: a Time-Stamping Authority signs
the hash of `manifest.json`, which proves the case existed, unchanged, at
that time.

## Prerequisites

| Requirement | Why |
|---|---|
| A case with `manifest.json` | from [`device acquire`](Device-Acquire), [`import`](Import) or `analyze --evidence` |
| **The computer online** (not the phone) | the request goes to the TSA over HTTP(S) |
| A TSA URL | e.g. `https://freetsa.org/tsr`, or your organization's TSA |

Only the SHA-256 of `manifest.json` is sent; no case content leaves the
computer.

## Usage

```sh
apex seal ./case-42 --tsa https://freetsa.org/tsr
apex verify ./case-42                 # now also checks the timestamp
```

## Output

Two files next to the manifest: `manifest.json.tsq` (request) and
`manifest.json.tsr` (signed token). `seal` prints the time, the TSA and the
signature check, plus the `openssl ts -verify` command to check the chain to
a trusted root.

## What it proves

[`verify`](Verify) fails if `manifest.json` was edited after the timestamp,
even if someone recomputed `manifest.json.sha256`. APEX checks the token's
signature (RSA, ECDSA P-256 / P-384) against the signer certificate in the
token; the chain to a trusted root is checked with `openssl`.

Seal right after the acquisition, before any analysis output is written.
