#!/usr/bin/env bash
# Regenerate src/stalkerware_iocs.rs from the Echap stalkerware-indicators feed.
#
# Keeps the bundled package-name indicators fresh (the upstream list evolves as
# new stalkerware appears/disappears). Pulls ioc.yaml, extracts every package
# name, deduplicates, and rewrites the Rust source in the same format.
#
# Usage:
#   scripts/update-iocs.sh            # fetch upstream and regenerate
#   scripts/update-iocs.sh <file>     # regenerate from a local ioc.yaml
#
# Source: https://github.com/AssoEchap/stalkerware-indicators (ioc.yaml)
set -euo pipefail

IOC_URL="https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/src/stalkerware_iocs.rs"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

SRC="${1:-}"
if [[ -n "$SRC" ]]; then
  cp "$SRC" "$TMP/ioc.yaml"
else
  echo "Fetching $IOC_URL …" >&2
  curl -fsSL "$IOC_URL" -o "$TMP/ioc.yaml"
fi

# Extract the `- item` list entries under each `packages:` / `certificates:`
# key with a small state machine (avoids a hard PyYAML dependency).
python3 - "$TMP/ioc.yaml" "$TMP" <<'PY2'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
want = {
    "packages": re.compile(r'^[A-Za-z][A-Za-z0-9_.]+$'),
    "certificates": re.compile(r'^[0-9A-Fa-f]{40}$'),  # SHA-1 of the signing cert
}
found = {k: set() for k in want}
cur = None
for ln in lines:
    if not ln.strip():
        continue
    m_key = re.match(r'^\s*([a-z_]+):\s*$', ln)
    if m_key:
        cur = m_key.group(1) if m_key.group(1) in want else None
        continue
    if cur:
        m_item = re.match(r'^\s*-\s*(\S+)\s*$', ln)
        if m_item:
            val = m_item.group(1).strip().strip('"').strip("'")
            if want[cur].match(val):
                found[cur].add(val.upper() if cur == "certificates" else val)
            continue
        cur = None  # any other line closes the block
for k, vals in found.items():
    with open(f"{sys.argv[2]}/{k}.txt", "w") as f:
        f.write("".join(v + "\n" for v in sorted(vals)))
PY2

COUNT="$(wc -l < "$TMP/packages.txt" | tr -d ' ')"
CERTS="$(wc -l < "$TMP/certificates.txt" | tr -d ' ')"
if [[ "$COUNT" -lt 100 || "$CERTS" -lt 50 ]]; then
  echo "Refusing to write: only $COUNT packages / $CERTS certs parsed. Aborting." >&2
  exit 1
fi

{
  echo '//! Bundled stalkerware / spyware indicators.'
  echo '//!'
  echo '//! Exact Android package names and signing-certificate SHA-1s of known'
  echo '//! stalkerware and "watchware" apps, sourced from the Echap'
  echo '//! `stalkerware-indicators` project (`ioc.yaml`):'
  echo '//! <https://github.com/AssoEchap/stalkerware-indicators> (CC0/GPL indicators).'
  echo '//! A hit is a strong signal but not proof; regenerate periodically as the'
  echo '//! upstream list evolves. Domains and APK hashes: pass the upstream'
  echo '//! `generated/stalkerware.stix2` to `--iocs`.'
  echo '//!'
  echo '//! Regenerate: scripts/update-iocs.sh'
  echo ''
  echo 'pub const STALKERWARE_PACKAGES: &[&str] = &['
  sed 's/.*/    "&",/' "$TMP/packages.txt"
  echo '];'
  echo ''
  echo '/// Uppercase hex SHA-1 of the DER signing certificate.'
  echo 'pub const STALKERWARE_CERTS: &[&str] = &['
  sed 's/.*/    "&",/' "$TMP/certificates.txt"
  echo '];'
} > "$OUT"

echo "Wrote $COUNT packages + $CERTS certs → $OUT" >&2
echo "Review the diff, then: cargo test --release" >&2
