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

# Extract package names: a small state machine that captures the `- item` list
# entries under each `packages:` key (avoids a hard PyYAML dependency).
python3 - "$TMP/ioc.yaml" > "$TMP/packages.txt" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
pkgs, in_pkgs = set(), False
for ln in lines:
    if not ln.strip():
        continue
    # A `packages:` key opens the block; its list items sit at the same or a
    # deeper indent (YAML). Any other `key:` line closes it.
    if re.match(r'^\s*packages:\s*$', ln):
        in_pkgs = True
        continue
    if in_pkgs:
        m_item = re.match(r'^\s*-\s*(\S+)\s*$', ln)
        if m_item:
            val = m_item.group(1).strip().strip('"').strip("'")
            # Package names: dotted identifiers, letters/digits/_/. only.
            if re.match(r'^[A-Za-z][A-Za-z0-9_.]+$', val):
                pkgs.add(val)
            continue
        # Any non-list line (e.g. `certificates:`, next `- name:`) ends it.
        in_pkgs = False
for p in sorted(pkgs):
    print(p)
PY

COUNT="$(wc -l < "$TMP/packages.txt" | tr -d ' ')"
if [[ "$COUNT" -lt 100 ]]; then
  echo "Refusing to write: only $COUNT packages parsed (expected >100). Aborting." >&2
  exit 1
fi

{
  echo '//! Bundled stalkerware / spyware package-name indicators.'
  echo '//!'
  echo '//! Exact Android package names of known stalkerware and "watchware" apps,'
  echo '//! sourced from the Echap `stalkerware-indicators` project (`ioc.yaml`):'
  echo '//! <https://github.com/AssoEchap/stalkerware-indicators> (CC0/GPL indicators).'
  echo '//! Matching is exact-package-name only — a hit is a strong signal but not'
  echo '//! proof; regenerate periodically as the upstream list evolves.'
  echo '//!'
  echo '//! Regenerate: scripts/update-iocs.sh'
  echo ''
  echo 'pub const STALKERWARE_PACKAGES: &[&str] = &['
  sed 's/.*/    "&",/' "$TMP/packages.txt"
  echo '];'
} > "$OUT"

echo "Wrote $COUNT package indicators → $OUT" >&2
echo "Review the diff, then: cargo test --release" >&2
