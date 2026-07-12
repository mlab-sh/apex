#!/usr/bin/env bash
# Build + package apex release tarballs locally, mirroring the CI matrix.
#
# Usage:
#   scripts/build-release.sh                # build for the host target only
#   scripts/build-release.sh --all          # attempt all 4 release targets
#   scripts/build-release.sh <target>...    # build specific target triples
#
# Output: dist/apex-<version>-<target>.tar.gz (+ .sha256)
#
# Cross-compiling requires the matching toolchains, e.g. on Linux:
#   rustup target add aarch64-unknown-linux-gnu
#   sudo apt-get install -y gcc-aarch64-linux-gnu
# and on macOS both apple-darwin targets build natively.

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(awk -F '"' '/^version[[:space:]]*=/ {print $2; exit}' Cargo.toml)
ALL_TARGETS=(
  x86_64-apple-darwin
  aarch64-apple-darwin
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
)

# Resolve target list from args.
targets=()
if [[ $# -eq 0 ]]; then
  targets=("$(rustc -vV | awk '/^host:/ {print $2}')")
elif [[ "${1:-}" == "--all" ]]; then
  targets=("${ALL_TARGETS[@]}")
else
  targets=("$@")
fi

mkdir -p dist
echo "Building apex v${VERSION} for: ${targets[*]}"

for target in "${targets[@]}"; do
  echo
  echo "==> $target"
  rustup target add "$target" >/dev/null 2>&1 || true

  # Use the cross C compiler for the vendored libusb sources when cross-linking.
  env_prefix=()
  if [[ "$target" == "aarch64-unknown-linux-gnu" && "$(uname -s)" == "Linux" ]]; then
    env_prefix=(
      env
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
      CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
    )
  fi

  "${env_prefix[@]+"${env_prefix[@]}"}" cargo build --release --locked --target "$target"

  name="apex-${VERSION}-${target}"
  stage="$(mktemp -d)/${name}"
  mkdir -p "$stage"
  cp "target/${target}/release/apex" "$stage/"
  cp LICENSE README.md "$stage/"
  tar -czf "dist/${name}.tar.gz" -C "$(dirname "$stage")" "${name}"

  if command -v sha256sum >/dev/null 2>&1; then
    (cd dist && sha256sum "${name}.tar.gz" > "${name}.tar.gz.sha256")
  else
    (cd dist && shasum -a 256 "${name}.tar.gz" > "${name}.tar.gz.sha256")
  fi
  echo "    -> dist/${name}.tar.gz"
done

echo
echo "Done. Artifacts in dist/:"
ls -la dist
