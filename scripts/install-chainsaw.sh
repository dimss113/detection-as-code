#!/usr/bin/env bash
# Downloads the pinned Chainsaw release into .tools/ and verifies its SHA-256 before use.
set -euo pipefail

VERSION=2.17.1
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  asset=chainsaw_aarch64-apple-darwin.zip;        sha=6212c27d067e68bfe2c9def4314cda486b70a3e34c7596d392ecbd9eafb2cfc4 ;;
  Linux-x86_64)  asset=chainsaw_x86_64-unknown-linux-gnu.tar.gz; sha=fc25f1eafbbff3e858d8dfba508d5e227bb56ef4dccc4d5cd0bbd6e49798cb4f ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

mkdir -p .tools
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -sSfL -o "$tmp/$asset" "https://github.com/WithSecureLabs/chainsaw/releases/download/v$VERSION/$asset"
echo "$sha  $tmp/$asset" | shasum -a 256 -c - >/dev/null
case "$asset" in
  *.zip)    unzip -q "$tmp/$asset" -d "$tmp" ;;
  *.tar.gz) tar -xzf "$tmp/$asset" -C "$tmp" ;;
esac
install -m 0755 "$tmp/chainsaw/chainsaw" .tools/chainsaw
.tools/chainsaw --version
