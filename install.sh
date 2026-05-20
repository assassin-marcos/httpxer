#!/usr/bin/env bash
# httpxer installer — one-liner usable, idempotent, no sudo unless needed.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash
#   curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | INSTALL_DIR=~/bin bash
#
# What it does:
#   1. Detects host OS + arch (linux/macos × x86_64/arm64).
#   2. Downloads the matching release asset from the latest GitHub release.
#   3. Drops the `httpxer` binary into /usr/local/bin (sudo only if needed).
#
# After install, manage with the binary itself:
#   httpxer -c   # check-update (prints status, doesn't install)
#   httpxer -u   # install latest release (replaces the binary in place)
#   httpxer -X   # uninstall
set -euo pipefail

REPO="assassin-marcos/httpxer"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "${OS}-${ARCH}" in
    linux-x86_64)          ASSET="httpxer-x86_64-unknown-linux-gnu.tar.gz" ;;
    darwin-x86_64)         ASSET="httpxer-x86_64-apple-darwin.tar.gz" ;;
    darwin-arm64 | darwin-aarch64) ASSET="httpxer-aarch64-apple-darwin.tar.gz" ;;
    *)
        echo "Unsupported platform: ${OS}-${ARCH}" >&2
        echo "Open an issue: https://github.com/${REPO}/issues" >&2
        exit 1
        ;;
esac

URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

if ! command -v curl >/dev/null 2>&1; then
    echo "curl is required but not installed." >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading ${ASSET}"
curl --proto '=https' --tlsv1.2 -fsSL "${URL}" -o "${TMP}/httpxer.tar.gz"

echo "==> Extracting"
tar -xzf "${TMP}/httpxer.tar.gz" -C "${TMP}"
chmod +x "${TMP}/httpxer"

echo "==> Installing to ${INSTALL_DIR}/httpxer"
if [ -w "${INSTALL_DIR}" ]; then
    install -m 0755 "${TMP}/httpxer" "${INSTALL_DIR}/httpxer"
elif command -v sudo >/dev/null 2>&1; then
    sudo install -m 0755 "${TMP}/httpxer" "${INSTALL_DIR}/httpxer"
else
    echo "Cannot write to ${INSTALL_DIR} and sudo is not available." >&2
    echo "Re-run with INSTALL_DIR=~/bin (or similar writable path)." >&2
    exit 1
fi

echo
echo "Installed. Try it out:"
echo "    httpxer --version"
echo "    httpxer -c                  # check for updates"
echo "    httpxer -u                  # install latest"
echo "    httpxer -l urls.txt -o out.jsonl   # run a probe"
