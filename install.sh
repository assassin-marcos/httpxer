#!/usr/bin/env bash
# httpxer installer — one-liner usable, idempotent, sudo-free by default.
#
# Usage:
#   curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | bash
#   curl -sL https://raw.githubusercontent.com/assassin-marcos/httpxer/main/install.sh | INSTALL_DIR=~/bin bash
#
# What it does:
#   1. Detects host OS + arch (linux/macos × x86_64/arm64).
#   2. Downloads the matching release asset from the latest GitHub release.
#   3. Picks the best install dir: prefers a user-writable path that's
#      already on $PATH (~/.local/bin, ~/bin, /opt/homebrew/bin) so future
#      `httpxer -u` invocations need no sudo. Falls back to /usr/local/bin
#      (with sudo) only when nothing user-writable exists.
#
# After install, manage with the binary itself:
#   httpxer -c   # check-update (prints status, doesn't install)
#   httpxer -u   # install latest release (auto-relocates from root-owned paths)
#   httpxer -X   # uninstall
set -euo pipefail

REPO="assassin-marcos/httpxer"

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

# ─── Smart install-dir selection ────────────────────────────────────────────
# Priority order (first hit wins):
#   1. $INSTALL_DIR (explicit user override — honoured as-is)
#   2. User-writable dirs already on $PATH — picked WITHOUT sudo so future
#      `httpxer -u` runs as the calling user. macOS gets /opt/homebrew/bin
#      bumped above ~/.local/bin because that's the default Apple-Silicon
#      shell PATH; Linux prefers ~/.local/bin (XDG convention).
#   3. /usr/local/bin with sudo as last resort.
on_path() {
    case ":${PATH}:" in *":$1:"*) return 0 ;; *) return 1 ;; esac
}

try_dir_no_sudo() {
    local d="$1"
    if [ -d "$d" ] && [ -w "$d" ]; then return 0; fi
    if [ ! -e "$d" ] && mkdir -p "$d" 2>/dev/null && [ -w "$d" ]; then return 0; fi
    return 1
}

pick_install_dir() {
    if [ -n "${INSTALL_DIR:-}" ]; then
        echo "$INSTALL_DIR"; return
    fi
    local -a candidates
    if [ "$OS" = "darwin" ]; then
        candidates=("/opt/homebrew/bin" "$HOME/.local/bin" "$HOME/bin" "/usr/local/bin")
    else
        candidates=("$HOME/.local/bin" "$HOME/bin" "/usr/local/bin")
    fi
    # First pass: prefer dirs that are BOTH user-writable AND on $PATH
    local d
    for d in "${candidates[@]}"; do
        if try_dir_no_sudo "$d" && on_path "$d"; then
            echo "$d"; return
        fi
    done
    # Second pass: user-writable but not on $PATH (will warn after)
    for d in "${candidates[@]}"; do
        if try_dir_no_sudo "$d"; then
            echo "$d"; return
        fi
    done
    echo "/usr/local/bin"
}

INSTALL_DIR=$(pick_install_dir)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> Downloading ${ASSET}"
curl --proto '=https' --tlsv1.2 -fsSL "${URL}" -o "${TMP}/httpxer.tar.gz"

echo "==> Extracting"
tar -xzf "${TMP}/httpxer.tar.gz" -C "${TMP}"
chmod +x "${TMP}/httpxer"

echo "==> Installing to ${INSTALL_DIR}/httpxer"
if [ -w "${INSTALL_DIR}" ] || { [ ! -e "${INSTALL_DIR}" ] && mkdir -p "${INSTALL_DIR}" 2>/dev/null && [ -w "${INSTALL_DIR}" ]; }; then
    install -m 0755 "${TMP}/httpxer" "${INSTALL_DIR}/httpxer"
elif command -v sudo >/dev/null 2>&1; then
    echo "    (using sudo — ${INSTALL_DIR} is root-owned)"
    sudo install -m 0755 "${TMP}/httpxer" "${INSTALL_DIR}/httpxer"
else
    echo "Cannot write to ${INSTALL_DIR} and sudo is not available." >&2
    echo "Re-run with INSTALL_DIR=~/.local/bin (or similar writable path)." >&2
    exit 1
fi

if ! on_path "${INSTALL_DIR}"; then
    case "${SHELL:-}" in
        */zsh) RC_FILE=~/.zshrc ;;
        */fish) RC_FILE=~/.config/fish/config.fish ;;
        *) RC_FILE=~/.bashrc ;;
    esac
    echo
    echo "[!] ${INSTALL_DIR} is NOT on your \$PATH."
    echo "    Add it and reload your shell:"
    echo "        echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ${RC_FILE}"
    echo "        source ${RC_FILE}"
fi

echo
echo "Installed. Try it out:"
echo "    httpxer --version"
echo "    httpxer -c                                          # check for updates"
echo "    httpxer -u                                          # install latest (auto-relocates if needed)"
echo "    httpxer -l urls.txt -o out.jsonl                    # enrich (1 probe per host)"
echo "    httpxer -l urls.txt -path words.txt -o out.jsonl    # fuzz (host x path)"
