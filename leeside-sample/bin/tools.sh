#!/usr/bin/env bash
# Generator toolchain for bin/benign.sh and bin/attack.sh (DEPLOY.md
# "Generator tools"). Run as the user that will run the generators, WITHOUT
# a sudo prefix: only the apt step and the /usr/local/bin installs use sudo.
# Idempotent: every step skips what is already present.
set -eu
BIN="$(cd "$(dirname "$0")" && pwd)"
FFUF_VER=2.3.0
NUCLEI_VER=3.11.1
case "$(uname -m)" in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

echo "== playwright browsers (user cache) and OS deps (root)"
(cd "$BIN/.." && npx playwright install chromium firefox webkit)
(cd "$BIN/.." && sudo npx playwright install-deps chromium firefox webkit)

install_gh_release() { # $1=repo $2=version $3=asset $4=binary $5=unpack(z|t)
    if command -v "$4" >/dev/null; then
        echo "== $4 already on PATH: $(command -v "$4")"
        return 0
    fi
    echo "== $4 v$2 from github ($1)"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    curl -sfL -o "$tmp/pkg" "https://github.com/$1/releases/download/v$2/$3"
    if [ "$5" = z ]; then
        unzip -q -o "$tmp/pkg" "$4" -d "$tmp"
    else
        tar -xzf "$tmp/pkg" -C "$tmp" "$4"
    fi
    sudo install -m755 "$tmp/$4" /usr/local/bin/"$4"
    trap - EXIT
    rm -rf "$tmp"
}

install_gh_release ffuf/ffuf "$FFUF_VER" "ffuf_${FFUF_VER}_linux_${GOARCH}.tar.gz" ffuf t
install_gh_release projectdiscovery/nuclei "$NUCLEI_VER" "nuclei_${NUCLEI_VER}_linux_${GOARCH}.zip" nuclei z

if command -v sqlmap >/dev/null; then
    echo "== sqlmap already on PATH: $(command -v sqlmap)"
else
    echo "== sqlmap from apt"
    sudo apt-get install -y sqlmap
fi

echo "== nuclei templates (per-user, into ~/nuclei-templates)"
nuclei -update-templates

echo "OK: $(ffuf -V 2>&1 | head -1) / $(nuclei -version 2>&1 | head -1) / $(sqlmap --version 2>&1 | head -1)"
