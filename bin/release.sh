#!/usr/bin/env bash
# bin/release.sh <tag>: stage every release asset under
# /tmp/leeside-release/<short-sha>/ and print the gh release command.
# The operator runs it and uploads; this script never touches gh.
# Refuses on a dirty tree or an unpushed HEAD.
set -euo pipefail

die() { printf 'release: %s\n' "$1" >&2; exit 1; }
log() { printf 'release: %s\n' "$*"; }

[ "${1:-}" != "" ] || die "usage: bin/release.sh <tag>  (e.g. bin/release.sh v0.1.0)"
TAG="$1"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [ -n "$(git status --porcelain)" ]; then
    die "tree is dirty; commit or stash first"
fi
git fetch origin -q || die "cannot fetch origin; check network access, then rerun"
HEAD_SHA="$(git rev-parse HEAD)"
[ "$HEAD_SHA" = "$(git rev-parse origin/master)" ] \
    || die "HEAD is not origin/master; push (or pull) first"
SHORT="$(git rev-parse --short HEAD)"
STAGE="/tmp/leeside-release/$SHORT"
rm -rf "$STAGE"
mkdir -p "$STAGE"

NATIVE_ARCH="$(uname -m)"
case "$NATIVE_ARCH" in
    x86_64) NATIVE_ASSET="leesided-x86_64-linux" ;;
    aarch64) NATIVE_ASSET="leesided-aarch64-linux" ;;
    *) die "native arch $NATIVE_ARCH has no asset name" ;;
esac

log "== native binary ($NATIVE_ASSET)"
(cd leesided && cargo build --release) || die "native build failed"
cp "leesided/target/release/leesided" "$STAGE/$NATIVE_ASSET"
chmod +x "$STAGE/$NATIVE_ASSET"
strip "$STAGE/$NATIVE_ASSET"

if [ "$NATIVE_ARCH" != "x86_64" ]; then
    log "== cross binary (leesided-x86_64-linux)"
    command -v x86_64-linux-gnu-gcc >/dev/null || die "no x86_64 cross gcc; run: sudo apt-get install -y gcc-x86-64-linux-gnu"
    rustup target list --installed 2>/dev/null | grep -q 'x86_64-unknown-linux-gnu' \
        || die "no x86_64 rust target; run: rustup target add x86_64-unknown-linux-gnu"
    (cd leesided && CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc \
        CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc \
        AR_x86_64_unknown_linux_gnu=x86_64-linux-gnu-ar \
        cargo build --release --target x86_64-unknown-linux-gnu) || die "cross build failed"
    cp "leesided/target/x86_64-unknown-linux-gnu/release/leesided" "$STAGE/leesided-x86_64-linux"
    chmod +x "$STAGE/leesided-x86_64-linux"
    x86_64-linux-gnu-strip "$STAGE/leesided-x86_64-linux"
    file "$STAGE/leesided-x86_64-linux" | grep -q 'x86-64' || die "cross binary is not x86-64"
    x86_64-linux-gnu-objdump -p "$STAGE/leesided-x86_64-linux" | grep NEEDED \
        | grep -qvE 'libgcc_s\.so|libm\.so|libc\.so|ld-linux' \
        && die "cross binary links unexpected libraries" || true
else
    log "== cross binary skipped (native is x86_64)"
fi

log "== dashboard"
[ -d leesided/ui/node_modules ] || (cd leesided/ui && npm ci) || die "npm ci failed"
(cd leesided/ui && npm run build) || die "dashboard build failed"
[ -f leesided/ui/dist/index.html ] || die "ui/dist has no index.html after the build"
# shellcheck disable=SC2046
(cd leesided/ui/dist && tar --owner=0 --group=0 --mtime='2026-01-01' -cf - \
    $(ls | LC_ALL=C sort) | gzip -n > "$STAGE/leeside-ui.tar.gz") \
    || die "ui tarball failed"
tar -tzf "$STAGE/leeside-ui.tar.gz" | grep -qx 'index.html' || die "ui tarball has no top-level index.html"

log "== rules tarball"
rm -rf "$STAGE/rtb" && mkdir -p "$STAGE/rtb/data"
cp leesided/rules/generic/auth-burst-peer.json leesided/rules/generic/credential-spray.json \
    leesided/rules/generic/http-404-scan.json leesided/rules/generic/server-error-watch.json "$STAGE/rtb/"
cp leesided/data/ja4-classes.json "$STAGE/rtb/data/"
tar --owner=0 --group=0 --mtime='2026-01-01' -cf - -C "$STAGE/rtb" \
    auth-burst-peer.json credential-spray.json http-404-scan.json server-error-watch.json \
    data/ja4-classes.json \
    | gzip -n > "$STAGE/leesided-rules.tar.gz" || die "rules tarball failed"
rm -rf "$STAGE/rtb"

log "== model"
[ -f windside/models/0.1.0/manifest.json ] && [ -f windside/models/0.1.0/model.txt ] \
    || die "windside/models/0.1.0 is missing manifest.json or model.txt"
cp windside/models/0.1.0/manifest.json windside/models/0.1.0/model.txt "$STAGE/"

log "== hashes"
ASSETS=()
[ -f "$STAGE/leesided-x86_64-linux" ] && ASSETS+=(leesided-x86_64-linux) || true
[ -f "$STAGE/leesided-aarch64-linux" ] && ASSETS+=(leesided-aarch64-linux) || true
ASSETS+=(manifest.json model.txt leeside-ui.tar.gz leesided-rules.tar.gz)
(cd "$STAGE" && for f in "${ASSETS[@]}"; do sha256sum "$f" > "$f.sha256"; done) || die "hashing failed"

UPLOAD=()
for f in "${ASSETS[@]}"; do UPLOAD+=("$f" "$f.sha256"); done
TITLE="Leeside ${TAG#v}"
printf '\nStaged %s (%s):\n' "$STAGE" "$SHORT"
(cd "$STAGE" && ls -la "${ASSETS[@]}" | awk '{print " ", $5, $9}')
printf '\nUpload with:\n\ncd %s && gh release create %s' "$STAGE" "$TAG"
printf ' %s' "${UPLOAD[@]}"
printf ' --title "%s" --notes "Release build: leesided binaries, Windside model 0.1.0, generic rule set, dashboard."\n' "$TITLE"
