#!/usr/bin/env bash
# Label every run database from its manifest (docs/windside.md step C):
# `leesided label-import` on runs/*/manifest.json with the run store as
# LEESIDED_DB. Idempotent (INSERT OR IGNORE); reruns report zero new.
set -eu
BIN="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="$(cd "$BIN/.." && pwd)"
LEESIDED="$SAMPLE/../leesided/target/release/leesided"
GEN_HASH_KEY="${GEN_HASH_KEY:-leeside-gen-test-key-do-not-use-in-production}"

[ -x "$LEESIDED" ] || { echo "build leesided first: (cd ../leesided && cargo build --release)" >&2; exit 1; }
[ -d "$SAMPLE/runs" ] || { echo "no runs/ directory; run bin/benign.sh / bin/attack.sh first" >&2; exit 1; }

n=0
for mf in "$SAMPLE"/runs/*/manifest.json; do
    [ -f "$mf" ] || continue
    dir="$(dirname "$mf")"
    [ -f "$dir/gen.sqlite" ] || { echo "no gen.sqlite next to $mf; skipping" >&2; continue; }
    if ! grep -q warmup_last_turn_id "$mf"; then
        echo "$(basename "$dir"): pre-watermark manifest, interval labels stand; skipping"
        continue
    fi
    out=$(LEESIDED_DB="$dir/gen.sqlite" LEESIDED_HASH_KEY="$GEN_HASH_KEY" "$LEESIDED" label-import "$mf")
    echo "$(basename "$dir"): $out"
    n=$((n + 1))
done
echo "labelled $n run(s)"
