#!/usr/bin/env bash
# Export every run database to one training CSV (docs/windside.md step D):
# `leesided export` per runs/*/gen.sqlite, concatenated with a single
# header, plus a merged manifest with per-kind row counts.
set -eu
BIN="$(cd "$(dirname "$0")" && pwd)"
SAMPLE="$(cd "$BIN/.." && pwd)"
LEESIDED="$SAMPLE/../leesided/target/release/leesided"
OUT="${1:-$SAMPLE/runs/dataset.csv}"

[ -x "$LEESIDED" ] || { echo "build leesided first: (cd ../leesided && cargo build --release)" >&2; exit 1; }
[ -d "$SAMPLE/runs" ] || { echo "no runs/ directory; run bin/benign.sh / bin/attack.sh first" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
first=1
n=0
for dir in "$SAMPLE"/runs/*/; do
    [ -f "$dir/gen.sqlite" ] || continue
    [ -f "$dir/manifest.json" ] || continue
    name=$(basename "$dir")
    case "$name" in dataset*) continue ;; esac
    run_id=$(python3 -c "import json;print(json.load(open('$dir/manifest.json'))['run_id'])")
    LEESIDED_DB="$dir/gen.sqlite" "$LEESIDED" export --since 0 --run-id "$run_id" --out "$work/$name.csv"
    if [ "$first" = 1 ]; then
        cat "$work/$name.csv" >"$OUT"
        first=0
    else
        tail -n +2 "$work/$name.csv" >>"$OUT"
    fi
    n=$((n + 1))
done
[ "$n" -gt 0 ] || { echo "no labelled run databases in runs/" >&2; exit 1; }

python3 - "$OUT" <<'EOF'
import csv, json, sys
from collections import Counter
out = sys.argv[1]
with open(out) as f:
    r = csv.DictReader(f)
    names = [c for c in r.fieldnames if c not in
             ("scope", "scope_id", "surface", "kind", "run_id", "ts_us", "ingest_seq",
              "label", "source", "confidence")]
    kinds, sources, scopes = Counter(), Counter(), Counter()
    runs = {}
    ts_min, ts_max, rows = None, None, 0
    for row in r:
        rows += 1
        kind = row["kind"] or "null"
        kinds[kind] += 1
        runs.setdefault(kind, Counter())[row["run_id"]] += 1
        sources[row["source"]] += 1
        scopes[row["scope"]] += 1
        ts = int(row["ts_us"])
        ts_min = ts if ts_min is None else min(ts_min, ts)
        ts_max = ts if ts_max is None else max(ts_max, ts)
with open(out + ".manifest.json", "w") as f:
    json.dump({
        "features_version": 2,
        "feature_names": names,
        "rows": rows,
        "counts_per_scope": dict(scopes),
        "counts_per_kind": {k: {"total": n, "runs": dict(runs[k])} for k, n in kinds.items()},
        "label_counts_by_source": dict(sources),
        "ts_min": ts_min,
        "ts_max": ts_max,
    }, f, indent=2)
print(f"dataset: {rows} rows from {len(kinds)} kinds -> {out}")
for kind in sorted(kinds):
    print(f"  {kind}: {kinds[kind]} across {len(runs[kind])} run(s)")
EOF
echo "exported $n run(s)"
