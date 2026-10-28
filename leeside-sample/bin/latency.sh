#!/usr/bin/env bash
# Mean latency of N requests against the running serve loop. Measures the
# current configuration only; see README for the on/off A/B procedure.
set -u

BASE="${BASE_URL:-http://127.0.0.1:8000}"
N="${N:-500}"

for _ in $(seq 1 "$N"); do
    curl -s -o /dev/null -w '%{time_total}\n' --max-time 10 "$BASE/"
done | awk -v n="$N" '{s+=$1} END {printf "%.3f ms/req over %d requests\n", s/n*1000, n}'
