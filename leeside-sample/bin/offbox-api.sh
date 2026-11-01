#!/usr/bin/env bash
# Off-box partner API client: run from another machine against the public
# endpoint during the shadow week, so verified api traffic with a real JA4
# exists for the shadow report's headline (docs/windside.md section 6).
# Needs nothing but curl. Env:
#   LEESIDE_OFFBOX_BASE (required): the public app URL, no trailing slash
#   LEESIDE_OFFBOX_API_KEY (required): a key the app verifies
set -eu
BASE="${LEESIDE_OFFBOX_BASE:?set LEESIDE_OFFBOX_BASE, e.g. https://webapp.leeside.halowifi.com}"
KEY="${LEESIDE_OFFBOX_API_KEY:?set LEESIDE_OFFBOX_API_KEY to a key the app verifies}"
echo "offbox: $BASE/api/ping every 5-30s with bursts of 20; Ctrl-C stops" >&2
n=0
while true; do
    n=$((n + 1))
    curl -sf -o /dev/null -H "X-Api-Key: $KEY" "$BASE/api/ping" \
        || echo "offbox: call $n failed" >&2
    if [ $((RANDOM % 12)) -eq 0 ]; then
        for i in $(seq 1 20); do
            curl -sf -o /dev/null -H "X-Api-Key: $KEY" "$BASE/api/ping" \
                || echo "offbox: burst call failed" >&2
        done
        echo "offbox: burst of 20 after call $n" >&2
    fi
    sleep $((5 + RANDOM % 26))
done
