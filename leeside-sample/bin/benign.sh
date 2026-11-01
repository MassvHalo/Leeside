#!/usr/bin/env bash
# Benign traffic (docs/windside.md section 4): browser page walks under
# Playwright, steady partner API calls, bursty signed webhooks. One
# invocation is one run with a fresh store and one manifest; `all` runs
# every kind in sequence. Target: the local stack on 7391, never 7390.
set -eu
BIN="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=gen-lib.sh
source "$BIN/gen-lib.sh"

traffic_browser() { # $1=base $2=work $3=browser
    # No sent file: back navigations serve from memory cache and emit
    # synthetic response events, so the walk cannot count what reached
    # the app. Sent derives from the artisan log (served minus warmups
    # and static assets), which is the authority for browser runs.
    node "$BIN/benign-walk.mjs" --browser "$3" --base "$1" --views 100
}

traffic_chromium() { traffic_browser "$1" "$2" chromium; }
traffic_firefox() { traffic_browser "$1" "$2" firefox; }
traffic_webkit() { traffic_browser "$1" "$2" webkit; }

traffic_api() { # $1=base $2=work: steady partner calls plus bursts (210)
    local base="$1" work="$2" key="${LEESIDE_DEMO_API_KEY:-demo-api-key}" i b
    for i in $(seq 1 60); do
        curl -sf -o /dev/null -H "X-Api-Key: $key" "$base/api/ping"
        sleep $((2 + RANDOM % 3))
    done
    for b in $(seq 1 3); do
        for i in $(seq 1 50); do
            curl -sf -o /dev/null -H "X-Api-Key: $key" "$base/api/ping"
        done
        sleep 2
    done
    echo 210 >"$work/sent"
    echo "   api: 60 steady + 3 bursts of 50 partner calls"
}

traffic_webhook() { # $1=base $2=work: seventeen signed bursts of a dozen (204)
    local base="$1" work="$2" body='{"order":42}' i b
    local sig
    sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "${LEESIDE_DEMO_WEBHOOK_SECRET:-demo-webhook-secret}" | sed 's/^.* //')
    for b in $(seq 1 17); do
        for i in $(seq 1 12); do
            curl -sf -o /dev/null -H 'Content-Type: application/json' \
                -H "X-Signature: $sig" -H "X-Signer: partner_$b" \
                -d "$body" "$base/webhooks/demo"
        done
        sleep 5
    done
    echo 204 >"$work/sent"
    echo "   webhook: 17 signed bursts of 12"
}

case "${1:-all}" in
    chromium) gen_run benign-chromium traffic_chromium ;;
    firefox) gen_run benign-firefox traffic_firefox ;;
    webkit) gen_run benign-webkit traffic_webkit ;;
    api) gen_run benign-api traffic_api ;;
    webhook) gen_run benign-webhook traffic_webhook ;;
    all)
        gen_run benign-chromium traffic_chromium
        gen_run benign-firefox traffic_firefox
        gen_run benign-webkit traffic_webkit
        gen_run benign-api traffic_api
        gen_run benign-webhook traffic_webhook
        ;;
    *) echo "usage: $0 [chromium|firefox|webkit|api|webhook|all]" >&2; exit 1 ;;
esac
