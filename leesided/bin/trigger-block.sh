#!/usr/bin/env bash
# Trip venue-enumeration against a running leesided + sample app and show
# the 403. Puts leesided and the rule in enforce first. Each run uses a
# fresh User-Agent, so it is a new peer with an empty window.
#
#   bin/trigger-block.sh            # defaults match bin/e2e.sh
#   APP=http://127.0.0.1:8765 API=127.0.0.1:7391 DB=/tmp/leeside-live/leesided.sqlite bin/trigger-block.sh
# With a token set on the daemon, pass it as LEESIDED_API_TOKEN.
set -u
APP="${APP:-http://127.0.0.1:8765}"
API="${API:-127.0.0.1:7391}"
DB="${DB:-/tmp/leeside-live/leesided.sqlite}"
UA="walker-$(date +%s)/1.0"
AUTH=(-H "Authorization: Bearer ${LEESIDED_API_TOKEN:-}")
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

curl -sf "http://$API/health" >/dev/null || { echo "leesided not answering on $API"; exit 1; }
curl -sf -o /dev/null "$APP/" || { echo "app not answering on $APP"; exit 1; }

echo "== enforce: global mode and venue-enumeration"
curl -s "${AUTH[@]}" -X PUT "http://$API/mode" -H 'content-type: application/json' -d '{"mode":"enforce"}'; echo
curl -sf "${AUTH[@]}" "http://$API/rules/venue-enumeration" \
  | python3 -c 'import sys,json; r=json.load(sys.stdin)["rule"]; r["mode"]="enforce"; print(json.dumps(r))' \
  | curl -s "${AUTH[@]}" -X PUT "http://$API/rules/venue-enumeration" -H 'content-type: application/json' -d @-; echo

get() { curl -s -o /dev/null -c "$JAR" -b "$JAR" -A "$UA" -w '%{http_code}' "$APP$1"; }

echo "== walk /venues/1..20 as $UA (6 exist, the rest 404)"
for id in $(seq 1 20); do printf '%s:%s ' "$id" "$(get "/venues/$id")"; done; echo

echo "== same client, real venues again (expect 403)"
for id in 1 2 3; do echo "  /venues/$id -> $(get "/venues/$id")"; done
echo "  GET / same session -> $(get /) (sticky)"
echo "  GET / no cookie    -> $(curl -s -o /dev/null -A "$UA" -w '%{http_code}' "$APP/")"

if [ -f "$DB" ]; then
  echo "== decisions"
  sqlite3 "$DB" "select scope, action, rule, expires_at - strftime('%s','now') || 's left' from decisions order by rowid desc limit 3;"
fi
