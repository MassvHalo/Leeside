#!/usr/bin/env bash
# End to end on one box: release leesided + `php artisan serve` from
# ../leeside-sample + bin/traffic.sh, then promote the OTP rule to enforce
# and show a live 429. Needs: cargo, php, curl, sqlite3, python3.
#
#   cargo build --release && bin/e2e.sh
#
# Sockets go under /tmp because sun_path is capped at 108 bytes.
set -u
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SAMPLE="$HERE/../leeside-sample"
WORK="${E2E_DIR:-/tmp/leeside-e2e}"
API=127.0.0.1:7391
PORT=8765
rm -rf "$WORK"; mkdir -p "$WORK/run"
if curl -sf "http://$API/health" >/dev/null 2>&1; then
  echo "something already answers on $API (a previous run?); stop it first: pgrep -a leesided" >&2
  exit 1
fi

cleanup() { kill "${PPID_:-}" 2>/dev/null; kill -INT "${LPID:-}" 2>/dev/null; wait "${LPID:-}" 2>/dev/null; }
trap cleanup EXIT

LEESIDED_SOCKET_DIR="$WORK/run" LEESIDED_DB="$WORK/leesided.sqlite" LEESIDED_API="$API" \
LEESIDED_RULES_DIR="$HERE/rules/install" RUST_LOG=info \
  "$HERE/target/release/leesided" serve >"$WORK/leesided.log" 2>&1 &
LPID=$!
for _ in $(seq 1 50); do curl -sf "http://$API/health" >/dev/null && break; sleep 0.1; done
echo "== leesided up"; curl -s "http://$API/health" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("mode", h["mode"], "| rules", h["rules"]["loaded"], "| hash", h["rules"]["hash"][:12])'

cd "$SAMPLE"
LEESIDE_TRANSPORT=udg LEESIDE_EVENTS_SOCKET="$WORK/run/events.sock" LEESIDE_CHECK_SOCKET="$WORK/run/check.sock" \
  php artisan serve --host 127.0.0.1 --port $PORT >"$WORK/php.log" 2>&1 &
PPID_=$!
for _ in $(seq 1 100); do curl -sf -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done

echo "== bin/traffic.sh in monitor mode (benign browse, validation burst, enumeration)"
BASE_URL="http://127.0.0.1:$PORT" JAR="$WORK/jar.txt" bash bin/traffic.sh
sleep 11   # one stats flush
echo "== what leesided saw"
curl -s "http://$API/health" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("checks", h["check"]["total"], "| events", h["ingest"]["total"], "| sessions", h["windows"]["sessions"], "| unjoined", h["check"]["unjoined"], "| dropped", h["store"]["dropped"])'
sqlite3 "$WORK/leesided.sqlite" "select 'turns', count(*) from turns union all select 'joined to a verdict', count(*) from turns where verdict is not null union all select 'feature rows', count(*) from features;"

echo "== promote: global enforce, portal-otp-burst to enforce"
curl -s -X PUT "http://$API/mode" -H 'content-type: application/json' -d '{"mode":"enforce"}'; echo
curl -s "http://$API/rules/portal-otp-burst" | python3 -c 'import sys,json; r=json.load(sys.stdin)["rule"]; r["mode"]="enforce"; print(json.dumps(r))' > "$WORK/otp.json"
curl -s -X PUT "http://$API/rules/portal-otp-burst" -H 'content-type: application/json' -d @"$WORK/otp.json"; echo

echo "== fresh session, seven bad OTPs: five 401s, then 429"
rm -f "$WORK/jar2.txt"
for otp in 000001 000002 000003 000004 000005 000006 000007; do
  curl -s -o /dev/null -c "$WORK/jar2.txt" -b "$WORK/jar2.txt" -A leeside-traffic/1.0 -w "  otp=$otp -> %{http_code}\n" -d "phone=0661111111&otp=$otp" "http://127.0.0.1:$PORT/portal/login"
done
curl -s -i -c "$WORK/jar2.txt" -b "$WORK/jar2.txt" -A leeside-traffic/1.0 -d "phone=0661111111&otp=123456" "http://127.0.0.1:$PORT/portal/login" | grep -iE "^HTTP|retry-after"
curl -s -o /dev/null -c "$WORK/jar2.txt" -b "$WORK/jar2.txt" -A leeside-traffic/1.0 -w "  same session GET / -> %{http_code} (sticky)\n" "http://127.0.0.1:$PORT/"
curl -s -o /dev/null -A leeside-traffic/1.0 -w "  no cookie  GET / -> %{http_code} (untouched)\n" "http://127.0.0.1:$PORT/"

echo "== every turn, by surface, credential status and verdict (events, not probes)"
sqlite3 "$WORK/leesided.sqlite" "select coalesce(surface,'v1'), coalesce(credential_status,'-'), coalesce(verdict,'no check'), count(*) from turns group by 1,2,3 order by 4 desc;"
echo "== the decision in SQLite"
sqlite3 "$WORK/leesided.sqlite" "select scope, action, mode, rule, expires_at - strftime('%s','now') || 's left' from decisions;"
echo "== logs: $WORK/leesided.log, $WORK/php.log; db: $WORK/leesided.sqlite"
