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
# Normalised: the private nginx's root must not contain a .., php-fpm answers
# "Primary script unknown" for a SCRIPT_FILENAME with one in it.
SAMPLE="$(cd "$HERE/../leeside-sample" && pwd)"
WORK="${E2E_DIR:-/tmp/leeside-e2e}"
API=127.0.0.1:7391
PORT=8765
# One hash key per install (docs/brief.md). The e2e pins a fixed test value so
# ip/net hashes and cluster keys exist and are deterministic, whatever the
# operator's environment holds. Never a production key.
E2E_HASH_KEY="${E2E_HASH_KEY:-leeside-e2e-test-key-do-not-use-in-production}"
# Collect failures and report them all at the end; the script exits 1 naming
# each one, so a green run means every assert below held.
FAIL=""
rm -rf "$WORK"; mkdir -p "$WORK/run"
if curl -sf "http://$API/health" >/dev/null 2>&1; then
  echo "something already answers on $API (a previous run?); stop it first: pgrep -a leesided" >&2
  exit 1
fi

cleanup() { kill "${PPID_:-}" "${TPID:-}" "${NGX_PID:-}" "${FPM_PID:-}" 2>/dev/null; kill -INT "${LPID:-}" 2>/dev/null; wait "${LPID:-}" 2>/dev/null; }
trap cleanup EXIT

LEESIDED_SOCKET_DIR="$WORK/run" LEESIDED_DB="$WORK/leesided.sqlite" LEESIDED_API="$API" \
LEESIDED_RULES_DIR="$HERE/rules/install" LEESIDED_HASH_KEY="$E2E_HASH_KEY" RUST_LOG=info \
  "$HERE/target/release/leesided" serve >"$WORK/leesided.log" 2>&1 &
LPID=$!
for _ in $(seq 1 50); do curl -sf "http://$API/health" >/dev/null && break; sleep 0.1; done
echo "== leesided up"; curl -s "http://$API/health" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("mode", h["mode"], "| rules", h["rules"]["loaded"], "| hash", h["rules"]["hash"][:12])'

cd "$SAMPLE"
LEESIDE_TRANSPORT=udg LEESIDE_EVENTS_SOCKET="$WORK/run/events.sock" LEESIDE_CHECK_SOCKET="$WORK/run/check.sock" LEESIDE_HASH_KEY="$E2E_HASH_KEY" \
  php artisan serve --host 127.0.0.1 --port $PORT >"$WORK/php.log" 2>&1 &
PPID_=$!
for _ in $(seq 1 100); do curl -sf -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done

echo "== bin/traffic.sh in monitor mode (benign browse, validation burst, enumeration)"
BASE_URL="http://127.0.0.1:$PORT" JAR="$WORK/jar.txt" bash bin/traffic.sh
echo "== machine surfaces: two signed webhooks, one unsigned, one good API key, three wrong keys"
BODY='{"order":42}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "${LEESIDE_DEMO_WEBHOOK_SECRET:-demo-webhook-secret}" | sed 's/^.* //')
for signer in acct_1 acct_2; do
  curl -s -o /dev/null -w "  webhook signed by $signer -> %{http_code}\n" -H 'Content-Type: application/json' -H "X-Signature: $SIG" -H "X-Signer: $signer" -d "$BODY" "http://127.0.0.1:$PORT/webhooks/demo"
done
curl -s -o /dev/null -w "  webhook unsigned -> %{http_code}\n" -H 'Content-Type: application/json' -d "$BODY" "http://127.0.0.1:$PORT/webhooks/demo"
curl -s -o /dev/null -w "  api/ping good key -> %{http_code}\n" -H "X-Api-Key: ${LEESIDE_DEMO_API_KEY:-demo-api-key}" "http://127.0.0.1:$PORT/api/ping"
for k in wrong-1 wrong-2 wrong-3; do
  curl -s -o /dev/null -w "  api/ping $k -> %{http_code}\n" -H "X-Api-Key: $k" "http://127.0.0.1:$PORT/api/ping"
done
sleep 11   # one stats flush
echo "== what leesided saw: traffic script + machine surfaces only (OTP, tag, tap acts still to come)"
curl -s "http://$API/health" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("checks", h["check"]["total"], "| events", h["ingest"]["total"], "| sessions", h["windows"]["sessions"], "| unjoined", h["check"]["unjoined"], "| dropped", h["store"]["dropped"])'
sqlite3 "$WORK/leesided.sqlite" "select 'turns', count(*) from turns union all select 'joined to a verdict', count(*) from turns where verdict is not null union all select 'feature rows (actor)', count(*) from feature_vectors where scope='actor' union all select 'feature rows (cluster)', count(*) from feature_vectors where scope='cluster';"
sqlite3 "$WORK/leesided.sqlite" "select '  no verdict (binding 404s never probe: GateTurn runs after SubstituteBindings): ' || status || ' ' || coalesce(exception,'-') || ' x' || count(*) from turns where verdict is null group by status, exception;"

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

echo "== tag: a browser-like session, three HTML pages with a cookie jar"
rm -f "$WORK/jar3.txt"
for i in 1 2 3; do
  curl -s -o /dev/null -c "$WORK/jar3.txt" -b "$WORK/jar3.txt" -A "Mozilla/5.0 (X11; Linux x86_64) Chrome/130.0.0.0 Safari/537.36" -w "  GET / #$i -> %{http_code}\n" "http://127.0.0.1:$PORT/"
done
grep -c "_lsd" "$WORK/jar3.txt" | sed 's/^/  _lsd cookies in the jar: /'
sleep 1
sqlite3 "$WORK/leesided.sqlite" "select '  tag_status', coalesce(tag_status,'-'), count(*), count(distinct tag_id) as ids from turns where ua_class='chromium' group by 2;"
echo "== tap: TLS through a private nginx and php-fpm on 18443, one curl and one python request"
TAP_BIN="$HERE/target/release/leesided"
if "$TAP_BIN" tap --probe >/dev/null 2>&1; then
  FPM_BIN="$(ls /usr/sbin/php-fpm8.* /usr/sbin/php-fpm 2>/dev/null | head -1)"
  mkdir -p "$WORK/tls/tmp" "$WORK/tls/logs"
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$WORK/tls/key.pem" -out "$WORK/tls/cert.pem" -subj "/CN=localhost" -days 2 >/dev/null 2>&1
  cat >"$WORK/tls/php-fpm.conf" <<CONF
[global]
pid = $WORK/tls/php-fpm.pid
error_log = $WORK/tls/logs/php-fpm.log
daemonize = no
[www]
listen = 127.0.0.1:19443
pm = static
pm.max_children = 2
clear_env = no
CONF
  cat >"$WORK/tls/nginx.conf" <<CONF
worker_processes 1;
pid $WORK/tls/nginx.pid;
error_log $WORK/tls/logs/nginx-error.log;
events { worker_connections 64; }
http {
    access_log $WORK/tls/logs/nginx-access.log;
    client_body_temp_path $WORK/tls/tmp/body;
    proxy_temp_path $WORK/tls/tmp/proxy;
    fastcgi_temp_path $WORK/tls/tmp/fastcgi;
    uwsgi_temp_path $WORK/tls/tmp/uwsgi;
    scgi_temp_path $WORK/tls/tmp/scgi;
    server {
        listen 127.0.0.1:18443 ssl;
        http2 on;
        ssl_certificate $WORK/tls/cert.pem;
        ssl_certificate_key $WORK/tls/key.pem;
        root $SAMPLE/public;
        index index.php;
        location / { try_files \$uri /index.php?\$query_string; }
        location ~ \.php\$ {
            fastcgi_pass 127.0.0.1:19443;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            fastcgi_param QUERY_STRING \$query_string;
            fastcgi_param REQUEST_METHOD \$request_method;
            fastcgi_param CONTENT_TYPE \$content_type;
            fastcgi_param CONTENT_LENGTH \$content_length;
            fastcgi_param SERVER_PROTOCOL \$server_protocol;
            fastcgi_param REQUEST_URI \$request_uri;
            fastcgi_param DOCUMENT_ROOT \$document_root;
            fastcgi_param REMOTE_ADDR \$remote_addr;
            fastcgi_param REMOTE_PORT \$remote_port;
            fastcgi_param SERVER_NAME \$server_name;
            fastcgi_param SERVER_PORT \$server_port;
            fastcgi_param HTTPS on;
        }
    }
}
CONF
  LEESIDE_TRANSPORT=udg LEESIDE_EVENTS_SOCKET="$WORK/run/events.sock" LEESIDE_CHECK_SOCKET="$WORK/run/check.sock" LEESIDE_HASH_KEY="$E2E_HASH_KEY" \
    "$FPM_BIN" -y "$WORK/tls/php-fpm.conf" -F >/dev/null 2>&1 & FPM_PID=$!
  nginx -c "$WORK/tls/nginx.conf" -p "$WORK/tls" -g 'daemon off;' >/dev/null 2>&1 & NGX_PID=$!
  LEESIDED_SOCKET_DIR="$WORK/run" "$TAP_BIN" tap --iface lo --ports 18443 --tls-ports 18443 >"$WORK/tap.log" 2>&1 & TPID=$!
  BEFORE_TAP=$(sqlite3 "$WORK/leesided.sqlite" "select coalesce(max(ts_ms),0) from turns;")
  for _ in $(seq 1 50); do curl -skf -o /dev/null "https://127.0.0.1:18443/" >/dev/null 2>&1 && break; sleep 0.1; done
  sleep 0.5
  CURL_W=$(curl -sk -o /dev/null -w "%{http_code} %{http_version}" "https://127.0.0.1:18443/"); echo "  curl   GET / -> $CURL_W"
  PY_CODE=$(python3 -c 'import ssl,urllib.request,urllib.error
c=ssl.create_default_context(); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
try:
    r=urllib.request.urlopen("https://127.0.0.1:18443/",context=c,timeout=5); print(r.status)
except urllib.error.HTTPError as e: print(e.code)'); echo "  python GET / -> $PY_CODE"
  [ "${CURL_W%% *}" = "200" ] || FAIL="$FAIL curl:$CURL_W"
  [ "$PY_CODE" = "200" ] || FAIL="$FAIL python:$PY_CODE"
  for _ in $(seq 1 10); do
    JA4_NOW=$(sqlite3 "$WORK/leesided.sqlite" "select count(*) from turns where ts_ms > $BEFORE_TAP and ja4 is not null;")
    [ "$JA4_NOW" = "3" ] && break; sleep 1
  done
  echo "  TLS-act turns (past the pre-tap watermark: warmup curl + curl + python):"
  sqlite3 "$WORK/leesided.sqlite" "select '  ' || status || ' ' || coalesce(ua_class,'-'), coalesce(ja4,'null'), coalesce(ja4t,'null'), coalesce(flags,'[]') from turns where ts_ms > $BEFORE_TAP order by ts_ms;"
  TLS_TURNS=$(sqlite3 "$WORK/leesided.sqlite" "select count(*) || '|' || count(ja4) || '|' || count(ja4t) from turns where ts_ms > $BEFORE_TAP;")
  echo "  tls turns|with ja4|with ja4t: $TLS_TURNS"
  [ "$TLS_TURNS" = "3|3|3" ] || FAIL="$FAIL tls:$TLS_TURNS"
  curl -s "http://$API/health" | python3 -c 'import sys,json; t=json.load(sys.stdin)["tap"]; print("  tap:", "messages", t["messages"], "| matched", t["matched"], "| deferred", t["deferred"], "| filled_late", t["filled_late"], "| unknown", t["unknown"])'
  echo "  (only these TLS turns can match: the tap watches 18443, artisan serve is on $PORT)"
  kill "$TPID" "$NGX_PID" "$FPM_PID" 2>/dev/null; wait "$TPID" "$NGX_PID" "$FPM_PID" 2>/dev/null
else
  echo "  skipped: this binary may not capture. Once: sudo setcap cap_net_raw+ep $TAP_BIN  (redo after each build)"
fi
echo "== every turn, by surface, credential status and verdict (events, not probes)"
sqlite3 "$WORK/leesided.sqlite" "select coalesce(surface,'v1'), coalesce(credential_status,'-'), coalesce(verdict,'no check'), count(*) from turns group by 1,2,3 order by 4 desc;"
echo "== the decision in SQLite"
sqlite3 "$WORK/leesided.sqlite" "select scope, action, mode, rule, expires_at - strftime('%s','now') || 's left' from decisions;"
echo "== totals over every act (the mid-run line above covered the traffic script and machine surfaces only)"
curl -s "http://$API/health" | python3 -c 'import sys,json; h=json.load(sys.stdin); print("  checks", h["check"]["total"], "| events", h["ingest"]["total"], "| unjoined", h["check"]["unjoined"], "| bad events", h["ingest"]["bad_event"], "| dropped", h["store"]["dropped"])'
sqlite3 "$WORK/leesided.sqlite" "select '  turns ' || count(*) || ' | joined to a verdict ' || count(verdict) || ' | with actor ' || count(actor_id) || ' | with cluster ' || count(cluster_key) || ' | with ja4 ' || count(ja4) from turns;"
sqlite3 "$WORK/leesided.sqlite" "select '  no verdict (binding 404s never probe: GateTurn runs after SubstituteBindings): ' || status || ' ' || coalesce(exception,'-') || ' x' || count(*) from turns where verdict is null group by status, exception;"
echo "== logs: $WORK/leesided.log, $WORK/php.log, $WORK/tap.log; db: $WORK/leesided.sqlite"
echo "== asserts"
CLUSTERLESS=$(sqlite3 "$WORK/leesided.sqlite" "select count(*) from turns where cluster_key is null;")
[ "$CLUSTERLESS" = "0" ] || FAIL="$FAIL clusterless:$CLUSTERLESS"
if [ -n "$FAIL" ]; then echo "E2E FAILED:$FAIL"; exit 1; fi
echo "E2E OK"
