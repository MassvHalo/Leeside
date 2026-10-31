#!/usr/bin/env bash
# Does header order survive nginx -> FastCGI -> php-fpm -> $_SERVER?
#
# Runs a private nginx and php-fpm as the current user on high ports with
# their own configs under a temp dir; touches nothing of the deployed
# stack (not :7390, not /etc, not the live sockets). Sends headers in two
# deliberately odd orders and compares what $_SERVER received.
#
#   deploy/header-order-check.sh            # prints RELIABLE or UNRELIABLE, exit 0/1
#   NGINX_PORT=18080 FPM_PORT=19000 deploy/header-order-check.sh
#
# The answer sets LEESIDE_HEADER_ORDER_RELIABLE for this host (see the
# brief, "Request shape"), and shape.order_reliable on every event.
set -u

NGINX_PORT="${NGINX_PORT:-18080}"
FPM_PORT="${FPM_PORT:-19000}"
NGINX_BIN="${NGINX_BIN:-$(command -v nginx || echo /usr/sbin/nginx)}"
FPM_BIN="${FPM_BIN:-$(ls /usr/sbin/php-fpm8.* /usr/sbin/php-fpm 2>/dev/null | head -1)}"

for bin in "$NGINX_BIN" "$FPM_BIN" curl python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "need $bin" >&2; exit 2; }
done
for port in "$NGINX_PORT" "$FPM_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "port $port is in use; pick another" >&2; exit 2; fi
done

WORK="$(mktemp -d /tmp/leeside-hoc.XXXXXX)"
mkdir -p "$WORK/www" "$WORK/logs" "$WORK/tmp"
cleanup() { kill "${FPM_PID:-}" "${NGX_PID:-}" 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

cat >"$WORK/www/order.php" <<'PHP'
<?php
// The HTTP_* keys of $_SERVER in the order PHP received them.
$names = [];
foreach ($_SERVER as $k => $_) {
    if (str_starts_with($k, 'HTTP_')) {
        $names[] = strtolower(strtr(substr($k, 5), '_', '-'));
    }
}
header('Content-Type: application/json');
echo json_encode(['received' => $names]);
PHP

cat >"$WORK/php-fpm.conf" <<CONF
[global]
pid = $WORK/php-fpm.pid
error_log = $WORK/logs/php-fpm.log
daemonize = no
[www]
listen = 127.0.0.1:$FPM_PORT
pm = static
pm.max_children = 2
clear_env = no
CONF

cat >"$WORK/nginx.conf" <<CONF
worker_processes 1;
pid $WORK/nginx.pid;
error_log $WORK/logs/nginx-error.log;
events { worker_connections 64; }
http {
    access_log $WORK/logs/nginx-access.log;
    client_body_temp_path $WORK/tmp/body;
    proxy_temp_path $WORK/tmp/proxy;
    fastcgi_temp_path $WORK/tmp/fastcgi;
    uwsgi_temp_path $WORK/tmp/uwsgi;
    scgi_temp_path $WORK/tmp/scgi;
    server {
        listen 127.0.0.1:$NGINX_PORT;
        root $WORK/www;
        location ~ \.php\$ {
            fastcgi_pass 127.0.0.1:$FPM_PORT;
            fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
            fastcgi_param QUERY_STRING \$query_string;
            fastcgi_param REQUEST_METHOD \$request_method;
            fastcgi_param CONTENT_TYPE \$content_type;
            fastcgi_param CONTENT_LENGTH \$content_length;
            fastcgi_param SERVER_PROTOCOL \$server_protocol;
            fastcgi_param REMOTE_ADDR \$remote_addr;
            fastcgi_param REQUEST_URI \$request_uri;
            fastcgi_param DOCUMENT_ROOT \$document_root;
        }
    }
}
CONF

"$FPM_BIN" -y "$WORK/php-fpm.conf" -F >/dev/null 2>&1 & FPM_PID=$!
"$NGINX_BIN" -c "$WORK/nginx.conf" -p "$WORK" -g 'daemon off;' >/dev/null 2>&1 & NGX_PID=$!
for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$NGINX_PORT/order.php" >/dev/null 2>&1 && break; sleep 0.1; done
if ! curl -sf "http://127.0.0.1:$NGINX_PORT/order.php" >/dev/null 2>&1; then
  echo "the private nginx/php-fpm pair did not come up; logs in $WORK/logs" >&2; trap - EXIT; exit 2
fi

check() {
  # $@ = header names in the order to send; prints the received order of those names
  local args=() h
  for h in "$@"; do args+=(-H "$h: x"); done
  curl -s "${args[@]}" "http://127.0.0.1:$NGINX_PORT/order.php" \
    | python3 -c '
import json, sys
sent = [s.lower() for s in sys.argv[1:]]
got = json.load(sys.stdin)["received"]
print(",".join(n for n in got if n in sent))' "$@"
}

ok=1
for order in "X-Zeta X-Alpha X-Mid Accept-Language X-Omega" "X-Omega X-Mid X-Zeta Accept-Language X-Alpha" "Accept-Language X-Alpha X-Omega X-Zeta X-Mid"; do
  # shellcheck disable=SC2086
  got="$(check $order)"
  want="$(echo "$order" | tr 'A-Z ' 'a-z,')"
  printf '  sent %-55s received %s\n' "$want" "$got"
  [ "$got" = "$want" ] || ok=0
done

if [ "$ok" = 1 ]; then
  echo "RELIABLE: header order survives nginx -> php-fpm. LEESIDE_HEADER_ORDER_RELIABLE=true"
  exit 0
else
  echo "UNRELIABLE: header order does not survive. Set LEESIDE_HEADER_ORDER_RELIABLE=false (names are hashed sorted)."
  exit 1
fi
