#!/usr/bin/env bash
# How does header order arrive in $_SERVER on this host, through
# nginx -> FastCGI -> php-fpm? Prints the transform the package must undo:
#
#   LEESIDE_HEADER_ORDER=received    order survives as sent
#   LEESIDE_HEADER_ORDER=reversed    exactly reversed (php-fpm prepends params)
#   LEESIDE_HEADER_ORDER=unknown     neither; the package hashes sorted names
#
# Runs a private nginx and php-fpm as the current user on high ports with
# their own configs under a temp dir; touches nothing of the deployed stack
# (not :7390, not /etc, not the live sockets). Then verifies the recipe:
# the same headers sent through the private stack and through the package
# directly in received order must give the same shape header-names hash.
#
#   deploy/header-order-check.sh                       # exit 0 for received/reversed, 1 for unknown, 2 on setup trouble
#   NGINX_PORT=18080 FPM_PORT=19000 deploy/header-order-check.sh
set -u

HERE="$(cd "$(dirname "$0")/.." && pwd)"
NGINX_PORT="${NGINX_PORT:-18080}"
FPM_PORT="${FPM_PORT:-19000}"
NGINX_BIN="${NGINX_BIN:-$(command -v nginx || echo /usr/sbin/nginx)}"
FPM_BIN="${FPM_BIN:-$(ls /usr/sbin/php-fpm8.* /usr/sbin/php-fpm 2>/dev/null | head -1)}"
AUTOLOAD="$HERE/vendor/autoload.php"

for bin in "$NGINX_BIN" "$FPM_BIN" curl php python3; do
  command -v "$bin" >/dev/null 2>&1 || { echo "need $bin" >&2; exit 2; }
done
[ -f "$AUTOLOAD" ] || { echo "need $AUTOLOAD (composer install in leeside-sample)" >&2; exit 2; }
for port in "$NGINX_PORT" "$FPM_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "port $port is in use; pick another" >&2; exit 2; fi
done

WORK="$(mktemp -d /tmp/leeside-hoc.XXXXXX)"
mkdir -p "$WORK/www" "$WORK/logs" "$WORK/tmp"
cleanup() { kill "${FPM_PID:-}" "${NGX_PID:-}" 2>/dev/null; wait 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# names: the HTTP_* keys of $_SERVER in the order PHP received them.
# hash: the package's header-names hash under ?order=<transform>.
cat >"$WORK/www/order.php" <<PHP
<?php
require '$AUTOLOAD';
\$names = [];
foreach (\$_SERVER as \$k => \$_) {
    if (str_starts_with(\$k, 'HTTP_')) {
        \$names[] = strtolower(strtr(substr(\$k, 5), '_', '-'));
    }
}
\$request = \\Illuminate\\Http\\Request::createFromGlobals();
\$order = \$_GET['order'] ?? 'unknown';
\$shape = \\Leeside\\Laravel\\Shape\\RequestShape::build(\$request, new \\Leeside\\Laravel\\Hash\\Hasher('check-key'), \$order)['shape'];
header('Content-Type: application/json');
echo json_encode(['received' => \$names, 'hash' => \$shape['header_names_hash'], 'recipe' => \$shape['order_recipe']]);
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

# The orders to send. Host goes first because curl sends it first.
ORDERS=(
  "Host X-Zeta X-Alpha X-Mid Accept-Language X-Omega"
  "Host X-Omega X-Mid X-Zeta Accept-Language X-Alpha"
  "Host Accept-Language X-Alpha X-Omega X-Zeta X-Mid"
)

fetch() { # $1 = order query, rest = header names in order -> JSON
  local order="$1"; shift
  # No curl defaults: both sides must see exactly the headers listed.
  local args=(-H 'User-Agent:' -H 'Accept:') h
  for h in "$@"; do
    if [ "$h" = "Host" ]; then args+=(-H "Host: 127.0.0.1:$NGINX_PORT"); else args+=(-H "$h: x"); fi
  done
  curl -s "${args[@]}" "http://127.0.0.1:$NGINX_PORT/order.php?order=$order"
}

# 1. The transform.
transform=""
for order in "${ORDERS[@]}"; do
  # shellcheck disable=SC2086
  got="$(fetch unknown $order | python3 -c '
import json, sys
sent = [s.lower() for s in sys.argv[1:]]
got = json.load(sys.stdin)["received"]
print(",".join(n for n in got if n in sent))' $order)"
  sent="$(echo "$order" | tr 'A-Z ' 'a-z,')"
  reversed="$(echo "$order" | tr ' ' '\n' | tac | tr 'A-Z\n' 'a-z,' | sed 's/,$//')"
  if [ "$got" = "$sent" ]; then this=received; elif [ "$got" = "$reversed" ]; then this=reversed; else this=unknown; fi
  printf '  sent %-58s received %-58s %s\n' "$sent" "$got" "$this"
  if [ -z "$transform" ]; then transform="$this"; elif [ "$transform" != "$this" ]; then transform=unknown; fi
done

# 2. The recipe: through the stack with the transform vs. the package directly in received order.
recipe_ok=1
for order in "${ORDERS[@]}"; do
  # shellcheck disable=SC2086
  via_stack="$(fetch "$transform" $order | python3 -c 'import json,sys; print(json.load(sys.stdin)["hash"])')"
  direct="$(php -r '
require $argv[1];
$server = ["SERVER_PROTOCOL" => "HTTP/1.1", "REQUEST_METHOD" => "GET", "REQUEST_URI" => "/order.php"];
foreach (array_slice($argv, 3) as $name) { $server["HTTP_".strtoupper(strtr($name, "-", "_"))] = "x"; }
$r = new \Illuminate\Http\Request([], [], [], [], [], $server);
$shape = \Leeside\Laravel\Shape\RequestShape::build($r, new \Leeside\Laravel\Hash\Hasher("check-key"), $argv[2])["shape"];
echo $shape["header_names_hash"];' "$AUTOLOAD" "$([ "$transform" = unknown ] && echo unknown || echo received)" $order)"
  printf '  recipe %-9s stack %s  direct %s  %s\n' "$transform" "$via_stack" "$direct" "$([ "$via_stack" = "$direct" ] && echo same || echo DIFFERENT)"
  [ "$via_stack" = "$direct" ] || recipe_ok=0
done
[ "$recipe_ok" = 1 ] || { echo "the recipe does not reproduce through the stack; do not trust shape hashes from this host" >&2; exit 2; }

echo "LEESIDE_HEADER_ORDER=$transform"
[ "$transform" != unknown ]
