#!/usr/bin/env bash
# Idempotent root deploy for https://webapp.leeside.halowifi.com.
# Pulls committed work from the working copy into /var/www/leeside.
# Run by me with sudo, never by the agent:
#   sudo bash leeside-sample/deploy/deploy.sh
# Touches /etc for nothing; install.sh owns /etc.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "deploy.sh must run as root (sudo bash leeside-sample/deploy/deploy.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
PROD=/var/www/leeside
SAMPLE="$PROD/leeside-sample"
# target/ is not committed; build it in the working copy first:
#   (cd leesided && cargo build --release)
LEESIDED_BIN="$REPO_ROOT/leesided/target/release/leesided"
# ui/dist is not committed either: (cd leesided/ui && npm ci && npm run build)
UI_DIST="$REPO_ROOT/leesided/ui/dist"

if [ ! -x "$LEESIDED_BIN" ]; then
    echo "no leesided binary at $LEESIDED_BIN; run cargo build --release in leesided/ first" >&2
    exit 1
fi
if [ ! -f "$UI_DIST/index.html" ]; then
    echo "no UI build at $UI_DIST; run npm ci && npm run build in leesided/ui first" >&2
    exit 1
fi

git -C "$PROD" pull
chown -R www-data:www-data "$PROD"

sudo -u www-data bash -c "
set -euo pipefail
cd '$SAMPLE'

FIRST_RUN=0
[ -f .env ] || FIRST_RUN=1

composer install --no-dev --optimize-autoloader

if [ \"\$FIRST_RUN\" -eq 1 ]; then
    cp deploy/.env.production.example .env
    if grep -q '^LEESIDE_HASH_KEY=\$' .env; then
        HASH_KEY=\$(php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;')
        sed -i \"s|^LEESIDE_HASH_KEY=\$|LEESIDE_HASH_KEY=\$HASH_KEY|\" .env
    fi
    php artisan key:generate --force
fi

[ -f database/database.sqlite ] || touch database/database.sqlite

if [ \"\$FIRST_RUN\" -eq 1 ]; then
    php artisan migrate --force --seed
else
    php artisan migrate --force
fi

php artisan optimize:clear
php artisan optimize
"

chown -R www-data:www-data "$SAMPLE/storage" "$SAMPLE/bootstrap/cache"

# The install rule set is imported only into an empty database; later rule
# edits go through the API on 127.0.0.1:7390.
install -m 0755 "$LEESIDED_BIN" /usr/local/bin/leesided
systemctl restart leesided
for _ in $(seq 1 50); do
    curl -sf http://127.0.0.1:7390/health >/dev/null && break
    sleep 0.1
done
curl -sf http://127.0.0.1:7390/health >/dev/null || {
    echo "leesided did not answer /health; journalctl -u leesided" >&2
    exit 1
}
echo "leesided up on 127.0.0.1:7390"

# Replace the UI in one step: old hashed assets go, index.html never points
# at a missing file for longer than the copy.
rsync -a --delete "$UI_DIST"/ /var/www/leeside-ui/
chown -R www-data:www-data /var/www/leeside-ui
echo "UI published to /var/www/leeside-ui"
