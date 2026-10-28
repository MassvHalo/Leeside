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
PROD=/var/www/leeside
SAMPLE="$PROD/leeside-sample"

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
