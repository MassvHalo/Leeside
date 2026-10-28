#!/usr/bin/env bash
# Idempotent root install for https://webapp.leeside.halowifi.com.
# Run once from the working copy, never by the agent:
#   sudo bash leeside-sample/deploy/install.sh
# Spec: docs/brief.md, "Deploy" section. install.sh is the only script that
# touches /etc. Ends by calling deploy.sh.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root (sudo bash leeside-sample/deploy/install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLE_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$SAMPLE_DIR")"
PROD=/var/www/leeside
DOMAIN=webapp.leeside.halowifi.com

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y \
    nginx \
    php8.5-cli php8.5-fpm php8.5-sqlite3 php8.5-mbstring php8.5-xml \
    php8.5-curl php8.5-zip php8.5-intl php8.5-bcmath php8.5-sockets \
    sqlite3 \
    certbot python3-certbot-nginx \
    git unzip ufw

if ! command -v composer >/dev/null 2>&1; then
    php -r "copy('https://getcomposer.org/installer', '/tmp/composer-setup.php');"
    php /tmp/composer-setup.php --install-dir=/usr/local/bin --filename=composer
    rm -f /tmp/composer-setup.php
fi

git config --global --add safe.directory "$PROD" 2>/dev/null || true

if [ ! -d "$PROD/.git" ]; then
    git clone "$REPO_ROOT" "$PROD"
fi
chown -R www-data:www-data "$PROD"

printf 'd /run/leeside 0770 www-data www-data -\n' > /etc/tmpfiles.d/leeside.conf
systemd-tmpfiles --create

mkdir -p /var/log/leeside
chown www-data:www-data /var/log/leeside
chmod 0755 /var/log/leeside

ufw allow OpenSSH >/dev/null
ufw allow 'Nginx Full' >/dev/null
ufw --force enable >/dev/null

cp "$SCRIPT_DIR/nginx/$DOMAIN.conf" /etc/nginx/sites-available/"$DOMAIN.conf"
ln -sf /etc/nginx/sites-available/"$DOMAIN.conf" /etc/nginx/sites-enabled/"$DOMAIN.conf"
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload-or-restart nginx

certbot --nginx -d "$DOMAIN" --redirect --agree-tos --no-eff-email \
    -m mrinal@halowifi.com -n --deploy-hook 'systemctl reload nginx'
certbot renew --dry-run

cp "$SCRIPT_DIR/logrotate/leeside" /etc/logrotate.d/leeside

cp "$SCRIPT_DIR/systemd/leeside-tap.service" /etc/systemd/system/leeside-tap.service
systemctl daemon-reload
systemctl enable --now leeside-tap

bash "$SCRIPT_DIR/deploy.sh"
