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
UI_DOMAIN=leeside.halowifi.com

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

# The API token: generated once, kept across reinstalls.
mkdir -p /etc/leeside
if [ ! -s /etc/leeside/leesided.env ]; then
    {
        printf 'LEESIDED_API_TOKEN=%s\n' "$(openssl rand -hex 32)"
        # Same value as the app's LEESIDE_HASH_KEY, so ip_hash/net_hash join.
        printf 'LEESIDED_HASH_KEY=\n'
        # MaxMind requires both for geoipupdate since May 2024; the daemon
        # itself only reads the .mmdb files named in the unit.
        printf 'LEESIDED_GEOIP_ACCOUNT_ID=\n'
        printf 'LEESIDED_GEOIP_LICENSE_KEY=\n'
    } > /etc/leeside/leesided.env
fi
chown root:www-data /etc/leeside/leesided.env
chmod 0640 /etc/leeside/leesided.env

mkdir -p /var/www/leeside-ui
chown www-data:www-data /var/www/leeside-ui

for site in "$DOMAIN" "$UI_DOMAIN"; do
    cp "$SCRIPT_DIR/nginx/$site.conf" /etc/nginx/sites-available/"$site.conf"
    ln -sf /etc/nginx/sites-available/"$site.conf" /etc/nginx/sites-enabled/"$site.conf"
done
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable --now nginx
systemctl reload-or-restart nginx

for site in "$DOMAIN" "$UI_DOMAIN"; do
    certbot --nginx -d "$site" --redirect --agree-tos --no-eff-email \
        -m mrinal@halowifi.com -n --deploy-hook 'systemctl reload nginx'
done
certbot renew --dry-run

cp "$SCRIPT_DIR/logrotate/leeside" /etc/logrotate.d/leeside

# leesided owns /run/leeside; the tap stand-in would hold events.sock.
# Both names: leeside-tap.service was the stand-in's name before the rename.
for unit in leeside-tap leeside-artisan-tap; do
    if [ -f /etc/systemd/system/$unit.service ]; then
        systemctl disable --now $unit || true
    fi
done
cp "$SCRIPT_DIR/systemd/leesided.service" /etc/systemd/system/leesided.service
cp "$SCRIPT_DIR/systemd/leesided-tap.service" /etc/systemd/system/leesided-tap.service
systemctl daemon-reload
# Started by deploy.sh once the binary is in place.
systemctl enable leesided leesided-tap

bash "$SCRIPT_DIR/deploy.sh"
