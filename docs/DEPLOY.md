# Fresh-server deployment note

Gets `leeside-sample` (with the `leeside/laravel` package) running on a bare
Ubuntu server that has no PHP yet. The sample is a demo harness, not
production code; this note gets you to the three-terminal flow from its
README, nothing more.

Assumes Ubuntu 26.04, which ships PHP 8.5 — the sample requires PHP ^8.3
(`leeside-sample/composer.json`), so 8.5 installs cleanly. On Ubuntu 24.04
(PHP 8.3) use the `php8.3-*` package names instead; on 22.04 and older add
the Ondřej Surý PPA first (`add-apt-repository ppa:ondrej/php`).

## 1. System packages

```bash
sudo apt update
sudo apt install -y git curl unzip sqlite3 \
  php8.5-cli php8.5-fpm php8.5-mbstring php8.5-xml php8.5-sqlite3 \
  php8.5-curl php8.5-zip php8.5-bcmath php8.5-sockets
php -v   # expect 8.5.x on Ubuntu 26.04
```

`php8.5-sockets` is only needed for `php artisan leeside:tap`; `php8.5-fpm`
only if you serve through nginx (step 6). The rest is what Laravel 13 plus
this app (SQLite session/cache/queue) requires.

## 2. Composer

Use the upstream installer — the distro package is usually stale:

```bash
php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');"
php composer-setup.php --install-dir=$HOME/.local/bin --filename=composer
rm composer-setup.php
export PATH="$HOME/.local/bin:$PATH"
composer --version
```

## 3. Checkout and install

Clone the whole repo: the sample pulls the package in through a path
repository (`../leeside-laravel`, symlinked), so both directories must sit
side by side.

```bash
git clone https://github.com/MassvHalo/Leeside
cd Leeside/leeside-sample
composer install
```

## 4. Environment

```bash
cp .env.example .env
php artisan key:generate
touch database/database.sqlite
php artisan migrate --seed
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

Put the generated value in `.env` as `LEESIDE_HASH_KEY`, and a second one as
`LEESIDE_TAG_SECRET`: it signs the tag cookie, and left unset it falls back to
`APP_KEY`, so a key rotation would invalidate every issued tag at once and
read as a wave of `bad_mac`. `LEESIDE_HEADER_ORDER` is whatever
`deploy/header-order-check.sh` prints for your host (`reversed` here); it
names the transform the package undoes before hashing header order. The socket
additions are already in `.env.example` and work as-is:

```bash
LEESIDE_EVENTS_SOCKET=storage/leeside/events.sock
LEESIDE_CHECK_SOCKET=storage/leeside/check.sock
```

Relative socket paths resolve against the app base path. If you serve over a
real hostname, also set `APP_URL` accordingly.

No leesided needed: with no listener on the sockets the package degrades to
nothing — events are dropped and counted (`dropped_since_last` on the next
event), checks fail open to `allow`. To see events in
`storage/logs/laravel.log` without running anything else, set
`LEESIDE_TRANSPORT=log`.

## 5. Run (demo)

```bash
php artisan leeside:tap   # terminal 1: events (add --gate for verdicts)
php artisan serve          # terminal 2: http://127.0.0.1:8000
bin/traffic.sh             # terminal 3: needs curl only
```

Smoke test without the traffic script:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/
curl -s -o /dev/null -w '%{http_code}\n' -d 'phone=0661111111&otp=000001' \
  http://127.0.0.1:8000/portal/login   # 401 JSON, login rejected
```

`composer test` inside `leeside-laravel/` should be green; it only needs the
dev dependencies `composer install` already pulled in.

## 6. Serving through nginx (optional)

For anything beyond a demo, point a server block at `public/` and let
`php-fpm` execute PHP:

```nginx
server {
    listen 80;
    server_name example.com;
    root /srv/Leeside/leeside-sample/public;

    index index.php;
    location / { try_files $uri $uri/ /index.php?$query_string; }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.5-fpm.sock;
    }
}
```

`storage/` and `bootstrap/cache/` must be writable by the fpm user:

```bash
sudo chown -R www-data:www-data storage bootstrap/cache
```

The datagram/stream sockets under `storage/leeside/` are created by
`leeside:tap` (or leesided) at runtime; nothing to pre-create, but that
directory needs the same writability when the tap runs as another user.

## Passive fingerprint tap

`leesided-tap.service` — the fingerprint tap unit, not to be confused
with the artisan stand-in `leeside-artisan-tap.service` — runs
`leesided tap` as www-data with `CAP_NET_RAW` (the unit grants it; no
setcap on the binary). It captures
SYNs and ClientHellos on ports 80 and 443 of the default-route interface and
sends JA4T and JA4 to leesided over `/run/leeside/fp.sock`; leesided fills
the turn columns. Nothing changes for nginx or the package, and stopping
the unit only leaves `ja4` and `ja4t` null again. Set `LEESIDED_TAP_IFACE`
in `/etc/leeside/leesided.env` when the default route is not the interface
clients arrive on. Check with:

```bash
systemctl status leesided-tap
curl -s 127.0.0.1:7390/health | python3 -c 'import sys,json; print(json.load(sys.stdin)["tap"])'
```

`matched` should climb with traffic; a high `unknown` means the tap is on
the wrong interface or the request reached PHP through a proxy, so
`remote_port` is the proxy's.

The e2e script's tap act needs the same capability on the development
binary, once per build: `sudo setcap cap_net_raw+ep leesided/target/release/leesided`.
Without it the act is skipped and says so.

## Generator tools

`leeside-sample/bin/benign.sh` and `bin/attack.sh` (docs/windside.md
section 4) need a toolchain that `composer install` does not provide:
Playwright browsers, ffuf, nuclei and sqlmap. `bin/tools.sh` installs all
of it and is the reproducible path on another box:

```bash
cd leeside-sample
./bin/tools.sh
```

Run it as the user that will run the generators, without a sudo prefix:
only the apt step (`playwright install-deps`, `sqlmap`) and the
`/usr/local/bin` installs use sudo. Versions are pinned in the script
(ffuf 2.3.0, nuclei 3.11.1); the Playwright browsers follow the `playwright`
npm version in `package.json`. Browsers land in that user's
`~/.cache/ms-playwright` and nuclei templates in `~/nuclei-templates`, so
every generating user runs it once. The Python scraper and the stuffing and
forgery runs need nothing beyond the system Python 3 and `requests`.

## Shadow week: off-box partner traffic

`leeside-sample/bin/offbox-api.sh` runs from any machine with curl against
the public app during the shadow week, so verified `api` traffic with a
real JA4 exists for the shadow report's headline (windside section 6). One
call every 5 to 30 seconds with an occasional burst of 20:

```bash
LEESIDE_OFFBOX_BASE=https://webapp.leeside.halowifi.com \
LEESIDE_OFFBOX_API_KEY=<a key the app verifies> \
./bin/offbox-api.sh
```

The key is the app's `LEESIDE_DEMO_API_KEY` (`config/leeside_demo.php`;
`StaticApiKeyVerifier` vouches for it, anything else reads unverified and
`RequireApiKey` answers 401). Set a real value in the deployed `.env` —
never the `demo-api-key` default — and hand the same value to whoever runs
the off-box client. Failed calls print a warning and the loop continues.

The daemon's route lists live in `/etc/leeside/leesided.env` next to the
other placeholders install.sh writes:

```bash
LEESIDED_HONEYTOKEN_ROUTES=admin.backup
LEESIDED_BUSINESS_ROUTES=portal.login,api.ping,webhooks.demo
```

`admin.backup` is the honeytoken route: a hit labels the actor's windows
malicious for the following hour. The business list names completed
actions that label a verified credential's window benign. Same names the
generators use (`bin/gen-lib.sh`); restart leesided after changing them.

## First v2 deploy

This deploy crosses migrations 0005 to 0012 and the v2 `ts` change
(integer microseconds; v1 keeps float seconds and its `(peer_key, ts_us)`
join). **Daemon first, package second, never the reverse:** the old and
new versions are mutually incompatible on v2 traffic, and the reverse
order corrupts silently — the old daemon reads an integer `ts` as float
seconds and saturates `ts_us` to i64::MAX on every turn (joining
everything onto one key), while the new daemon at least rejects the old
package's float `ts` lines loudly (`bad_probe`/`bad_event` climb, checks
fail open, events drop). Stopping the daemon first is what makes the
window safe: with nothing listening, checks fail open and events drop
counted, and no corrupt row can land. `deploy.sh` then installs the app
and restarts the daemon in one run; do not start the new binary by hand
ahead of it.

```bash
# 0. Prerequisites, as the deploy user: build both artifacts, fill
# /etc/leeside/leesided.env (LEESIDED_HASH_KEY = the app's
# LEESIDE_HASH_KEY; GeoIP credentials; the route lists above; the
# shadow model below), and copy the model files onto the box. The
# loader reads manifest.json and model.txt only.
(cd leesided && cargo build --release)
(cd leesided/ui && npm ci && npm run build)
sudo mkdir -p /var/lib/leeside/windside-model
sudo cp windside/models/0.1.0/manifest.json windside/models/0.1.0/model.txt \
  /var/lib/leeside/windside-model/
sudo chown -R www-data:www-data /var/lib/leeside/windside-model
# /etc/leeside/leesided.env:
#   LEESIDED_WINDSIDE_MODEL=/var/lib/leeside/windside-model
#   LEESIDED_WINDSIDE_MODE=shadow

# 1. Pre-flight: record the old daemon's /health for the rollback
# comparison, then stop the daemon.
curl -s 127.0.0.1:7390/health | sudo tee /var/lib/leeside/health.pre-v2.json > /dev/null
sudo systemctl stop leesided

# 2. Back up the store and the binary. A clean shutdown checkpoints the
# WAL, so the one sqlite file is the whole store.
sudo cp /var/lib/leeside/leesided.sqlite /var/lib/leeside/leesided.sqlite.pre-v2
sudo cp /usr/local/bin/leesided /usr/local/bin/leesided.pre-v2

# 3. Deploy (app first, then the new binary) and watch the migrations.
sudo bash leeside-sample/deploy/deploy.sh
journalctl -u leesided -f   # expect: migrated version=5 .. version=12

# 4. Verify /health.
curl -s 127.0.0.1:7390/health | python3 -m json.tool
# schema_versions [1, 2]; features_version 2; migration_version 12;
# ip_hashing true; geoip true; tap counters zero (its unit is not
# started yet); windside mode shadow, model_version 0.1.0, no error.

# 5. The package is live with the deploy. Confirm the new wire: no
# bad_probe or bad_event climb on the next requests.

# 6. Start the fingerprint tap unit, leesided-tap.service (not the
# artisan stand-in, leeside-artisan-tap.service), then watch matched
# climb with traffic.
sudo systemctl start leesided-tap

# 7. One real request, checked in the store.
curl -s -o /dev/null https://webapp.leeside.halowifi.com/
sudo sqlite3 /var/lib/leeside/leesided.sqlite \
  "SELECT ts_us, route, actor_id, cluster_key FROM turns ORDER BY ingest_seq DESC LIMIT 1;"
# check.unjoined in /health stays 0: the probe joined its turn.
```

Rollback: stop leesided, copy the `.pre-v2` files back over the store
and `/usr/local/bin/leesided`, start, and re-check /health against
`/var/lib/leeside/health.pre-v2.json` (same shape, old versions).
