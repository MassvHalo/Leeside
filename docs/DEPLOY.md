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
