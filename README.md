# Leeside

Leeside is an application-level firewall for Laravel apps, built for the Meta
Global AI Developer Hackathon (startup track). A Composer package captures one
PII-free turn event per request and asks a Rust engine for a rule verdict on a
synchronous check; the engine answers from deterministic rules and a fast
classifier, while larger models score and reason asynchronously, off the
request path.

## How it works

- `leeside/laravel` (the capture layer) emits a turn event per request —
  shapes and hashes only, never values — over a Unix datagram socket, and
  gates the `web` and `api` groups on a verdict read from a Unix stream
  socket within milliseconds, failing open on every failure.
- `leesided` (the Rust engine) ingests the events, serves the check from
  rules and the Windside classifier, and queues conversations for the Glimmer
  and Spark model tiers.
- `leeside-sample` is a portal-shaped demo app that produces real
  session-shaped events, measures the package's overhead, and proves no PII
  leaves the app.

## Layout

| Path | What it is |
| --- | --- |
| `docs/brief.md` | The contract: event schema v1, sync check protocol, sample spec, deploy |
| `docs/DEPLOY.md` | Fresh-server note for running the sample on a bare box |
| `leeside-laravel/` | Composer package `leeside/laravel` |
| `leeside-sample/` | Demo Laravel app, served at `https://webapp.leeside.halowifi.com` |
| `leesided/` | The Rust engine (scaffolded; PHP contract first) |

Each directory has its own `AGENTS.md`. A change to the event schema or the
check protocol is written in `docs/brief.md` before any code changes.

## Quickstart

Prerequisites: PHP 8.3+ with the usual Laravel extensions, Composer, curl.

```bash
git clone https://github.com/MassvHalo/Leeside
cd Leeside/leeside-sample
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate --seed
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'   # -> LEESIDE_HASH_KEY in .env
```

Then three terminals:

```bash
php artisan leeside:tap                     # 1: events (stand-in for leesided)
php artisan serve                           # 2: the app
bin/traffic.sh                              # 3: benign browse, validation burst, enumeration
```

Block the login burst live:

```bash
php artisan leeside:tap --gate --action=block --mode=enforce --route=portal.login
```

Two measurements gate the production rollout: added latency under 1 ms
(`bin/latency.sh`, package on vs `LEESIDE_ENABLED=false`) and an empty PII
grep over the tapped events. See `leeside-sample/README.md` for both
procedures.

## Deploy

The sample runs at `https://webapp.leeside.halowifi.com` (nginx + PHP-FPM,
SQLite, Let's Encrypt). Both scripts are idempotent, run with sudo, and live
in `leeside-sample/deploy/`:

```bash
sudo bash leeside-sample/deploy/install.sh   # once: packages, checkout, nginx, cert, tap service
sudo bash leeside-sample/deploy/deploy.sh    # every release: pull, composer, migrate, optimize
```

The full spec, including the certificate and done-tests, is the Deploy
section of `docs/brief.md`.

## Status

- Capture package: done to the brief; `composer test` green, tap shows all
  three traffic acts, PII grep empty, added latency under 1 ms.
- Sample app: deployed; this working copy is never served.
- `leesided`: next — implements the other end of both sockets exactly as the
  brief writes them.

## License

`leeside/laravel` is MIT-licensed (see its `composer.json`). The repo has no
root `LICENSE` file yet.
