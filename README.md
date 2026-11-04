# Leeside

Leeside is an application-level firewall for Laravel apps, built for the Meta
Global AI Developer Hackathon (startup track). A Composer package captures one
PII-free turn event per request and asks a Rust engine for a rule verdict on a
synchronous check; the engine answers from deterministic rules and a fast
classifier, while larger models score and reason asynchronously, off the
request path.

## Status

Deployed on `webapp.leeside.halowifi.com`: the capture package, the Rust
engine with deterministic rules, the Windside classifier (model 0.1.0) scoring
in shadow, the passive TLS tap, and the Windside console at `/windside/` with
admin and read-only viewer sessions. The LLM tiers (Glimmer scoring, Spark
reasoning) run asynchronously off a queue; the console's review queue and rule
drafting are live.

Built with Muse Spark Open.

Label-point evals (post-faithfulness agreement, as prod would score them):

| Eval | Rows | Agreement |
| --- | --- | --- |
| 1 | 10 | 0.20 |
| 3 | 142 | 0.80 |
| 5 | 156 | 0.92 |
| 7 | 148 | 0.971 ± 0.009 |

What's next: flip Windside from shadow to active after the shadow week,
per-surface windows and fingerprint features for v3, and the designed console
on the same data layer.

Install on an Ubuntu 22.04 or 24.04 box that already hosts a Laravel app
behind nginx:

```bash
curl -sSL https://raw.githubusercontent.com/MassvHalo/Leeside/master/install.sh | sudo LEESIDE_DOMAIN=example.com bash -s -- --yes
```

Unattended form above: the variable goes before `bash`, since one
before `curl` never reaches it. Swap in the app's domain.

Fresh installs start in global monitor: rules watch, nothing acts.
Switch with the admin token from `/etc/leeside/leesided.env`:

```bash
source /etc/leeside/leesided.env && curl -X PUT http://127.0.0.1:7390/mode -H "Authorization: Bearer $LEESIDE_API_TOKEN" -d '{"mode":"enforce"}'
```

The release ships `leesided` for x86_64 and aarch64; the installer picks
the asset matching the box. Anything else builds from source.

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

## Component status

- Capture package: done to the brief; `composer test` green, tap shows all
  three traffic acts, PII grep empty, added latency under 1 ms.
- Sample app: deployed; this working copy is never served.
- `leesided`: next — implements the other end of both sockets exactly as the
  brief writes them.

## Licensing

Leeside is MIT-licensed: `leeside/laravel` (see its `composer.json`) and
the repo root (see `LICENSE`). Third-party notices live in
`THIRD_PARTY.md`. Note the JA4T exception: FoxIO License 1.1, patent
pending, permitted for this non-commercial build, to be replaced by a
vendor-neutral TCP fingerprint or an OEM licence before any commercial
use.
