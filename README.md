# Leeside

Leeside is an application-level firewall for Laravel apps, built for the Meta
Global AI Developer Hackathon (startup track). A Composer package captures one
PII-free turn event per request and asks a Rust engine for a rule verdict on a
synchronous check; the engine answers from deterministic rules and a fast
classifier, while larger models score and reason asynchronously, off the
request path.

## Status

Deployed on webapp.leeside.halowifi.com: the capture package, the Rust engine with deterministic rules, the Windside classifier (model 0.1.0) scoring in shadow, the passive TLS tap, and the Windside console at /windside with the dashboard, review queue, actor pages, status and controls, admin and read-only viewer sessions. Muse Spark Open, Meta's open-weights model, labels, explains and drafts rules asynchronously, off the request path, with every citation checked against the stored turns; autopilot (off by default) acts on the decisive subset and asks afterwards.

Release v0.1.1 installs on a fresh Ubuntu box with one line (below). Proven today on a throwaway Ubuntu 24.04 box running the Filament demo app we did not write: install, dashboard, "Turn enforcement on" from the console, and 429s from the eleventh failed Livewire login.

Landing page: https://massvhalo.github.io/Leeside/ · Release: https://github.com/MassvHalo/Leeside/releases/latest · Demo video: <link to be added before submission>

Built with Muse Spark Open.

Label-point evals (post-faithfulness agreement, as prod would score them):

| Eval | Rows | Agreement |
| --- | --- | --- |
| 1 | 10 | 0.20 |
| 3 | 142 | 0.80 |
| 5 | 156 | 0.92 |
| 7 | 148 | 0.971 ± 0.009 |

What's next: Windside active mode after the shadow week, per-surface windows and fingerprint features for v3, adapters for ASP.NET Core, Django and Express on the same engine, named users with passwords, editable assistant settings in the console, and a vendor-neutral TCP fingerprint in place of JA4T.

## See it act

The console is live and read-only at https://webapp.leeside.halowifi.com/windside with a viewer token. The dashboard shows the last day of the sample app's traffic: attacks stopped, actors waiting on a person, odd traffic watched. Opening an episode shows the evidence, the Windside score beside the rules, and for Muse Spark Open proposals each signal with the requests it cites.

Viewer token: available in the demo video, or on request.

To trigger it yourself, walk the venue ids the way a scraper would:

```bash
for i in $(seq 1 30); do curl -s -o /dev/null "https://webapp.leeside.halowifi.com/api/venues/$i"; done
```

Those ids match no route, so every hit lands as a 404; refreshing the console shows a new scored actor waiting on a person, under an episode titled "Someone scanned for weak spots". It touches only the public demo app, and the rule flagging it (http-404-scan) ships in every install.

Install on an Ubuntu 22.04, 24.04 or 26.04 box that already hosts a Laravel app
behind nginx:

```bash
curl -sSL https://raw.githubusercontent.com/MassvHalo/Leeside/master/install.sh | sudo LEESIDE_DOMAIN=example.com bash -s -- --yes
```

Unattended form above: the variable goes before `bash`, since one
before `curl` never reaches it. Swap in the app's domain.

Turn enforcement on: fresh installs watch only; the global mode starts at monitor and the install rules start as shadow, so run both steps when you are ready for Leeside to act; PUT /mode {"mode":"monitor"} is the kill switch.

```bash
TOKEN=$(grep ^LEESIDED_API_TOKEN= /etc/leeside/leesided.env | cut -d= -f2-)
curl -s -X PUT http://127.0.0.1:7390/mode -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"mode":"enforce"}'
for f in /usr/local/bin/rules/install/*.json; do curl -s -X PUT "http://127.0.0.1:7390/rules/$(basename "$f" .json)" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @"$f"; echo; done
```

To change the admin password later, edit LEESIDED_API_TOKEN in
/etc/leeside/leesided.env and restart leesided.

Both switches are also on the console's Settings page: Protection
(the global mode selector, "Turn enforcement on", and the "Monitor
only" kill switch) and Assistant (autopilot `off`, `block` or
`block+rules` with its two thresholds, applied without a restart).
Autopilot is off by default; when on, a label proposal acts on its
own only past all three gates: malicious at or above the minimum
confidence, every cited signal surviving the check, and a decisive
signal (`webhook_forgery`, `honeytoken_hit`, `attack_payload`) or
the score at or above its threshold. It stays in the review queue
for confirmation. See `docs/llm.md` section 9.

The release ships `leesided` for x86_64 and aarch64; the installer picks
the asset matching the box. Anything else builds from source.

## How it works

- `leeside/laravel` (the capture layer) emits a turn event per request,
  shapes and hashes only, never values, over a Unix datagram socket, and
  gates the `web` and `api` groups on a verdict read from a Unix stream
  socket within milliseconds, failing open on every failure.
- `leesided` (the Rust engine) ingests the events, serves the check from
  rules and the Windside classifier, and queues conversations for the Glimmer
  and Spark model tiers.
- The Windside console at `/windside`, served by the daemon through the
  app's nginx server block: dashboard, review queue, actor pages, status
  and controls; viewer sessions see everything and change nothing.
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
- `leesided`: next, implements the other end of both sockets exactly as the
  brief writes them.

## Licensing

Leeside is MIT-licensed: `leeside/laravel` (see its `composer.json`) and
the repo root (see `LICENSE`). Third-party notices live in
`THIRD_PARTY.md`. Note the JA4T exception: FoxIO License 1.1, patent
pending, permitted for this non-commercial build, to be replaced by a
vendor-neutral TCP fingerprint or an OEM licence before any commercial
use.
