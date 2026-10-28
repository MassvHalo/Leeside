# leeside-sample

Stock Laravel app with `leeside/laravel` installed through a path repository.
Produces real session-shaped events on a laptop, and is the harness for the
overhead measurement and the PII diff. Nothing here is production code.

## Setup

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate --seed
```

`.env` carries three Leeside additions (also present in `.env.example`):

```bash
LEESIDE_EVENTS_SOCKET=storage/leeside/events.sock
LEESIDE_CHECK_SOCKET=storage/leeside/check.sock
LEESIDE_HASH_KEY=<random 32 bytes, base64>
```

Generate a hash key with:

```bash
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
```

## Three-terminal flow

```bash
php artisan leeside:tap                     # terminal 1: events
php artisan serve                           # terminal 2
bin/traffic.sh                              # terminal 3: three acts, prints nothing
php artisan leeside:tap --gate --action=block --route=portal.login   # then rerun act two
```

With `--gate`, logins matching `--route` get the scripted verdict; anything
else gets `allow`. Try the full verdict set:

```bash
php artisan leeside:tap --gate --action=rate_limit --mode=enforce --route=portal.login
php artisan leeside:tap --gate --action=challenge --mode=enforce --route=portal.login
```

A challenged login returns `428 {"step_up":"otp"}` via the `ChallengeDemo`
middleware, which stands in for whatever step-up the app would really do.

`--raw` prints NDJSON instead of pretty JSON:

```bash
php artisan leeside:tap --raw > /tmp/events.ndjson &
bin/traffic.sh
```

## Routes

| Route name | Verb and URI | Behaviour |
| --- | --- | --- |
| `home` | GET / | the welcome view |
| `portal.login` | POST /portal/login | validates `phone` digits:10 and `otp` digits:6; OTP `123456` logs in, anything else 401s |
| `venues.show` | GET /venues/{venue} | route-model binding; 404 for unknown ids |
| `api.venues.index` | GET /api/venues | JSON list of venues |
| `api.venues.visit` | POST /api/venues/{venue}/visit | validates `guests` integer |
| `secret` | GET /secret | `abort(403)` |
| `boom` | GET /boom | throws (a 500) |

## Measurements

They gate the production rollout.

1. Added latency per request, package on versus `LEESIDE_ENABLED=false`,
   500 requests each over the serve loop (target under 1 ms added):

   ```bash
   bin/latency.sh            # serve running with the package on
   # set LEESIDE_ENABLED=false in .env, restart serve
   bin/latency.sh            # ... and compare
   ```

2. A PII diff: tap `--raw` to a file, run the traffic script, grep for every
   literal the script sent. Expect zero hits:

   ```bash
   php artisan leeside:tap --raw > /tmp/events.ndjson &
   TAP=$!
   bin/traffic.sh
   kill $TAP
   grep -E -o '066[0-9]+|00000[0-9]|12345|999999|leeside-traffic|Alpine Lodge|Harbor Inn|Desert Rose|City Central|Lakeside Retreat|Old Town Hostel|/venues/[0-9]+' /tmp/events.ndjson | sort | uniq -c
   ```
