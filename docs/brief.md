# leeside/laravel build brief

As of 2026-10-29. This file is the contract: the event schema and the check
protocol here are what leesided (the Rust engine) is built against.

## Repo layout

One repo, `Leeside/`, with a directory per component and this file as the
shared contract:

```
Leeside/
  AGENTS.md            shared rules; each directory below has its own
  docs/brief.md        this file
  docs/architecture.md the solution architecture
  leeside-laravel/     Composer package leeside/laravel
  leeside-sample/      Laravel app using the package; deploy/ lives here
  leesided/            the Rust engine
```

Muse Code sessions start inside the directory being worked on
(`cd leeside-sample && muse`), so that directory's AGENTS.md loads on top of
the root one and the sandbox confines writes to it. Paths in this file are
relative to the repo root.

## What to build

Two directories, both PHP, both buildable before leesided exists.

| Directory | What it is | Why it comes first |
| --- | --- | --- |
| `leeside-laravel` | Composer package `leeside/laravel`: the capture layer. One global middleware that emits a PII-free turn event per request, one route-group middleware that asks leesided for a rule match, a shape reducer, hashing, transports, and a `leeside:tap` dev command that stands in for leesided. | It defines the event schema leesided ingests and the check protocol leesided serves. Freezing both here means the Rust side has a contract to build against. |
| `leeside-sample` | A stock Laravel app with the package installed through a path repository and a handful of portal-shaped routes (login with OTP validation, venues with model binding, a JSON API, a 403, a 404, a 500) plus a traffic script. | Produces real session-shaped events on a laptop tonight, and is the harness for the overhead measurement and the PII diff before anything touches a production app. |

No production application is touched in this phase. The package is the only
thing that will ever be installed there, so it must carry no app-specific
assumptions.

## Package spec: leeside/laravel

Namespace `Leeside\Laravel`, PHP 8.2+, `illuminate/*` ^11|^12|^13 (current
Laravel is 13.x), auto-discovered service provider, publishable
`config/leeside.php`. Zero runtime dependencies beyond Illuminate.

### Two middlewares, not one

Laravel runs global middleware before routing, so a single global middleware
can neither see the route template in `handle()` nor the session. Split the job:

| Middleware | Registered | handle() | terminate() |
| --- | --- | --- | --- |
| `CaptureTurn` | Global, appended (catches 404s and unrouted turns) | Stamps `ts` and `hrtime` on a per-request `TurnContext`. Nothing else. | After the response has gone out: build the event, hand it to the transport. Never throws. |
| `GateTurn` | Appended to the `web` and `api` groups; added to middleware priority after `SubstituteBindings` so it runs after auth and binding | Sets `route` on the context, builds the probe, calls `RuleClient::check()` within the timeout, applies the verdict only when `mode == enforce`. | none |

`TurnContext` is a scoped container binding (Octane-safe), reset by `begin()`
on every request.

The service provider also registers:

- A `renderable` callback on the exception handler, typed `Throwable`, that
  returns null and records the exception on the context. This is the only hook
  that sees `ValidationException`, `ModelNotFoundException`,
  `AuthorizationException` and `TokenMismatchException`; Laravel never reports
  those, so `reportable` callbacks never see them. Laravel wraps the last three
  in Symfony HTTP exceptions before rendering; record the class basename of the
  original cause (unwrap one level of `getPrevious()` on an HTTP exception).
- Listeners for `Login`, `Failed`, `Logout`, `Registered`, `PasswordReset`,
  `Lockout`, `Verified` that record only the event name (last one wins).
- A `RouteMatched` listener that records the route template, for routes
  outside the gated groups.
- Middleware registration: the global middleware through the HTTP kernel's
  `pushMiddleware()` when the kernel is already resolved and through
  `afterResolving()` otherwise, so console processes never resolve the kernel.
  The gate goes into the groups with `Router::pushMiddlewareToGroup()` and into
  the priority list with `addToMiddlewarePriorityAfter()` when that method
  exists. `register_middleware = false` turns all of this off for apps that
  wire it in `bootstrap/app.php` themselves.

### The event, one per request, schema v1

| Field | Example | Rule |
| --- | --- | --- |
| `v`, `ts` | 1, 1761600000.123 | schema version; wall clock at handle() |
| `session_key` | 16 hex | HMAC of the session id; falls back to `peer_key` when no session |
| `peer_key` | 16 hex | HMAC of ip + user agent, always present |
| `principal` | 16 hex or `anon` | HMAC of the auth identifier of an already-resolved user (check `hasUser()` on each configured guard); never resolve a guard from here, that can cost a query |
| `verb`, `route` | `POST`, `portal.login` | route name, else the URI pattern with `{param}` braces, else `_unrouted`; never the raw path |
| `status`, `latency_ms`, `bytes_in`, `bytes_out` | 422, 38.2, 410, 1204 | `bytes_in` from Content-Length; `bytes_out` is -1 for streamed responses |
| `req_shape`, `resp_shape` | `{otp:str:6,phone:str:10}` | shape of `$request->all()` and of the JSON body (up to 64 KB); else `html`, `redirect`, `file`, `stream`, `empty`, `text`, or the main content type |
| `bound` | `[{model:"Venue",id_hash:"7f3a9c21"}]` | route parameters: model basename + 8-hex HMAC of the key; scalar params as `{param, id_hash}` |
| `validation_failed` | `["otp"]` | keys of `ValidationException::errors()`, never messages |
| `exception` | `ModelNotFoundException` | class basename of the original cause |
| `auth_event` | `login_failed` | last auth event name during the turn |
| `gate` | `{action, mode, rule, applied}` | the verdict received and what was actually done; null when no check answered |
| `ua_hash` | 8 hex | hashed user agent |
| `dropped_since_last` | 0 | events dropped since the last successful send |

Example:

```json
{"v":1,"ts":1761600000.123,"session_key":"a1b2c3d4e5f60718","peer_key":"0f1e2d3c4b5a6978",
 "principal":"anon","verb":"POST","route":"portal.login","status":422,"latency_ms":38.2,
 "bytes_in":410,"bytes_out":1204,"req_shape":"{otp:str:6,phone:str:10}",
 "resp_shape":"{errors:{otp:[str:23*1]},message:str:23}","bound":[],
 "validation_failed":["otp"],"exception":"ValidationException","auth_event":null,
 "gate":null,"ua_hash":"9c8b7a6f","dropped_since_last":0}
```

### The event, schema v2: surface, identifiers, tag, shape, flags

As of 2026-10-31. Source: `docs/actor-identity.md`. v2 is v1 plus the fields
below; every v1 field keeps its name and meaning. The package emits `v: 2`
once it fills these; leesided accepts v1 and v2 side by side and stores
null for v2 columns on a v1 event. leesided must accept v2 before the
package ships it.

**Surface.** `surface` is one of `honeypot`, `webhook`, `api`, `web`,
evaluated in that order, first match wins: the route is in the honeypot
group; the route name or path prefix is in the configured webhook list
(default prefix `/webhooks/`); the request carries `Authorization: Bearer`,
a configured API-key header (default `X-Api-Key`, `Api-Key`), the `api`
middleware group or the `/api` prefix; else `web`. Config can force a
surface by route name or path prefix. `is_asset` is true when the path ends
in a configured static extension, whatever the surface.

**Identifiers.** Facts, not identity: the package records them, leesided
resolves actors from them (`docs/actor-identity.md` section 8).

| Field | Content | Rule |
| --- | --- | --- |
| `surface`, `is_asset` | `web`, false | as above |
| `credential_kind` | `bearer`, `api_key`, `webhook_sig`, null | which machine credential was presented |
| `credential_hash` | 16 hex or null | HMAC (`credential` namespace) of the token, key, or verified webhook signer id; never the value |
| `tag_id` | 16 hex or null | the id half of the Leeside tag cookie, hex |
| `tag_status` | `valid`, `absent`, `malformed`, `bad_mac`, `issued` | `issued` when this response set a new tag |
| `ip` | string or null | the client address as Laravel resolves it with trusted proxies; **socket transport only**: the `log` and `array` transports write null. leesided hashes it on ingest and stores `ip_hash` (16 hex, `ip` namespace), `net_hash` (16 hex of the /24 or /48, `net` namespace) and `asn`; the address is never written |
| `ip_trust` | `direct`, `forwarded` | `forwarded` only when the hop was a trusted proxy |
| `ua_class` | `chromium`, `firefox`, `safari`, `other_browser`, `library`, `empty` | cheap regex, no parser; the raw user agent never leaves PHP |
| `ua_hash` | 16 hex | widened from 8; the v1 column is replaced |
| `shape_hash` | 16 hex | the request-shape fingerprint below |
| `shape` | object | its components, so leesided can re-derive with another recipe |
| `flags` | list of strings | consistency flags below, per request only |
| `ja4`, `ja4t`, `h2_fp` | string or null | copied from `X-Leeside-JA4`, `-JA4T`, `-H2` only when the hop was a trusted proxy; else null and the flag `proxy_header_untrusted`. Contract only: nothing produces them yet |

`auth_id` from the source brief is `principal`; `session_hash` is
`session_key`; `ts_ms` is `ts`, which already carries microseconds.

**Tag cookie** (`web` surface only). Name `_lsd` (configurable). Value
`base64url(id || issued_at) . "." . base64url(mac)`: `id` 16 random bytes,
`issued_at` 4-byte big-endian unix seconds, `mac` the first 16 bytes of
`HMAC-SHA256(secret, id || issued_at)`. Secret `LEESIDE_TAG_SECRET`, else
derived from `APP_KEY` under the label `leeside-tag`. Attributes `HttpOnly;
SameSite=Lax; Path=/; Max-Age=31536000`, plus `Secure` when the request is
secure. Set only when `surface = web`, the response is `text/html` and no
`valid` tag came in; never on `api`, `webhook` or assets; a valid tag is
never rotated. Read from `$_COOKIE`, not the cookie bag, so `EncryptCookies`
cannot interfere; the install step adds `_lsd` to the host's
`encryptCookies(except: [...])`. An incoming value that looks like a
Laravel encrypted payload is `malformed` and logs one config warning.
Status: missing `absent`, wrong shape `malformed`, MAC mismatch `bad_mac`,
MAC ok `valid`.

This is the one place the package modifies a response other than a
denial, and it happens in `handle()`, since `terminate()` runs after the
response has gone out.

**Request shape** (JA4H-style). `shape` holds `method`, `http_version`
(`SERVER_PROTOCOL`), `has_cookie`, `has_referer`, `header_count` (client
headers only, nginx-added `X-Forwarded-*` and `X-Real-IP` excluded),
`accept_language` (first 4 chars of the primary language, else `0000`),
`header_names_hash` (lowercased names in received order), `cookie_names_hash`
(sorted names), `order_reliable` (false when header order was found not to
survive FastCGI, in which case `header_names_hash` is over sorted names).
`shape_hash` is the hash of those joined with `_`.

**Flags**, each from the current request alone: `ua_chromium_no_ch`,
`browser_no_sec_fetch`, `browser_no_accept_language`,
`html_get_no_html_accept`, `library_ua_on_web`, `cookies_on_api`,
`bearer_with_sec_fetch`, `tag_bad_mac`, `proxy_header_untrusted`.
Definitions in `docs/actor-identity.md` section 5. Flags are features,
never verdicts.

| `remote_port` | int or null | the client source port, to tell users apart behind one NAT address |
| `ts_ms` | int | request time in whole milliseconds; `ts` keeps the float with microseconds |

**What leesided does with v2.** `turns` gains the columns above
(migrations 0002, 0003). The probe gains `surface` so rules can match on
it. Windows gain a `credential` scope keyed on `credential_hash`. When a
credential is presented, the credential is the identity: the peer window
reads as empty for that probe and the sticky lookup skips the peer key, so
no rule ever rate-limits a partner's address on behalf of one of its users.
Without a credential the peer applies exactly as on `web`, whatever the
surface, so an unauthenticated scanner on `api` is still caught per
address. Actor resolution is a later phase.

An intended consequence: a peer blocked for `web` abuse is **not** blocked
when the same address arrives on `api` with a valid credential. The
credential's own window and decisions govern there. This is by design, not
a gap to close.

### Shape notation

Keys and types, never values.

- Scalars: `null`, `bool`, `int`, `num`, `file`, `obj`, `unk`.
- Strings: `str:<n>`, exact length up to 64, then `>64`, `>256`, `>1k`, `>4k`,
  `>16k`, `>64k`.
- Lists: `[int*12]`, typed by the first element.
- Maps: `{k:shape,...}`, keys sorted; a key longer than 24 chars is cut; a key
  that is itself a number of 6+ digits becomes `#`; reserved characters in
  keys (`: , { } [ ] *`) become `_`.
- Depth cap 4 renders as `{…}` or `[…]`; key cap 32 renders as `…+N`; the
  whole shape is cut at 2 KB.

### Hashing

HMAC-SHA256 under `LEESIDE_HASH_KEY` (derived from `APP_KEY` when unset, as
HMAC of the string "leeside"), one namespace per field so a session hash and a
principal hash of the same value never match. Truncated: session, principal,
peer, credential, tag, shape and (from v2) user agent to 16 hex; id to 8 hex.
leesided uses the same key and recipe for `ip` and `net`, so values join
across the two sides. There is one key and one recipe per install; no second
salt.

Sampling is deterministic on `session_key`: the first 8 hex digits as a draw
in [0, 1) compared against `sample_rate`, so a session is wholly in or out.
The synchronous check is never sampled.

### Transports

Behind a `Transport` interface with `send(array $event): bool`, which never
throws and never blocks the request:

- `udg`: one datagram per event via `stream_socket_sendto()` on
  `udg://<events socket>`, non-blocking, 1 s backoff after a failed connect,
  drop and count on any failure. Datagrams are atomic, so there is no framing.
- `log`: one JSON line per event to a Laravel log channel, for before leesided
  exists.
- `null`: discard.
- `array`: in memory, for tests.

### Sync check protocol

Behind a `RuleClient` interface with `check(array $probe): Verdict`, which
never throws and returns allow on any failure.

Client connects to `unix://<check socket>`, writes one JSON line, reads one
JSON line, closes. Connect and read are each bounded by `check.timeout_ms`
(default 2). After a failed connect the client skips the socket for 1 s, since
leesided being down is the normal state of a fresh install.

Probe:

```json
{"v":1,"ts":1761600000.123,"verb":"POST","route":"portal.login",
 "session_key":"a1b2c3d4e5f60718","peer_key":"0f1e2d3c4b5a6978","principal":"anon"}
```

A v2 probe adds `surface` and, when present, `credential_hash`, so rules can
match on the surface and count per credential:

```json
{"v":2,"ts":1761600000.123,"verb":"POST","route":"portal.login","surface":"web",
 "session_key":"a1b2c3d4e5f60718","peer_key":"0f1e2d3c4b5a6978","principal":"anon",
 "credential_hash":null}
```

Verdict:

```json
{"action":"block","mode":"enforce","rule":"portal-otp-burst","retry_after":30}
```

Actions: `allow`, `log`, `watch`, `rate_limit`, `challenge`, `block`.
Modes: `monitor`, `shadow`, `enforce`. Unknown values decode to allow and
monitor. No listener, timeout, bad JSON: all allow.

In enforce mode: `block` returns 403; `rate_limit` returns 429 with
`Retry-After`; `challenge` sets the request attribute `leeside.challenge` (to
the rule name) and lets the request continue, so the app decides what a
step-up looks like (re-OTP, captcha, re-login). Every other action, and every
verdict in monitor or shadow, is recorded on the event's `gate` field and
changes nothing. Denial bodies are generic (`Forbidden`, `Too Many Requests`,
JSON when the request expects JSON); no Leeside headers on the wire.

### Config keys

```php
'enabled'             => env('LEESIDE_ENABLED', true),          // kill switch
'register_middleware' => env('LEESIDE_REGISTER_MIDDLEWARE', true),
'gate_groups'         => ['web', 'api'],
'sample_rate'         => (float) env('LEESIDE_SAMPLE_RATE', 1.0),
'hash_key'            => env('LEESIDE_HASH_KEY'),
'transport'           => env('LEESIDE_TRANSPORT', 'udg'),       // udg | log | null
'events_socket'       => env('LEESIDE_EVENTS_SOCKET', '/run/leeside/events.sock'),
'log_channel'         => env('LEESIDE_LOG_CHANNEL'),
'check' => [
    'enabled'    => env('LEESIDE_CHECK_ENABLED', true),
    'socket'     => env('LEESIDE_CHECK_SOCKET', '/run/leeside/check.sock'),
    'timeout_ms' => (int) env('LEESIDE_CHECK_TIMEOUT_MS', 2),
],
'shape' => ['max_depth' => 4, 'max_keys' => 32, 'max_response_bytes' => 65536, 'max_shape_length' => 2048],
'ignore' => ['up', 'telescope*', 'horizon*', '_debugbar*', 'livewire*'],  // route names or URI fnmatch patterns
// v2
'surface' => [
    'honeypot_group'  => 'honeypot',                       // middleware group name; may not exist yet
    'webhook'         => ['/webhooks/'],                   // route names or path prefixes
    'api_key_headers' => ['X-Api-Key', 'Api-Key'],
    'force'           => [],                               // ['route.name' => 'api', '/partner/' => 'api']
    'asset_extensions'=> ['css', 'js', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf'],
],
'tag' => [
    'enabled' => env('LEESIDE_TAG_ENABLED', true),
    'cookie'  => env('LEESIDE_TAG_COOKIE', '_lsd'),
    'secret'  => env('LEESIDE_TAG_SECRET'),                // derived from APP_KEY when unset
],
'fingerprint' => [
    'proxy_headers' => ['X-Leeside-JA4', 'X-Leeside-JA4T', 'X-Leeside-H2'],
    'header_order_reliable' => env('LEESIDE_HEADER_ORDER_RELIABLE', true),   // set from the deploy-time test
],
```

Relative socket paths resolve against `base_path()`.

### php artisan leeside:tap

Binds the events datagram socket and pretty-prints each event (`--raw` for
NDJSON). With `--gate` it also serves the check socket, answering
`--action=block --mode=enforce --route=portal.login` (route repeatable) and
`allow` otherwise. This is the stand-in for leesided until the Rust engine
answers the same sockets.

### Never written, by construction

Raw paths with ids, query strings, header values other than the hashed user
agent, body values, phone numbers, OTPs, payment fields, tokens, cookies,
validation messages, exception messages, redirect targets. Reduction to shape
and hashing happen inside the middleware before serialisation; the event array
is built from reduced values only.

v2 adds two bounded exceptions. The client `ip` travels only over the Unix
socket to leesided on the same host, which hashes it on ingest and never
stores the address; the `log` and `array` transports write null. The tag
cookie's `id` is a random value the package itself minted, carries nothing
about the user, and is stored as `tag_id`; the cookie's MAC is never stored.
The raw user agent, credential values and header values still never leave
PHP: what crosses is `ua_class`, `credential_hash` and `shape`.

### Tests

PHPUnit with orchestra/testbench:

- Reducer notation on nested payloads, lists, files and numeric keys.
- Hasher namespaces differ for the same input; sampling is deterministic.
- A feature test that boots routes mirroring the sample app, drives them with
  phone and OTP values, binds `ArrayTransport` and `ArrayRuleClient` in the
  container, and asserts the emitted event field by field.
- A PII scan: collect every literal value the test sent (phones, OTPs, ids,
  the user agent) and assert none appears in `json_encode()` of any event.
- Gate tests: block (403), rate_limit (429 with Retry-After), challenge
  (attribute set, request continues), shadow (no effect, gate recorded),
  timeout and missing socket (allow).
- 404 and 500 are captured with `_unrouted` / the route and the exception
  basename; a 404 from a bound model records `ModelNotFoundException`.
- Routes in `ignore` produce no event and no check.

v2 (`docs/actor-identity.md` section 10):

- The tag is issued on an HTML `web` response and only there; never on
  `api`, `webhook`, JSON or asset responses. A valid tag presented back
  yields `valid` and no new `Set-Cookie`; a tampered MAC yields `bad_mac`
  and the flag; an encrypted-looking value yields `malformed` and one
  logged warning.
- Surface: bearer on a `web` route is `api`; the webhook prefix is
  `webhook`; a `force` override by route name wins.
- `credential_hash` is stable across requests for one token and never
  equals the token; the PII scan covers tokens, cookies and the user agent.
- `X-Leeside-JA4` from a hop that is not a trusted proxy is dropped and
  flagged.
- `ip` is null under the `log` and `array` transports.
- Header-order survival through nginx + php-fpm is a script in
  `leeside-sample/deploy/`, run against the real stack; its result sets
  `header_order_reliable`.

## Sample app spec: leeside-sample

A stock `composer create-project laravel/laravel leeside-sample`, SQLite, with
the package pulled in through a path repository so edits to the package show up
without a publish:

```json
"repositories": [{ "type": "path", "url": "../leeside-laravel", "options": { "symlink": true } }],
"require": { "leeside/laravel": "@dev" }
```

`.env` additions: `LEESIDE_EVENTS_SOCKET=storage/leeside/events.sock`,
`LEESIDE_CHECK_SOCKET=storage/leeside/check.sock`, `LEESIDE_HASH_KEY=` (a
random 32-byte value).

### Routes

Deliberately portal-shaped so the events look like a captive portal's will.

| Route name | Verb and URI | Behaviour |
| --- | --- | --- |
| `home` | GET / | the welcome view (an `html` response) |
| `portal.login` | POST /portal/login | validates `phone` digits:10 and `otp` digits:6; OTP `123456` fires `Login` and returns JSON `{ok:true}`; any other OTP fires `Failed` and returns 401 JSON |
| `venues.show` | GET /venues/{venue} | route-model binding on `Venue`; 404 via `ModelNotFoundException` for unknown ids |
| `api.venues.index` | GET /api/venues | JSON list of venues |
| `api.venues.visit` | POST /api/venues/{venue}/visit | a mutation; validates `guests` integer |
| `secret` | GET /secret | `abort(403)` |
| `boom` | GET /boom | throws `RuntimeException` (a 500) |

`Venue` model, migration (`id`, `name`, `city`, timestamps), seeder with six
venues. A `challenge` demo: a tiny app middleware that, when
`leeside.challenge` is set on the request, returns 428 with
`{"step_up":"otp"}`, so the whole verdict set can be shown end to end.

### bin/traffic.sh

curl against `php artisan serve` with a cookie jar so the session key is
stable. Three acts: a benign browse (home, three venues, API list, one visit);
a validation burst (ten logins with bad phone lengths and bad OTPs); an
enumeration (venues 1 to 25, most 404). Prints nothing itself; the tap shows
the events.

### Three-terminal flow (README)

```bash
php artisan leeside:tap                     # terminal 1: events and, with --gate, verdicts
php artisan serve                           # terminal 2
bin/traffic.sh                              # terminal 3
php artisan leeside:tap --gate --action=block --route=portal.login   # then rerun act two
```

### Two measurements the sample must make possible

They gate the production rollout:

1. Added latency per request with the package on versus
   `LEESIDE_ENABLED=false`, 500 requests each over the serve loop (target
   under 1 ms added).
2. A PII diff: run the traffic script, concatenate the tapped events, grep for
   every phone number, OTP, venue id and user agent string the script sent.
   Expect zero hits.

## Deploy: webapp.leeside.halowifi.com

The sample app runs at `https://webapp.leeside.halowifi.com` behind nginx and
PHP 8.3 FPM on the box the DNS record already points to, with a Let's Encrypt
certificate that renews itself. Ubuntu 24.04 assumed; adjust package names
otherwise. Keep the Cloudflare record DNS-only (grey cloud): nginx then sees
real client IPs, which `peer_key` depends on, and the HTTP-01 challenge is
plain.

### On the box

The box is the same EC2 instance Muse Code works on. The working copy in
`~/meta-hackathon/Leeside` is never served: nginx serves a separate
production checkout at `/var/www/leeside`, cloned from the working copy and
owned by `www-data`. That keeps the app's user away from the `ubuntu` home
directory, its SSH keys and any AWS credentials, which matters on a host that
will be attacked on purpose. Only committed work reaches production, since
the production checkout pulls from the working copy's commits.

| Item | Value |
| --- | --- |
| Working copy | `/home/ubuntu/meta-hackathon/Leeside`, where Muse Code runs; never served |
| Production checkout | `/var/www/leeside`, `git clone /home/ubuntu/meta-hackathon/Leeside /var/www/leeside`, owned by `www-data`; `leeside-laravel` and `leeside-sample` sit side by side inside it so the path repository keeps working |
| Web root | `/var/www/leeside/leeside-sample/public`, the only directory nginx serves |
| AWS | ports 80 and 443 open in the instance's security group; ufw alone is not enough |
| PHP-FPM | `unix:/run/php/php8.3-fpm.sock`, runs as `www-data` |
| Sockets | `/run/leeside/events.sock`, `/run/leeside/check.sock` in a `0770 www-data:www-data` directory created by systemd-tmpfiles on every boot |
| Event log | `/var/log/leeside/events.ndjson`, written by the tap service until leesided takes the sockets |
| Certificate | certbot with the nginx plugin, HTTP-01, renewed by `certbot.timer` |

### Files under deploy/ in leeside-sample

Nothing is hand-typed on the server. Both scripts are run with sudo from
the working copy (`sudo bash leeside-sample/deploy/install.sh`), never by
the agent, whose sandbox cannot write `/etc` or `/var/www` anyway.

| File | Contents |
| --- | --- |
| `deploy/install.sh` | Idempotent root script, `set -euo pipefail`: apt nginx, php8.3-fpm and the sqlite3, mbstring, xml, curl, zip, intl, bcmath extensions, certbot, python3-certbot-nginx, git, unzip, ufw; Composer if missing; the production checkout cloned from the working copy if `/var/www/leeside` is absent, with `safe.directory` set for root; tmpfiles entry `d /run/leeside 0770 www-data www-data -` applied with `systemd-tmpfiles --create`; `/var/log/leeside` owned by www-data; `ufw allow OpenSSH`, `ufw allow 'Nginx Full'`, enable; nginx site linked into sites-enabled, default site removed, `nginx -t`, reload; certbot run (below) plus a renewal deploy hook that reloads nginx; logrotate file installed; tap service enabled and started; finally calls deploy.sh |
| `deploy/deploy.sh` | Root script, never touches `/etc`: `git -C /var/www/leeside pull` from the working copy, `chown -R www-data:www-data /var/www/leeside`, then as www-data (`sudo -u www-data`) in `leeside-sample`: `composer install --no-dev --optimize-autoloader`, copy `.env.production.example` to `.env` only if `.env` is absent (then `php artisan key:generate`), `php artisan migrate --force` (`--seed` on first run), `php artisan optimize:clear` then `php artisan optimize`; storage and bootstrap/cache writable |
| `deploy/nginx/webapp.leeside.halowifi.com.conf` | Port 80 block only; certbot adds 443 and the redirect. `root .../public`, `index index.php`, `try_files $uri $uri/ /index.php?$query_string`, PHP via the FPM socket with `fastcgi_param SCRIPT_FILENAME $realpath_root$fastcgi_script_name` and `include fastcgi_params`, `fastcgi_hide_header X-Powered-By`, `client_max_body_size 10m`, headers `X-Frame-Options SAMEORIGIN`, `X-Content-Type-Options nosniff`, `Referrer-Policy strict-origin-when-cross-origin`, `location ~ /\.(?!well-known) { deny all; }`, own access and error logs |
| `deploy/systemd/leeside-tap.service` | `php artisan leeside:tap --raw` as www-data from the sample dir, stdout appended to `/var/log/leeside/events.ndjson`, `Restart=always`, `After=php8.3-fpm.service`; disabled the day leesided listens on the same paths |
| `deploy/logrotate/leeside` | daily, 14 rotations, copytruncate |
| `deploy/.env.production.example` | `APP_ENV=production`, `APP_DEBUG=false`, `APP_URL=https://webapp.leeside.halowifi.com`, `LOG_LEVEL=warning`, `SESSION_SECURE_COOKIE=true`, SQLite at the sample's `database/database.sqlite`, `LEESIDE_EVENTS_SOCKET=/run/leeside/events.sock`, `LEESIDE_CHECK_SOCKET=/run/leeside/check.sock`, `LEESIDE_HASH_KEY=` (generate 32 random bytes), `LEESIDE_SAMPLE_RATE=1.0` |

### Certificate

One command, idempotent, run by install.sh after the port 80 site is live:

```bash
certbot --nginx -d webapp.leeside.halowifi.com --redirect --agree-tos --no-eff-email -m mrinal@halowifi.com -n
certbot renew --dry-run
```

If it fails it is one of three things: the A record not resolving from
outside yet (`dig +short webapp.leeside.halowifi.com @1.1.1.1`), port 80
closed at a cloud security group rather than ufw, or the record still
proxied through Cloudflare.

### Deploy done-tests

- `https://webapp.leeside.halowifi.com` loads with a valid chain; `http://`
  answers 301.
- `nginx -t` passes and the 443 block certbot wrote still carries the headers
  and the dotfile deny.
- `POST /portal/login` with a bad OTP returns 422 JSON.
- `/var/log/leeside/events.ndjson` grows with every request and a grep for
  the values sent is empty.
- `systemctl status leeside-tap` is active; a reboot brings back
  `/run/leeside` and the tap.

## Done when

- `composer test` is green in the package.
- The tap shows events from all three acts of the traffic script.
- The PII grep is empty.
- The added latency is under 1 ms.
- `https://webapp.leeside.halowifi.com` answers over a valid certificate and
  its events land in `/var/log/leeside/events.ndjson`.
- The event JSON and the check protocol in this file are unchanged, or the
  change is written here first, so the Rust session starts from the same file.
