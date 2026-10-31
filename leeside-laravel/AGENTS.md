# leeside/laravel

Composer package: Leeside's capture layer for Laravel. One global middleware
(CaptureTurn) emits a PII-free turn event per request to leesided over a Unix
datagram socket in terminate(); one route-group middleware (GateTurn) asks
leesided over a Unix stream socket whether a deterministic rule matches, and
acts only when the verdict says enforce. Read ../docs/brief.md first.

## Non-negotiables
- Nothing identifying leaves the app unhashed, nothing valued leaves it
  unreduced. Reduce and hash before the event array exists. No raw paths,
  query strings, body values, header values (except the hashed user agent,
  its cheap class, and the hash of a presented credential; the client
  address travels on the socket to leesided only, which hashes it and never
  stores it, and the log and array transports null it),
  validation messages or exception messages, ever.
- No model call anywhere in this package. The sync check talks to leesided
  only, bounded by check.timeout_ms, and fails open on every failure.
- Capture never adds to the response path: handle() stamps the clock,
  terminate() does the work, and nothing in terminate() can throw.
- The middleware degrades to nothing when leesided is absent: dropped
  events are counted and carried on the next event as dropped_since_last.
- Enforcement applies only when mode == enforce; shadow and monitor
  verdicts are recorded on the event and change nothing.
- No HaloWiFi assumptions. This package installs on any Laravel 11+ app.

## Install notes the host app must follow (see README.md)
- `encryptCookies(except: ['_lsd'])` so the tag cookie is readable and
  writable in clear.
- Webhook signature verification runs as middleware in the `webhook`
  group, ahead of Leeside's gate, and sets `leeside.webhook_signer`; in the
  controller it is too late for the probe.
- API keys the app recognises are vouched for by binding
  `Leeside\Laravel\Surface\CredentialVerifier`; an unverified header is
  recorded but exempts nothing.

## Stack
- PHP 8.2+, illuminate/* ^11|^12|^13 only. No other runtime dependencies.
- Tests with PHPUnit and orchestra/testbench. `composer test` must pass.
- Follow Laravel package conventions: auto-discovered provider,
  publishable config, PSR-4 under Leeside\Laravel.

## Layout
config/leeside.php
src/LeesideServiceProvider.php
src/Middleware/{CaptureTurn,GateTurn}.php
src/Event/{TurnContext,TurnEventFactory,RouteName}.php
src/Reduce/ShapeReducer.php
src/Hash/Hasher.php
src/Transport/{Transport,UnixDatagramTransport,LogTransport,NullTransport,ArrayTransport}.php
src/Check/{RuleClient,UnixRuleClient,NullRuleClient,ArrayRuleClient,Verdict}.php
src/Console/TapCommand.php
src/Stats.php
tests/Unit, tests/Feature

## Done means
- Tests cover the schema, the PII scan, every gate action and the fail-open paths.
- `php artisan leeside:tap` shows events from the sample app.
- No commit, no push. I review the diff and commit.
