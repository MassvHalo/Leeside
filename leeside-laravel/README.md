# leeside/laravel

The Leeside capture layer for Laravel 11+: one PII-free turn event per
request to leesided over a Unix datagram socket, and a sub-millisecond rule
check over a Unix stream socket that acts only in enforce mode. The
contract is `../docs/brief.md`. The turn event carries hashes and shapes
only, save for the brief's bounded payload capture: `path` on unrouted
requests, redacted and truncated `sample_query`/`body_slice` on unrouted,
4xx or honeypot turns.

## Install

```bash
composer require 'leeside/laravel:@dev'
php artisan vendor:publish --tag=leeside-config   # optional
```

`.env`:

```dotenv
LEESIDE_HASH_KEY=            # 32 random bytes, base64; the same value goes into leesided's LEESIDED_HASH_KEY
LEESIDE_EVENTS_SOCKET=/run/leeside/events.sock
LEESIDE_CHECK_SOCKET=/run/leeside/check.sock
LEESIDE_TRANSPORT=udg        # udg | log | null
```

The provider registers `CaptureTurn` globally and `GateTurn` on the `web`,
`api` and `webhook` groups. With `LEESIDE_REGISTER_MIDDLEWARE=false` the
app wires both itself.

## Three things the host app must do

### 1. Keep the tag cookie in clear

Leeside sets a tag cookie `_lsd` on HTML pages of the `web` surface and
reads it back raw. In `bootstrap/app.php`:

```php
$middleware->encryptCookies(except: ['_lsd']);
```

Without this the cookie arrives encrypted, every request reads
`tag_status = malformed`, and the log carries one warning saying so.

### 2. Verify webhook signatures ahead of the gate

A webhook's identity is its verified signer, and a forgery must still
reach leesided. So the verifying middleware runs first in the `webhook`
group and **never aborts**: it names the signer on success or marks the
request rejected on failure, Leeside's gate probes either way (unverified
on failure, so the peer applies), and the package's `RequireWebhookSigner`,
appended after the gate, answers the 401 before the controller:

```php
// bootstrap/app.php
$middleware->group('webhook', [\App\Http\Middleware\VerifyWebhookSignature::class]);
$middleware->validateCsrfTokens(except: ['webhooks/*']);

// the middleware: set one of the two attributes, then always $next($request)
$request->attributes->set(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, $signerId);      // verified
$request->attributes->set(SurfaceClassifier::WEBHOOK_REJECTED_ATTRIBUTE, $claimedSigner); // rejected
```

```php
// routes
Route::post('/webhooks/demo', ...)->middleware('webhook');
```

`webhook` is in `leeside.gate_groups`, so the order is verifier, gate,
`RequireWebhookSigner`, controller. The signer (or the claimed one) is
hashed into `credential_hash`; the value itself never leaves the app. A
forged burst from one address shows up in leesided as rejected credentials
on one peer.

### 3. Vouch for API keys you recognise

A bare `Authorization: Bearer x` or `X-Api-Key` header is recorded as an
`unverified` credential and exempts the address from nothing. To have a
genuine key count as the identity at probe time, bind a verifier:

```php
// AppServiceProvider::register()
$this->app->bind(\Leeside\Laravel\Surface\CredentialVerifier::class, \App\Leeside\ApiKeyVerifier::class);
```

```php
final class ApiKeyVerifier implements CredentialVerifier
{
    public function verify(Request $request, string $kind, string $value): bool
    {
        return $kind === 'api_key' && hash_equals(config('services.partner.key'), $value);
    }
}
```

**It runs on the probe path**, inside the sub-millisecond budget: keep it
cheap, cache the key lookup (a config value, an in-memory map, a cache
store hit), and never let it throw. The package itself adds no database
round trip, and a verifier should not either. A user resolved by auth
middleware ahead of the gate also verifies whatever credential the request
carried.
An unverified credential the app answers 401 or 403 is recorded as
`rejected`, which is what a credential-stuffing rule counts.

## Livewire and Filament

Panel routes use their own middleware stack and their own
EncryptCookies, so the automatic group wiring does not reach them.
In the panel provider, add both middleware to the panel's stack and
list `_lsd` in that EncryptCookies except:

```php
use Leeside\Laravel\Middleware\GateTurn;
use Leeside\Laravel\Middleware\TagTurn;
->middleware([TagTurn::class, GateTurn::class])
```

This manual wiring is the documented path; picking panel stacks up
automatically is a follow-up.

## Header order

Run `leeside-sample/deploy/header-order-check.sh` once per host and put its
answer in `.env` as `LEESIDE_HEADER_ORDER` (`received`, `reversed` or
`unknown`). php-fpm hands headers over reversed; the package undoes that
before hashing header order, so the shape fingerprint stays comparable
across hosts. `unknown` hashes sorted names.

## Surfaces

Every event names its surface: `honeypot`, `webhook`, `api` or `web`, in
that order of precedence. Routes under odd prefixes can be forced in
`config/leeside.php`:

```php
'surface' => [
    'webhook' => ['/webhooks/', 'hooks.*'],
    'force'   => ['/partner/' => 'api'],
],
```

## Unrouted fallback

Unmatched requests still pass the gate: the package registers a fallback
route under the `web` group that records surface `web` with the `unrouted`
flag and answers the 404. An app with its own fallback disables the
package's with `'capture' => ['fallback' => false]` (or
`LEESIDE_CAPTURE_FALLBACK=false`) and attaches `GateTurn` to its own
route, or its unrouted requests go unprobed. The package fallback also
skips the group's CSRF check so unrouted POSTs 404 instead of 419; an
app-owned fallback under `web` that wants the same skips it on its
route the same way.

## Development

```bash
composer test
php artisan leeside:tap           # stand-in for leesided: prints events
php artisan leeside:tap --gate --action=block --mode=enforce --route=portal.login
```
