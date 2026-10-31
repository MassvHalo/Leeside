# leeside/laravel

The Leeside capture layer for Laravel 11+: one PII-free turn event per
request to leesided over a Unix datagram socket, and a sub-millisecond rule
check over a Unix stream socket that acts only in enforce mode. The
contract is `../docs/brief.md`.

## Install

```bash
composer require leeside/laravel
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

A webhook's identity is its verified signer. The verifying middleware must
run before Leeside's `GateTurn` so the signer is on the probe, which means
a middleware in the `webhook` group, not a check in the controller:

```php
// bootstrap/app.php
$middleware->group('webhook', [\App\Http\Middleware\VerifyWebhookSignature::class]);
$middleware->validateCsrfTokens(except: ['webhooks/*']);

// the middleware, after the HMAC check passes
$request->attributes->set(\Leeside\Laravel\Surface\SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, $signerId);
```

```php
// routes
Route::post('/webhooks/demo', ...)->middleware('webhook');
```

`webhook` is in `leeside.gate_groups`, so the gate is appended after the
verifier. The signer id is hashed into `credential_hash`; the value itself
never leaves the app.

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

Keep it cheap and never let it throw. A user resolved by auth middleware
ahead of the gate also verifies whatever credential the request carried.
An unverified credential the app answers 401 or 403 is recorded as
`rejected`, which is what a credential-stuffing rule counts.

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

## Development

```bash
composer test
php artisan leeside:tap           # stand-in for leesided: prints events
php artisan leeside:tap --gate --action=block --mode=enforce --route=portal.login
```
