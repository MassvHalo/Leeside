<?php

namespace App\Leeside;

use Illuminate\Http\Request;
use Leeside\Laravel\Surface\CredentialVerifier;

/**
 * Vouches for the demo API key so Leeside treats a genuine key as the
 * identity at probe time. A wrong key is recorded as unverified, then
 * rejected once RequireApiKey answers 401.
 */
final class StaticApiKeyVerifier implements CredentialVerifier
{
    public function verify(Request $request, string $kind, string $value): bool
    {
        return $kind === 'api_key' && hash_equals((string) config('leeside_demo.api_key'), $value);
    }
}
