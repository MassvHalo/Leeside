<?php

namespace Leeside\Laravel\Surface;

use Illuminate\Http\Request;

/**
 * An app-registered check that a presented machine credential is genuine.
 * Bind an implementation to this interface in the container and Leeside
 * calls it while building the probe, so an API key the app recognises
 * counts as verified before the controller runs. Must be cheap and must
 * not throw; a throw reads as "not verified".
 */
interface CredentialVerifier
{
    /**
     * @param  string  $kind  `bearer`, `api_key` or `webhook_sig`
     * @param  string  $value  the raw credential; never store or log it
     */
    public function verify(Request $request, string $kind, string $value): bool;
}
