<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Leeside\Laravel\Surface\SurfaceClassifier;

/**
 * Demo webhook verification: HMAC-SHA256 of the raw body under a shared
 * secret, sent as X-Signature (hex). Runs first in the `webhook` group and
 * never aborts: it names the verified signer, or marks the request rejected,
 * and lets Leeside's gate probe either way. The package's
 * RequireWebhookSigner, appended after the gate, answers the 401, so a
 * forgery reaches leesided as a probe and a `rejected` event before the
 * controller is ever reached.
 */
class VerifyWebhookSignature
{
    public function handle(Request $request, Closure $next): mixed
    {
        $secret = (string) config('leeside_demo.webhook_secret');
        $expected = hash_hmac('sha256', (string) $request->getContent(), $secret);
        $given = (string) $request->header('X-Signature', '');

        if ($given !== '' && hash_equals($expected, $given)) {
            $request->attributes->set(
                SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE,
                (string) $request->header('X-Signer', 'demo-partner')
            );
        } else {
            // The claimed signer (or the bare signature) is what gets hashed
            // as the rejected credential; the value itself never leaves.
            $request->attributes->set(
                SurfaceClassifier::WEBHOOK_REJECTED_ATTRIBUTE,
                (string) $request->header('X-Signer', $given !== '' ? $given : 'unsigned')
            );
        }

        return $next($request);
    }
}
