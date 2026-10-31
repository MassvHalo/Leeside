<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Leeside\Laravel\Surface\SurfaceClassifier;

/**
 * Demo webhook verification: HMAC-SHA256 of the raw body under a shared
 * secret, sent as X-Signature (hex). Runs in the `webhook` group ahead of
 * Leeside's gate, so the verified signer is on the probe. A check in the
 * controller would be too late for that.
 */
class VerifyWebhookSignature
{
    public function handle(Request $request, Closure $next): mixed
    {
        $secret = (string) config('leeside_demo.webhook_secret');
        $expected = hash_hmac('sha256', (string) $request->getContent(), $secret);
        $given = (string) $request->header('X-Signature', '');

        if ($given === '' || ! hash_equals($expected, $given)) {
            return response()->json(['message' => 'bad signature'], 401);
        }

        $signer = (string) $request->header('X-Signer', 'demo-partner');
        $request->attributes->set(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, $signer);

        return $next($request);
    }
}
