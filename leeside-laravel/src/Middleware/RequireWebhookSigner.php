<?php

namespace Leeside\Laravel\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Leeside\Laravel\Surface\SurfaceClassifier;

/**
 * The 401 for a webhook whose signature did not verify. The app's verifier
 * never aborts: it sets `leeside.webhook_signer` on success or
 * `leeside.webhook_rejected` on failure, the gate probes (unverified, so
 * the peer applies), and this middleware, which the package appends to the
 * `webhook` group after the gate, refuses before the controller. A forgery
 * therefore reaches leesided as a probe and as a `rejected` event.
 */
class RequireWebhookSigner
{
    public function handle(Request $request, Closure $next): mixed
    {
        $signer = $request->attributes->get(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE);

        if (! is_string($signer) || $signer === '') {
            return new JsonResponse(['message' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
