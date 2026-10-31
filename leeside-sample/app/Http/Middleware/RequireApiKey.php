<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

/**
 * Demo API authentication: a static key in X-Api-Key. This is the app's
 * own 401; Leeside learns whether the key was genuine from the
 * StaticApiKeyVerifier binding, not from this middleware.
 */
class RequireApiKey
{
    public function handle(Request $request, Closure $next): mixed
    {
        $given = (string) $request->header('X-Api-Key', '');
        $expected = (string) config('leeside_demo.api_key');

        if ($given === '' || ! hash_equals($expected, $given)) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return $next($request);
    }
}
