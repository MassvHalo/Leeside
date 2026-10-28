<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ChallengeDemo
{
    /**
     * Step-up demo: GateTurn runs after this middleware, so the attribute is
     * read on the way out and the response swapped for a 428.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $response = $next($request);

        if ($request->attributes->has('leeside.challenge')) {
            return response()->json(['step_up' => 'otp'], 428);
        }

        return $response;
    }
}
