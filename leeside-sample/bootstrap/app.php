<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: function (): void {
            // The verifier sits first in the group; Leeside appends its gate
            // after it, so the verified signer is on the probe.
            Route::middleware('webhook')->group(__DIR__.'/../routes/webhooks.php');
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->validateCsrfTokens(except: ['portal/login', 'api/*', 'webhooks/*']);
        $middleware->appendToGroup('web', \App\Http\Middleware\ChallengeDemo::class);
        $middleware->group('webhook', [\App\Http\Middleware\VerifyWebhookSignature::class]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*', 'portal/login') || $request->expectsJson(),
        );
    })->create();
