<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// Registered under the `webhook` group in bootstrap/app.php: the signature
// verifier runs first, then Leeside's gate, then this.
Route::post('/webhooks/demo', fn (Request $request) => response()->json([
    'received' => true,
    'signer' => $request->attributes->get('leeside.webhook_signer'),
]))->name('webhooks.demo');
