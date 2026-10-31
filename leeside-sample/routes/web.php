<?php

use App\Models\Venue;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Str;
use App\Models\User;

Route::get('/', fn () => view('welcome', ['venues' => Venue::all()]))->name('home');

Route::post('/portal/login', function (Request $request) {
    $data = $request->validate(['phone' => 'required|digits:10', 'otp' => 'required|digits:6']);

    $user = User::firstOrCreate(
        ['email' => 'demo@example.com'],
        ['name' => 'Demo Portal User', 'password' => Str::random(32)]
    );

    if ($data['otp'] === '123456') {
        Auth::guard('web')->login($user);

        return response()->json(['ok' => true]);
    }

    event(new Failed('web', $user, ['phone' => $data['phone']]));

    return response()->json(['ok' => false], 401);
})->name('portal.login');

Route::get('/venues/{venue}', fn (Venue $venue) => response()->json($venue))->name('venues.show');

Route::get('/secret', fn () => abort(403))->name('secret');

// Reserved for the honeypot group: a named 404 for now, so the surface rule
// can pick it up by route name later.
Route::get('/admin-backup', fn () => abort(404))->name('admin.backup');

Route::get('/boom', function () {
    throw new RuntimeException('boom');
})->name('boom');
