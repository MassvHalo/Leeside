<?php

use App\Models\Venue;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/venues', fn () => response()->json(Venue::all()))->name('api.venues.index');

// Keyed: RequireApiKey answers the 401; StaticApiKeyVerifier tells Leeside
// whether the key was genuine.
Route::get('/ping', fn () => response()->json(['pong' => true]))
    ->middleware(\App\Http\Middleware\RequireApiKey::class)->name('api.ping');

Route::post('/venues/{venue}/visit', function (Request $request, Venue $venue) {
    $data = $request->validate(['guests' => 'required|integer|min:1']);

    return response()->json(['venue' => $venue->id, 'guests' => $data['guests'], 'city' => $venue->city]);
})->name('api.venues.visit');
