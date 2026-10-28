<?php

use App\Models\Venue;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::get('/venues', fn () => response()->json(Venue::all()))->name('api.venues.index');

Route::post('/venues/{venue}/visit', function (Request $request, Venue $venue) {
    $data = $request->validate(['guests' => 'required|integer|min:1']);

    return response()->json(['venue' => $venue->id, 'guests' => $data['guests'], 'city' => $venue->city]);
})->name('api.venues.visit');
