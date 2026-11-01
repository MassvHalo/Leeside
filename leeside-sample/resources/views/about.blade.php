<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>About · Leeside Sample Portal</title>
    <link rel="stylesheet" href="/sample.css">
    <script src="/sample.js" defer></script>
</head>
<body>
<div class="wrap">
    <header class="top">
        <h1>About this <span>portal</span></h1>
    </header>
    <p class="sample-note">A second portal page so benign walks have somewhere to go.</p>
    <ul>
        <li><a href="{{ route('home') }}">Home</a></li>
        <li><a href="{{ route('venues.show', 1) }}">First venue</a></li>
        <li><a href="{{ route('api.venues.index') }}">/api/venues</a></li>
    </ul>
</div>
</body>
</html>
