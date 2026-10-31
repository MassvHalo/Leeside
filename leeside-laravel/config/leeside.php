<?php

return [

    // Master kill switch. When false, no events are captured and no checks run.
    'enabled' => env('LEESIDE_ENABLED', true),

    // When false, the package registers nothing on the kernel/router; the app
    // wires the middleware itself (e.g. in bootstrap/app.php).
    'register_middleware' => env('LEESIDE_REGISTER_MIDDLEWARE', true),

    // Route groups the gate middleware is appended to. Put webhook routes in a
    // 'webhook' group whose signature verifier comes first: the gate is
    // appended after it, so the verified signer is on the probe.
    'gate_groups' => ['web', 'api', 'webhook'],

    // Deterministic sampling in [0, 1]; a session is wholly in or out.
    // The synchronous check is never sampled.
    'sample_rate' => (float) env('LEESIDE_SAMPLE_RATE', 1.0),

    // HMAC key. Derived from APP_KEY when unset.
    'hash_key' => env('LEESIDE_HASH_KEY'),

    // Event transport: udg | log | null.
    'transport' => env('LEESIDE_TRANSPORT', 'udg'),

    // Unix datagram socket leesided ingests events from.
    'events_socket' => env('LEESIDE_EVENTS_SOCKET', '/run/leeside/events.sock'),

    // Laravel log channel for the log transport (null = default channel).
    'log_channel' => env('LEESIDE_LOG_CHANNEL'),

    'check' => [
        'enabled' => env('LEESIDE_CHECK_ENABLED', true),

        // Unix stream socket leesided serves verdicts on.
        'socket' => env('LEESIDE_CHECK_SOCKET', '/run/leeside/check.sock'),

        // Bound in milliseconds for the connect and for the read, each.
        'timeout_ms' => (int) env('LEESIDE_CHECK_TIMEOUT_MS', 2),
    ],

    'shape' => [
        'max_depth' => 4,
        'max_keys' => 32,
        'max_response_bytes' => 65536,
        'max_shape_length' => 2048,
    ],

    // Route names or URI fnmatch patterns that produce no event and no check.
    'ignore' => ['up', 'telescope*', 'horizon*', '_debugbar*', 'livewire*'],

    // Schema v2: which kind of client a request belongs to. Evaluated in
    // order: force, honeypot group, webhook list, api (bearer, API-key header,
    // the api group or the /api prefix), else web.
    'surface' => [
        // Middleware group name whose routes are honeypots; may not exist yet.
        'honeypot_group' => 'honeypot',
        // Route names (fnmatch) or path prefixes (leading slash).
        'webhook' => ['/webhooks/'],
        'api_key_headers' => ['X-Api-Key', 'Api-Key'],
        // Force a surface by route name or path prefix: ['partner.*' => 'api', '/partner/' => 'api'].
        'force' => [],
        'asset_extensions' => ['css', 'js', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'woff', 'woff2', 'ttf'],
    ],

];
