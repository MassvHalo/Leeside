<?php

return [

    // Master kill switch. When false, no events are captured and no checks run.
    'enabled' => env('LEESIDE_ENABLED', true),

    // When false, the package registers nothing on the kernel/router; the app
    // wires the middleware itself (e.g. in bootstrap/app.php).
    'register_middleware' => env('LEESIDE_REGISTER_MIDDLEWARE', true),

    // Route groups the gate middleware is appended to.
    'gate_groups' => ['web', 'api'],

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

];
