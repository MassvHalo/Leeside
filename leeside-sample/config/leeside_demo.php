<?php

// Secrets for the demo's machine surfaces. Demo values by default so the
// sample runs from a fresh checkout; production sets both in .env.
return [
    'webhook_secret' => env('LEESIDE_DEMO_WEBHOOK_SECRET', 'demo-webhook-secret'),
    'api_key' => env('LEESIDE_DEMO_API_KEY', 'demo-api-key'),
];
