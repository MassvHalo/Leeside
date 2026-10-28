<?php

namespace Leeside\Laravel\Tests\Feature;

class CaptureTest extends SampleAppTestCase
{
    public function test_home_event(): void
    {
        $this->get('/')->assertOk();

        $event = $this->lastEvent();

        $this->assertSame('home', $event['route']);
        $this->assertSame('GET', $event['verb']);
        $this->assertSame(200, $event['status']);
        $this->assertSame('html', $event['resp_shape']);
        $this->assertNull($event['gate']);
    }

    public function test_login_success_event_field_by_field(): void
    {
        $payload = ['phone' => '0123456789', 'otp' => '123456'];
        $response = $this->postJson('/portal/login', $payload, ['User-Agent' => 'FieldTest/1.0']);
        $response->assertOk();

        $event = $this->lastEvent();
        $hasher = $this->hasher();

        $this->assertSame(1, $event['v']);
        $this->assertIsFloat($event['ts']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $event['session_key']);
        $this->assertNotSame($event['peer_key'], $event['session_key']);
        $this->assertSame($hasher->peerKey('127.0.0.1', 'FieldTest/1.0'), $event['peer_key']);
        $this->assertSame($hasher->principal('7'), $event['principal']);
        $this->assertSame('POST', $event['verb']);
        $this->assertSame('portal.login', $event['route']);
        $this->assertSame(200, $event['status']);
        $this->assertIsFloat($event['latency_ms']);
        $this->assertGreaterThanOrEqual(0.0, $event['latency_ms']);
        $this->assertSame(strlen((string) json_encode($payload)), $event['bytes_in']);
        $this->assertSame(strlen($response->getContent()), $event['bytes_out']);
        $this->assertSame('{otp:str:6,phone:str:10}', $event['req_shape']);
        $this->assertSame('{ok:bool}', $event['resp_shape']);
        $this->assertSame([], $event['bound']);
        $this->assertNull($event['validation_failed']);
        $this->assertNull($event['exception']);
        $this->assertSame('login', $event['auth_event']);
        $this->assertSame(
            ['action' => 'allow', 'mode' => 'monitor', 'rule' => null, 'applied' => false],
            $event['gate']
        );
        $this->assertSame($hasher->uaHash('FieldTest/1.0'), $event['ua_hash']);
        $this->assertSame(0, $event['dropped_since_last']);
    }

    public function test_fixed_session_id_produces_stable_session_key(): void
    {
        $sessionId = str_repeat('a1', 20);
        $this->withCredentials()->withCookie((string) config('session.cookie'), $sessionId);

        $this->postJson('/portal/login', ['phone' => '0123456789', 'otp' => '000000'])
            ->assertStatus(401);

        $event = $this->lastEvent();

        $this->assertSame($this->hasher()->sessionKey($sessionId), $event['session_key']);
        $this->assertSame('anon', $event['principal']);
        $this->assertSame('login_failed', $event['auth_event']);
        $this->assertSame('{ok:bool}', $event['resp_shape']);
    }

    public function test_validation_failure_records_keys_and_exception(): void
    {
        $this->postJson('/portal/login', ['phone' => '123', 'otp' => '12'])->assertStatus(422);

        $event = $this->lastEvent();
        $failed = $event['validation_failed'];
        sort($failed);

        $this->assertSame('portal.login', $event['route']);
        $this->assertSame(422, $event['status']);
        $this->assertSame(['otp', 'phone'], $failed);
        $this->assertSame('ValidationException', $event['exception']);
        $this->assertSame('{otp:str:2,phone:str:3}', $event['req_shape']);
        $this->assertStringStartsWith('{errors:{otp:[str:', $event['resp_shape']);
    }

    public function test_venue_show_binds_model(): void
    {
        $this->getJson('/venues/1')->assertOk();

        $event = $this->lastEvent();

        $this->assertSame('venues.show', $event['route']);
        $this->assertSame(
            [['model' => 'TestVenue', 'id_hash' => $this->hasher()->idHash('1')]],
            $event['bound']
        );
        $this->assertSame('{name:str:16}', $event['resp_shape']);
    }

    public function test_api_visit_validates_and_binds(): void
    {
        $this->postJson('/api/venues/2/visit', ['guests' => 3])->assertOk();

        $event = $this->lastEvent();

        $this->assertSame('api.venues.visit', $event['route']);
        $this->assertSame(
            [['model' => 'TestVenue', 'id_hash' => $this->hasher()->idHash('2')]],
            $event['bound']
        );
        $this->assertSame('{guests:int}', $event['req_shape']);
        $this->assertSame('{guests:int,venue:int}', $event['resp_shape']);

        $this->postJson('/api/venues/2/visit', ['guests' => 'many'])->assertStatus(422);

        $event = $this->lastEvent();

        $this->assertSame(['guests'], $event['validation_failed']);
        $this->assertSame('ValidationException', $event['exception']);
    }

    public function test_api_index_lists_venues_as_shaped_list(): void
    {
        $this->getJson('/api/venues')->assertOk();

        $event = $this->lastEvent();

        $this->assertSame('api.venues.index', $event['route']);
        $this->assertSame('[str:16*3]', $event['resp_shape']);
    }

    public function test_unknown_venue_records_model_not_found(): void
    {
        $this->getJson('/venues/999')->assertNotFound();

        $event = $this->lastEvent();

        $this->assertSame('venues.show', $event['route']);
        $this->assertSame(404, $event['status']);
        $this->assertSame('ModelNotFoundException', $event['exception']);
    }

    public function test_plain_404_is_unrouted(): void
    {
        $this->get('/missing')->assertNotFound();

        $event = $this->lastEvent();

        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame(404, $event['status']);
        $this->assertSame('NotFoundHttpException', $event['exception']);
    }

    public function test_500_records_route_and_exception(): void
    {
        $this->get('/boom')->assertStatus(500);

        $event = $this->lastEvent();

        $this->assertSame('boom', $event['route']);
        $this->assertSame(500, $event['status']);
        $this->assertSame('RuntimeException', $event['exception']);
    }

    public function test_authorization_and_csrf_exceptions_unwrap(): void
    {
        $this->get('/deny')->assertForbidden();
        $this->assertSame('AuthorizationException', $this->lastEvent()['exception']);

        $this->get('/csrf-throw')->assertStatus(419);
        $this->assertSame('TokenMismatchException', $this->lastEvent()['exception']);
    }

    public function test_403_abort_is_captured(): void
    {
        $this->get('/secret')->assertForbidden();

        $event = $this->lastEvent();

        $this->assertSame('secret', $event['route']);
        $this->assertSame(403, $event['status']);
    }

    public function test_unnamed_route_uses_uri_pattern(): void
    {
        $this->get('/plain')->assertOk();

        $event = $this->lastEvent();

        $this->assertSame('plain', $event['route']);
        $this->assertNull($event['gate']);
    }

    public function test_ignored_routes_emit_nothing_and_skip_check(): void
    {
        $this->get('/up')->assertOk();
        $this->get('/livewire/update')->assertOk();

        $this->assertSame([], $this->transport->events);
        $this->assertSame([], $this->rules->probes);
    }

    public function test_disabled_package_emits_nothing(): void
    {
        $this->app['config']->set('leeside.enabled', false);

        $this->get('/')->assertOk();
        $this->postJson('/portal/login', ['phone' => '0123456789', 'otp' => '123456'])->assertOk();

        $this->assertSame([], $this->transport->events);
        $this->assertSame([], $this->rules->probes);
    }

    public function test_sampled_out_requests_still_check(): void
    {
        $this->app['config']->set('leeside.sample_rate', 0.0);

        $this->postJson('/portal/login', ['phone' => '0123456789', 'otp' => '123456'])->assertOk();

        $this->assertSame([], $this->transport->events);
        $this->assertCount(1, $this->rules->probes);
    }

    public function test_dropped_events_are_counted_and_carried_once(): void
    {
        $this->transport->succeed = false;
        $this->get('/')->assertOk();
        $this->get('/')->assertOk();

        $this->assertSame([], $this->transport->events);

        $this->transport->succeed = true;
        $this->get('/')->assertOk();

        $this->assertSame(2, $this->lastEvent()['dropped_since_last']);

        $this->get('/')->assertOk();
        $this->assertSame(0, $this->lastEvent()['dropped_since_last']);
    }

    public function test_pii_scan(): void
    {
        $phone = '0123456789';
        $goodOtp = '123456';
        $badOtp = '000000';

        $this->withHeader('User-Agent', 'PII-Probe-UA/1.0');
        $this->withHeader('X-Test-Header', 'ZZZ-header-secret');

        $this->get('/?token=ZZZ-query-secret')->assertOk();
        $this->postJson('/portal/login', ['phone' => $phone, 'otp' => $goodOtp])->assertOk();
        $this->postJson('/portal/login', ['phone' => $phone, 'otp' => $badOtp])->assertStatus(401);
        $invalid = $this->postJson('/portal/login', ['phone' => '123', 'otp' => '12'])->assertStatus(422);
        $this->getJson('/venues/1')->assertOk();
        $this->getJson('/api/venues')->assertOk();
        $this->postJson('/api/venues/2/visit', ['guests' => 3])->assertOk();
        $this->get('/boom')->assertStatus(500);

        $this->assertCount(8, $this->transport->events);

        $json = $this->eventsJson();
        $literals = [
            $phone,
            $goodOtp,
            $badOtp,
            'PII-Probe-UA/1.0',
            'ZZZ-header-secret',
            'ZZZ-query-secret',
            'ZZZ-Alpine-Lodge',
            'Harbor Inn',
            'ZZZ-boom-secret',
            '/venues/1',
            '/api/venues/2/visit',
            '127.0.0.1',
            $this->app['session']->getId(),
            $invalid->json('message'),
        ];

        foreach ($literals as $literal) {
            $this->assertNotSame('', $literal, 'vacuous literal in PII scan');
            $this->assertStringNotContainsString($literal, $json, "leaked: {$literal}");
        }
    }
}
