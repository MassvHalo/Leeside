<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Leeside\Laravel\Surface\SurfaceClassifier;
use Leeside\Laravel\Transport\LogTransport;

/** Schema v2: surface classification and the identifier fields. */
class IdentityTest extends SampleAppTestCase
{
    protected function defineSampleRoutes(): void
    {
        parent::defineSampleRoutes();

        $router = $this->app['router'];
        $router->post('/webhooks/demo', function (Request $request) {
            $request->attributes->set(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, 'acct_42');

            return new JsonResponse(['received' => true]);
        })->name('webhooks.demo');
        $router->get('/build/app.css', fn () => new Response('body{}', 200, ['Content-Type' => 'text/css']))
            ->middleware('web')->name('asset.css');
    }

    public function test_web_page_has_v2_identifiers(): void
    {
        $before = microtime(true);
        $this->withHeader('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36')
            ->get('/venues/1')->assertOk();

        $event = $this->lastEvent();

        $this->assertSame(2, $event['v']);
        $this->assertSame('web', $event['surface']);
        $this->assertFalse($event['is_asset']);
        $this->assertNull($event['credential_kind']);
        $this->assertNull($event['credential_hash']);
        $this->assertNull($event['ip'], 'the array transport nulls the address');
        $this->assertSame('direct', $event['ip_trust']);
        $this->assertSame('chromium', $event['ua_class']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $event['ua_hash']);
        $this->assertTrue($event['remote_port'] === null || is_int($event['remote_port']));
        $this->assertIsInt($event['ts_ms']);
        $this->assertSame((int) floor($event['ts'] * 1000), $event['ts_ms']);
        $this->assertGreaterThanOrEqual((int) floor($before * 1000), $event['ts_ms']);

        $probe = $this->rules->probes[0];
        $this->assertSame(2, $probe['v']);
        $this->assertSame('web', $probe['surface']);
        $this->assertNull($probe['credential_hash']);
    }

    public function test_api_group_route_is_api(): void
    {
        $this->getJson('/api/venues')->assertOk();

        $event = $this->lastEvent();
        $this->assertSame('api', $event['surface']);
        $this->assertNull($event['credential_kind']);
        $this->assertSame('api', $this->rules->probes[0]['surface']);
    }

    public function test_bearer_on_a_web_route_is_api_with_a_stable_credential_hash(): void
    {
        $token = 'ZZZ-bearer-secret-token-1234567890';

        $this->withHeader('Authorization', 'Bearer '.$token)->get('/venues/1')->assertOk();
        $first = $this->lastEvent();
        $this->withHeader('Authorization', 'Bearer '.$token)->get('/venues/1')->assertOk();
        $second = $this->lastEvent();

        $this->assertSame('api', $first['surface']);
        $this->assertSame('bearer', $first['credential_kind']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $first['credential_hash']);
        $this->assertSame($first['credential_hash'], $second['credential_hash'], 'stable across requests');
        $this->assertSame($this->hasher()->credentialHash($token), $first['credential_hash']);
        $this->assertNotSame($token, $first['credential_hash']);
        $this->assertStringNotContainsString($token, $this->eventsJson(), 'the token never leaves');
        $this->assertStringNotContainsString($token, (string) json_encode($this->rules->probes));
        $this->assertSame($first['credential_hash'], $this->rules->probes[0]['credential_hash'], 'the probe carries the same hash');
        $this->assertSame('api', $this->rules->probes[0]['surface']);

        $this->withHeader('Authorization', 'Bearer other-token')->get('/')->assertOk();
        $this->assertNotSame($first['credential_hash'], $this->lastEvent()['credential_hash']);
    }

    public function test_api_key_header_is_api(): void
    {
        $this->withHeader('X-Api-Key', 'ZZZ-key-secret')->get('/')->assertOk();

        $event = $this->lastEvent();
        $this->assertSame('api', $event['surface']);
        $this->assertSame('api_key', $event['credential_kind']);
        $this->assertSame($this->hasher()->credentialHash('ZZZ-key-secret'), $event['credential_hash']);
        $this->assertStringNotContainsString('ZZZ-key-secret', $this->eventsJson());
    }

    public function test_webhook_prefix_is_webhook_and_carries_the_verified_signer(): void
    {
        $this->postJson('/webhooks/demo', ['x' => 1], ['Authorization' => 'Bearer t'])->assertOk();

        $event = $this->lastEvent();
        $this->assertSame('webhook', $event['surface'], 'the webhook list beats a bearer');
        $this->assertSame('webhook_sig', $event['credential_kind']);
        $this->assertSame($this->hasher()->credentialHash('acct_42'), $event['credential_hash']);
        $this->assertStringNotContainsString('acct_42', $this->eventsJson());
    }

    public function test_force_override_by_route_name(): void
    {
        $this->app['config']->set('leeside.surface.force', ['venues.show' => 'api']);

        $this->get('/venues/1')->assertOk();

        $this->assertSame('api', $this->lastEvent()['surface']);
        $this->assertSame('api', $this->rules->probes[0]['surface']);
    }

    public function test_asset_flag(): void
    {
        $this->get('/build/app.css')->assertOk();

        $event = $this->lastEvent();
        $this->assertTrue($event['is_asset']);
        $this->assertSame('web', $event['surface']);
    }

    public function test_library_user_agent_is_classified(): void
    {
        $this->withHeader('User-Agent', 'python-requests/2.32.3')->get('/')->assertOk();
        $this->assertSame('library', $this->lastEvent()['ua_class']);

        $this->withHeader('User-Agent', '')->get('/')->assertOk();
        $this->assertSame('empty', $this->lastEvent()['ua_class']);
    }

    public function test_log_transport_nulls_the_address(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'leeside-log-');
        $this->app['config']->set('logging.channels.leeside_test', ['driver' => 'single', 'path' => $path, 'level' => 'debug']);
        $transport = new LogTransport($this->app['log'], 'leeside_test');

        $this->assertTrue($transport->send(['v' => 2, 'ip' => '203.0.113.7', 'route' => 'home']));

        $written = (string) file_get_contents($path);
        @unlink($path);
        $this->assertStringContainsString('"ip":null', $written);
        $this->assertStringNotContainsString('203.0.113.7', $written);
    }
}
