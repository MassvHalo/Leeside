<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Session\Middleware\StartSession;
use Leeside\Laravel\Check\ArrayRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Check\Verdict;
use Leeside\Laravel\LeesideServiceProvider;
use Leeside\Laravel\Transport\Transport;

class FallbackTest extends SampleAppTestCase
{
    private RecordingTransport $recorder;

    protected function setUp(): void
    {
        parent::setUp();

        // The socket view: ArrayTransport nulls the capture like the log
        // transport does, so this recorder keeps what the socket carries.
        $this->recorder = new RecordingTransport;
        $this->app->instance(Transport::class, $this->recorder);
    }

    private function registerPackageFallback(): void
    {
        // Production order, reproduced: the provider's booted callback runs
        // after the app's routes load, so the catch-all lands last.
        $this->app->getProvider(LeesideServiceProvider::class)->registerFallbackRoute();
    }

    private function scriptVerdict(Verdict $verdict): void
    {
        $this->rules = new ArrayRuleClient($verdict);
        $this->app->instance(RuleClient::class, $this->rules);
    }

    public function test_package_fallback_probes_and_404s(): void
    {
        $this->registerPackageFallback();

        // Real routes still match first: the catch-all is last.
        $this->get('/venues/1')->assertOk();

        $response = $this->get('/nope?x=1');
        $response->assertNotFound();

        $this->assertCount(2, $this->rules->probes);
        $this->assertSame('_unrouted', $this->rules->probes[1]['route']);
        $this->assertSame('web', $this->rules->probes[1]['surface']);

        $this->assertCount(2, $this->recorder->events);
        $this->assertNull($this->recorder->events[0]['path']);
        $event = $this->recorder->events[1];
        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame('web', $event['surface']);
        $this->assertContains('unrouted', $event['flags']);
        $this->assertSame(404, $event['status']);
        $this->assertSame('/nope', $event['path']);
        $this->assertSame('x=1', $event['sample_query']);
    }

    public function test_package_fallback_covers_post(): void
    {
        $this->registerPackageFallback();

        $response = $this->post('/nope-post', ['a' => 'b']);
        $response->assertNotFound();

        $this->assertCount(1, $this->rules->probes);
        $this->assertSame('_unrouted', $this->rules->probes[0]['route']);
        $this->assertSame('_unrouted', $this->recorder->events[0]['route']);
    }

    public function test_unrouted_post_skips_csrf_and_404s(): void
    {
        // Mirror the sample app's web group: a real session and a real,
        // enforcing CSRF check ahead of the gate. (The base case neuters
        // CSRF, the middleware skips itself under unit tests, and the test
        // app's web group starts empty.) Without the fallback's
        // withoutMiddleware this POST 419s ahead of the gate, unprobed.
        $this->app->instance('env', 'production');
        $this->app->forgetInstance(PreventRequestForgery::class);
        $router = $this->app['router'];
        $router->prependMiddlewareToGroup('web', PreventRequestForgery::class);
        $router->prependMiddlewareToGroup('web', StartSession::class);
        $this->registerPackageFallback();

        $response = $this->post('/nope-post', ['a' => 'b']);
        $response->assertNotFound();

        $this->assertCount(1, $this->rules->probes);
        $this->assertSame('_unrouted', $this->rules->probes[0]['route']);
        $this->assertSame(404, $this->recorder->events[0]['status']);
    }

    public function test_sticky_block_answers_429_on_unrouted_path(): void
    {
        $this->registerPackageFallback();
        $this->scriptVerdict(new Verdict('rate_limit', 'enforce', 'venue-enumeration', 30));

        $response = $this->get('/nope');
        $response->assertStatus(429);
        $this->assertSame('30', $response->headers->get('Retry-After'));

        $event = $this->recorder->events[0];
        $this->assertSame(429, $event['status']);
        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame(
            ['action' => 'rate_limit', 'mode' => 'enforce', 'rule' => 'venue-enumeration', 'applied' => true],
            $event['gate']
        );
    }

    public function test_app_fallback_with_gate_behaves_the_same(): void
    {
        // The app's own catch-all, last, under the web group so the gate
        // rides along. The package fallback stays disabled (base env).
        $this->app['router']->fallback(fn () => response('app-fallback-marker', 404))
            ->middleware('web');

        $response = $this->get('/nope');
        $response->assertNotFound();
        $this->assertSame('app-fallback-marker', $response->getContent());

        $this->assertCount(1, $this->rules->probes);
        $this->assertSame('_unrouted', $this->rules->probes[0]['route']);
        $this->assertSame('web', $this->rules->probes[0]['surface']);

        $event = $this->recorder->events[0];
        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame('web', $event['surface']);
        $this->assertContains('unrouted', $event['flags']);
        $this->assertSame('/nope', $event['path']);
    }
}

class RecordingTransport implements Transport
{
    /** @var array<int, array<string, mixed>> */
    public array $events = [];

    public function send(array $event): bool
    {
        $this->events[] = $event;

        return true;
    }
}
