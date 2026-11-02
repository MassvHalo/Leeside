<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Routing\UrlRoutable;
use Illuminate\Contracts\Session\Session as LaravelSession;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Route;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Leeside\Laravel\Event\RouteName;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Event\TurnEventFactory;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Reduce\ShapeReducer;
use Leeside\Laravel\Stats;
use Leeside\Laravel\Tests\TestCase;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;

class TurnEventFactoryTest extends TestCase
{
    private Hasher $hasher;
    private TurnEventFactory $factory;
    private Stats $stats;

    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = new Hasher('test-key');
        $this->stats = new Stats;
        $this->factory = new TurnEventFactory(
            $this->hasher, new ShapeReducer, $this->app['auth'], $this->stats
        );
    }

    public function test_builds_full_event_field_by_field(): void
    {
        $request = Request::create(
            '/portal/login', 'POST',
            ['phone' => '0123456789', 'otp' => '123456'],
            [], [],
            ['CONTENT_LENGTH' => '410', 'HTTP_USER_AGENT' => 'TestAgent/1.0', 'REMOTE_ADDR' => '10.0.0.9']
        );
        $response = new JsonResponse(['ok' => true], 200);
        $context = new TurnContext;
        $context->begin();
        $context->recordRoute('portal.login');

        $event = $this->factory->build($request, $response, $context);

        $peer = $this->hasher->peerKey('10.0.0.9', 'TestAgent/1.0');
        $this->assertSame(2, $event['v']);
        $this->assertSame($context->tsUs, $event['ts']);
        $this->assertSame($peer, $event['session_key']);
        $this->assertSame($peer, $event['peer_key']);
        $this->assertSame('anon', $event['principal']);
        $this->assertSame('POST', $event['verb']);
        $this->assertSame('portal.login', $event['route']);
        $this->assertSame(200, $event['status']);
        $this->assertIsFloat($event['latency_ms']);
        $this->assertGreaterThanOrEqual(0.0, $event['latency_ms']);
        $this->assertSame(410, $event['bytes_in']);
        $this->assertSame(strlen((string) $response->getContent()), $event['bytes_out']);
        $this->assertSame('{otp:str:6,phone:str:10}', $event['req_shape']);
        $this->assertSame('{ok:bool}', $event['resp_shape']);
        $this->assertSame([], $event['bound']);
        $this->assertNull($event['validation_failed']);
        $this->assertNull($event['exception']);
        $this->assertNull($event['auth_event']);
        $this->assertNull($event['gate']);
        $this->assertSame($this->hasher->uaHash('TestAgent/1.0'), $event['ua_hash']);
        $this->assertSame(0, $event['dropped_since_last']);
    }

    public function test_carries_context_state(): void
    {
        $context = new TurnContext;
        $context->begin();
        $context->recordRoute('portal.login');
        $context->recordException(new \RuntimeException('hidden'));
        $context->validationFailed = ['otp'];
        $context->recordAuthEvent('login_failed');
        $context->recordGate('block', 'shadow', 'portal-otp-burst', false);

        $event = $this->factory->build(
            Request::create('/', 'GET'), new Response('ok'), $context
        );

        $this->assertSame(['otp'], $event['validation_failed']);
        $this->assertSame('RuntimeException', $event['exception']);
        $this->assertSame('login_failed', $event['auth_event']);
        $this->assertSame(
            ['action' => 'block', 'mode' => 'shadow', 'rule' => 'portal-otp-burst', 'applied' => false],
            $event['gate']
        );
        $this->assertSame('html', $event['resp_shape']);
    }

    public function test_route_falls_back_to_request_then_unrouted(): void
    {
        $request = Request::create('/venues/7', 'GET');
        $route = new Route(['GET'], 'venues/{venue}', ['as' => 'venues.show', 'uses' => fn () => null]);
        $route->bind($request);
        $request->setRouteResolver(fn () => $route);

        $event = $this->factory->build($request, new Response('ok'), $this->begun());

        $this->assertSame('venues.show', $event['route']);
        $this->assertSame(
            [['param' => 'venue', 'id_hash' => $this->hasher->idHash('7')]],
            $event['bound']
        );

        $event = $this->factory->build(Request::create('/nope', 'GET'), new Response('x', 404), $this->begun());

        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame([], $event['bound']);
    }

    public function test_bound_models_carry_basename_and_hashed_key(): void
    {
        $request = Request::create('/venues/42', 'GET');
        $route = new Route(['GET'], 'venues/{venue}', fn () => null);
        $route->bind($request);
        $request->setRouteResolver(fn () => $route);

        $property = new \ReflectionProperty(Route::class, 'parameters');
        $property->setValue($route, ['venue' => new FakeVenue(42)]);

        $event = $this->factory->build($request, new Response('ok'), $this->begun());

        $this->assertSame(
            [['model' => 'FakeVenue', 'id_hash' => $this->hasher->idHash('42')]],
            $event['bound']
        );
    }

    public function test_started_session_produces_distinct_session_key(): void
    {
        $store = new Store('array', new ArraySessionHandler(60));
        $store->start();

        $request = Request::create('/', 'GET', [], [], [], ['HTTP_USER_AGENT' => 'A']);
        $request->setLaravelSession($store);

        $event = $this->factory->build($request, new Response('ok'), $this->begun());

        $this->assertSame($this->hasher->sessionKey($store->getId()), $event['session_key']);
        $this->assertNotSame($event['session_key'], $event['peer_key']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $event['session_key']);
    }

    public function test_empty_session_id_falls_back_to_peer_key(): void
    {
        $session = $this->createStub(LaravelSession::class);
        $session->method('getId')->willReturn('');

        $request = Request::create('/', 'GET', [], [], [], ['HTTP_USER_AGENT' => 'A']);
        $request->setLaravelSession($session);

        $event = $this->factory->build($request, new Response('ok'), $this->begun());

        $this->assertSame($event['peer_key'], $event['session_key']);
    }

    public function test_principal_hashes_resolved_user_only(): void
    {
        $request = Request::create('/', 'GET');
        $this->assertSame('anon', $this->factory->build($request, new Response('ok'), $this->begun())['principal']);

        $this->app['auth']->guard('web')->setUser(new GenericUser(['id' => 7]));

        $event = $this->factory->build($request, new Response('ok'), $this->begun());
        $this->assertSame($this->hasher->principal('7'), $event['principal']);

        $other = new TurnEventFactory(
            $this->hasher, new ShapeReducer, $this->app['auth'], $this->stats, ['guards' => ['missing-guard']]
        );
        $this->assertSame('anon', $other->build($request, new Response('ok'), $this->begun())['principal']);
    }

    public function test_sampled_out_returns_null_without_consuming_drops(): void
    {
        $factory = new TurnEventFactory(
            $this->hasher, new ShapeReducer, $this->app['auth'], $this->stats, ['sample_rate' => 0.0]
        );

        $this->stats->dropped();

        $this->assertNull($factory->build(Request::create('/', 'GET'), new Response('ok'), $this->begun()));
        $this->assertSame(1, $this->stats->pending());
    }

    public function test_dropped_count_is_carried_without_reset(): void
    {
        $this->stats->dropped();
        $this->stats->dropped();

        $event = $this->factory->build(Request::create('/', 'GET'), new Response('ok'), $this->begun());
        $this->assertSame(2, $event['dropped_since_last']);
        $this->assertSame(2, $this->stats->pending());

        $this->stats->acknowledge(2);
        $this->assertSame(0, $this->stats->pending());

        $event = $this->factory->build(Request::create('/', 'GET'), new Response('ok'), $this->begun());
        $this->assertSame(0, $event['dropped_since_last']);

        $this->stats->acknowledge(5);
        $this->assertSame(0, $this->stats->pending());
    }

    /** @return array<string, array{callable, string}> */
    public static function responseShapes(): array
    {
        return [
            'redirect' => [fn () => new RedirectResponse('/target'), 'redirect'],
            'location header' => [fn () => new Response('', 301, ['Location' => '/moved']), 'redirect'],
            'file' => [fn () => new BinaryFileResponse(__FILE__), 'file'],
            'stream' => [fn () => new StreamedResponse(fn () => print('x')), 'stream'],
            'empty' => [fn () => new Response(''), 'empty'],
            'not modified' => [fn () => new Response('', 304), 'empty'],
            'html' => [fn () => new Response('<h1>hi</h1>', 200, ['Content-Type' => 'text/html']), 'html'],
            'implicit html' => [fn () => new Response('<h1>hi</h1>'), 'html'],
            'text' => [fn () => new Response('hello', 200, ['Content-Type' => 'text/plain']), 'text'],
            'pdf' => [fn () => new Response('%pdf', 200, ['Content-Type' => 'application/pdf']), 'application/pdf'],
            'json' => [fn () => new JsonResponse(['a' => 1]), '{a:int}'],
            'json content type' => [
                fn () => new Response('{"a":1}', 200, ['Content-Type' => 'application/problem+json']),
                '{a:int}',
            ],
            'broken json' => [
                fn () => new Response('{oops', 200, ['Content-Type' => 'application/json']),
                'application/json',
            ],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('responseShapes')]
    public function test_response_shapes(callable $make, string $expected): void
    {
        $event = $this->factory->build(Request::create('/', 'GET'), $make(), $this->begun());

        $this->assertSame($expected, $event['resp_shape']);
    }

    public function test_oversized_json_body_is_not_shaped(): void
    {
        $event = $this->factory->build(
            Request::create('/', 'GET'),
            new JsonResponse(['blob' => str_repeat('x', 70000)]),
            $this->begun()
        );

        $this->assertSame('application/json', $event['resp_shape']);
    }

    public function test_bytes_out_covers_streams_and_files(): void
    {
        $stream = $this->factory->build(
            Request::create('/', 'GET'), new StreamedResponse(fn () => print('x')), $this->begun()
        );
        $this->assertSame(-1, $stream['bytes_out']);

        $file = new BinaryFileResponse(__FILE__);
        $file->headers->set('Content-Length', (string) filesize(__FILE__));
        $download = $this->factory->build(Request::create('/', 'GET'), $file, $this->begun());
        $this->assertSame(filesize(__FILE__), $download['bytes_out']);
    }

    public function test_probe_carries_exactly_the_check_fields(): void
    {
        $request = Request::create(
            '/portal/login', 'POST', [], [], [],
            ['HTTP_USER_AGENT' => 'Probe/1.0', 'REMOTE_ADDR' => '10.1.2.3']
        );
        $context = $this->begun();
        $context->recordRoute('portal.login');

        $probe = $this->factory->probe($request, $context);

        $this->assertSame(
            ['v', 'ts', 'turn_id', 'verb', 'route', 'surface', 'session_key', 'peer_key', 'principal', 'credential_hash', 'credential_status', 'tag_id'],
            array_keys($probe)
        );
        $this->assertSame(2, $probe['v']);
        $this->assertSame($context->tsUs, $probe['ts']);
        $this->assertSame('POST', $probe['verb']);
        $this->assertSame('portal.login', $probe['route']);
        $this->assertSame($this->hasher->peerKey('10.1.2.3', 'Probe/1.0'), $probe['peer_key']);
        $this->assertSame($probe['peer_key'], $probe['session_key']);
        $this->assertSame('anon', $probe['principal']);

        $event = $this->factory->build($request, new Response('ok'), $context);
        foreach (['v', 'ts', 'turn_id', 'verb', 'route', 'surface', 'session_key', 'peer_key', 'principal', 'credential_hash', 'credential_status', 'tag_id'] as $key) {
            $this->assertSame($probe[$key], $event[$key], "event[$key] matches probe[$key]");
        }
    }

    public function test_route_name_helper_matches_factory_fallback(): void
    {
        $this->assertSame('_unrouted', RouteName::fromRoute(Request::create('/x', 'GET')->route()));
    }

    public function test_routed_200_carries_no_capture(): void
    {
        $request = Request::create('/venues/7?token=abc&page=2', 'GET');
        $route = new Route(['GET'], 'venues/{venue}', ['as' => 'venues.show', 'uses' => fn () => null]);
        $route->bind($request);
        $request->setRouteResolver(fn () => $route);

        $event = $this->factory->build($request, new Response('ok', 200), $this->begun());

        $this->assertSame('venues.show', $event['route']);
        $this->assertNull($event['path']);
        $this->assertNull($event['sample_query']);
        $this->assertNull($event['body_slice']);
    }

    public function test_unrouted_404_carries_all_three_redacted(): void
    {
        $request = Request::create(
            '/wp-login.php?token=S3CR3T-token-value&page=2', 'POST',
            [], [], [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            'user=admin&otp=654321'
        );

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame('_unrouted', $event['route']);
        $this->assertSame('/wp-login.php', $event['path']);
        $this->assertSame('token=%5Bredacted%5D&page=2', $event['sample_query']);
        $this->assertSame('user=admin&otp=%5Bredacted%5D', $event['body_slice']);
    }

    public function test_unrouted_path_scrubs_both_personal_shapes(): void
    {
        $request = Request::create('/u/john@example.com/4111111111111111', 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame('/u/[redacted]/[redacted]', $event['path']);
    }

    public function test_unrouted_path_truncates_to_512(): void
    {
        $request = Request::create('/'.str_repeat('d', 2047), 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame(512, strlen($event['path']));
    }

    public function test_redacted_values_never_appear_in_any_form(): void
    {
        $request = Request::create(
            '/.env?password=hunter2-hunter2&x=1', 'POST',
            [], [], [],
            ['CONTENT_TYPE' => 'application/json'],
            '{"user":{"otp":"112233"},"token":"tok-tok-token","ok":true}'
        );

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $json = (string) json_encode($event);
        foreach (['hunter2-hunter2', '112233', 'tok-tok-token'] as $secret) {
            $this->assertStringNotContainsString($secret, $json, "leaked: {$secret}");
        }
        // ... but the evidence kept its shape: redacted markers, plain fields.
        $this->assertStringContainsString('password=%5Bredacted%5D', $event['sample_query']);
        $this->assertSame(
            '{"user":{"otp":"[redacted]"},"token":"[redacted]","ok":true}',
            $event['body_slice']
        );
    }

    public function test_routed_4xx_captures_samples_without_path(): void
    {
        $request = Request::create(
            '/portal/login?next=%2F', 'POST', [], [], [],
            ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            'phone=123&otp=12'
        );
        $context = $this->begun();
        $context->recordRoute('portal.login');

        $event = $this->factory->build($request, new Response('x', 422), $context);

        $this->assertNull($event['path']);
        $this->assertSame('next=%2F', $event['sample_query']);
        $this->assertSame('phone=%5Bredacted%5D&otp=%5Bredacted%5D', $event['body_slice']);
    }

    public function test_capture_truncates_values_total_and_body(): void
    {
        $long = str_repeat('a', 100);
        $request = Request::create("/x?v={$long}", 'GET');
        $event = $this->factory->build($request, new Response('x', 404), $this->begun());
        $this->assertSame('v='.str_repeat('a', 64), $event['sample_query']);

        $many = implode('&', array_map(fn ($i) => "p{$i}=".str_repeat('b', 60), range(0, 20)));
        $request = Request::create("/x?{$many}", 'GET');
        $event = $this->factory->build($request, new Response('x', 404), $this->begun());
        $this->assertSame(512, strlen($event['sample_query']));

        $request = Request::create('/x', 'POST', [], [], [], [], str_repeat('c', 3000));
        $event = $this->factory->build($request, new Response('x', 404), $this->begun());
        $this->assertSame(2048, strlen($event['body_slice']));
    }

    public function test_redact_list_is_configurable(): void
    {
        config(['leeside.capture.redact_params' => ['phone']]);
        $factory = new TurnEventFactory(
            $this->hasher, new ShapeReducer, $this->app['auth'], $this->stats,
            [], null, null, $this->app['config']
        );
        $request = Request::create(
            '/x?phone=0661111111&otp=123456', 'GET'
        );

        $event = $factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame('phone=%5Bredacted%5D&otp=123456', $event['sample_query']);
    }

    public function test_redact_names_match_case_insensitively(): void
    {
        $request = Request::create('/x?Token=abc&OTP=123', 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame('Token=%5Bredacted%5D&OTP=%5Bredacted%5D', $event['sample_query']);
    }

    public function test_personal_names_redact_by_default(): void
    {
        $request = Request::create('/x?email=a%40b.com&phone=0661111111&name=Jo&address=Main+1', 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame(
            'email=%5Bredacted%5D&phone=%5Bredacted%5D&name=%5Bredacted%5D&address=%5Bredacted%5D',
            $event['sample_query']
        );
    }

    public function test_email_and_digit_runs_redact_regardless_of_name(): void
    {
        $request = Request::create('/x?q=ops%40example.com&id=4111111111111111&short=123456789012', 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame(
            'q=%5Bredacted%5D&id=%5Bredacted%5D&short=123456789012',
            $event['sample_query']
        );
    }

    public function test_thirteen_digit_runs_redact(): void
    {
        // A millisecond timestamp is 13 digits: the card range takes it too.
        $request = Request::create('/x?ts=1761600000123', 'GET');

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame('ts=%5Bredacted%5D', $event['sample_query']);
    }

    public function test_unnamed_json_values_redact_by_shape(): void
    {
        $request = Request::create(
            '/x', 'POST', [], [], [],
            ['CONTENT_TYPE' => 'application/json'],
            '{"ids":["4111111111111111","ok"],"mail":"a@b.co"}'
        );

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame(
            '{"ids":["[redacted]","ok"],"mail":"[redacted]"}',
            $event['body_slice']
        );
    }

    public function test_opaque_bodies_scrub_shapes_not_names(): void
    {
        $request = Request::create(
            '/x', 'POST', [], [], [],
            ['CONTENT_TYPE' => 'text/plain'],
            'call me at jane@example.com or 4111111111111111 tomorrow'
        );

        $event = $this->factory->build($request, new Response('x', 404), $this->begun());

        $this->assertSame(
            'call me at [redacted] or [redacted] tomorrow',
            $event['body_slice']
        );
    }

    private function begun(): TurnContext
    {
        $context = new TurnContext;
        $context->begin();

        return $context;
    }
}

class FakeVenue implements UrlRoutable
{
    public function __construct(private readonly int $id) {}

    public function getRouteKey()
    {
        return $this->id;
    }

    public function getRouteKeyName()
    {
        return 'id';
    }

    public function resolveRouteBinding($value, $field = null)
    {
        return new self((int) $value);
    }

    public function resolveChildRouteBinding($childType, $value, $field = null)
    {
        return new self((int) $value);
    }
}
