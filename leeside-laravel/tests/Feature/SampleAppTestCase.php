<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\GenericUser;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Session\TokenMismatchException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Schema;
use Leeside\Laravel\Check\ArrayRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Tests\TestCase;
use Leeside\Laravel\Transport\ArrayTransport;
use Leeside\Laravel\Transport\Transport;
use RuntimeException;

abstract class SampleAppTestCase extends TestCase
{
    protected ArrayTransport $transport;
    protected ArrayRuleClient $rules;

    protected function defineEnvironment($app): void
    {
        $app['config']->set('session.driver', 'array');
        $app['config']->set('database.default', 'sqlite');
        $app['config']->set('database.connections.sqlite.database', ':memory:');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('t', 32)));
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->withoutMiddleware(PreventRequestForgery::class);

        $this->transport = new ArrayTransport;
        $this->rules = new ArrayRuleClient;
        $this->app->instance(Transport::class, $this->transport);
        $this->app->instance(RuleClient::class, $this->rules);

        Schema::create('test_venues', function (Blueprint $table) {
            $table->increments('id');
            $table->string('name');
            $table->string('city');
        });
        TestVenue::insert([
            ['name' => 'ZZZ-Alpine-Lodge', 'city' => 'Innsbruck'],
            ['name' => 'Harbor Inn', 'city' => 'Bergen'],
            ['name' => 'Desert Rose', 'city' => 'Marrakech'],
        ]);

        $this->defineSampleRoutes();
    }

    protected function defineSampleRoutes(): void
    {
        $router = $this->app['router'];

        $router->get('/', fn () => new Response('<h1>home</h1>', 200, ['Content-Type' => 'text/html']))
            ->name('home');

        $router->post('/portal/login', function (Request $request) {
            $data = $request->validate(['phone' => 'required|digits:10', 'otp' => 'required|digits:6']);

            if ($data['otp'] === '123456') {
                Auth::guard('web')->login(new GenericUser(['id' => 7]));

                return new JsonResponse(['ok' => true]);
            }

            event(new Failed('web', new GenericUser(['id' => 7]), ['phone' => $data['phone']]));

            return new JsonResponse(['ok' => false], 401);
        })->middleware('web')->name('portal.login');

        $router->get('/venues/{venue}', fn (TestVenue $venue) => new JsonResponse(['name' => $venue->name]))
            ->middleware('web')->name('venues.show');

        $router->get('/api/venues', fn () => new JsonResponse(TestVenue::query()->pluck('name')))
            ->middleware('api')->name('api.venues.index');

        $router->post('/api/venues/{venue}/visit', function (Request $request, TestVenue $venue) {
            $data = $request->validate(['guests' => 'required|integer']);

            return new JsonResponse(['venue' => $venue->id, 'guests' => $data['guests']]);
        })->middleware('api')->name('api.venues.visit');

        $router->get('/secret', fn () => abort(403))->middleware('web')->name('secret');

        $router->get('/boom', function () {
            throw new RuntimeException('ZZZ-boom-secret');
        })->middleware('web')->name('boom');

        $router->get('/deny', function () {
            throw new AuthorizationException('ZZZ-deny-secret');
        })->middleware('web')->name('deny');

        $router->get('/csrf-throw', function () {
            throw new TokenMismatchException('ZZZ-csrf-secret');
        })->middleware('web')->name('csrf.throw');

        $router->get('/challenge-demo', fn (Request $request) => new JsonResponse(
            ['challenge' => $request->attributes->get('leeside.challenge')]
        ))->middleware('web')->name('challenge.demo');

        $router->get('/up', fn () => new Response('ok'))->middleware('web')->name('up');
        $router->get('/livewire/update', fn () => new Response('ok'))->middleware('web');
        $router->get('/plain', fn () => new Response('ok'));
    }

    protected function hasher(): Hasher
    {
        return $this->app[Hasher::class];
    }

    /** @return array<string, mixed> */
    protected function lastEvent(): array
    {
        $events = $this->transport->events;
        $this->assertNotEmpty($events, 'no events captured');

        return end($events);
    }

    protected function eventsJson(): string
    {
        return (string) json_encode($this->transport->events);
    }
}

class TestVenue extends Model
{
    protected $table = 'test_venues';
    protected $guarded = [];
    public $timestamps = false;
}
