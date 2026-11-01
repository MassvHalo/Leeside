<?php

namespace Leeside\Laravel;

use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Registered;
use Illuminate\Auth\Events\Verified;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Events\RouteMatched;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\ServiceProvider;
use Leeside\Laravel\Check\NullRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Check\UnixRuleClient;
use Leeside\Laravel\Console\TapCommand;
use Leeside\Laravel\Event\RouteName;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Event\TurnEventFactory;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Middleware\CaptureTurn;
use Leeside\Laravel\Middleware\GateTurn;
use Leeside\Laravel\Middleware\RequireWebhookSigner;
use Leeside\Laravel\Middleware\TagTurn;
use Leeside\Laravel\Reduce\ShapeReducer;
use Leeside\Laravel\Surface\CredentialVerifier;
use Leeside\Laravel\Surface\SurfaceClassifier;
use Leeside\Laravel\Tag\TagCookie;
use Leeside\Laravel\Transport\LogTransport;
use Leeside\Laravel\Transport\NullTransport;
use Leeside\Laravel\Transport\Transport;
use Leeside\Laravel\Transport\UnixDatagramTransport;
use Throwable;

class LeesideServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/leeside.php', 'leeside');

        $this->app->singleton(Stats::class);
        $this->app->scoped(TurnContext::class);

        $this->app->singleton(Hasher::class, fn ($app) => Hasher::fromConfig(
            $this->stringOrNull($app['config']->get('leeside.hash_key')),
            (string) $app['config']->get('app.key', '')
        ));

        $this->app->singleton(ShapeReducer::class, fn ($app) => new ShapeReducer(
            (array) $app['config']->get('leeside.shape', [])
        ));

        $this->app->singleton(SurfaceClassifier::class, fn ($app) => new SurfaceClassifier($app['config']));

        $this->app->singleton(TagCookie::class, fn ($app) => TagCookie::fromConfig(
            $this->stringOrNull($app['config']->get('leeside.tag.secret')),
            (string) $app['config']->get('app.key', ''),
            $this->stringOrNull($app['config']->get('leeside.tag.cookie'))
        ));

        $this->app->singleton(TurnEventFactory::class, fn ($app) => new TurnEventFactory(
            $app[Hasher::class],
            $app[ShapeReducer::class],
            $app['auth'],
            $app[Stats::class],
            [
                'sample_rate' => (float) $app['config']->get('leeside.sample_rate', 1.0),
                'guards' => array_keys((array) $app['config']->get('auth.guards', ['web' => []])),
                'max_response_bytes' => (int) $app['config']->get('leeside.shape.max_response_bytes', 65536),
                'session_cookie' => (string) $app['config']->get('session.cookie', 'laravel_session'),
                'tag_cookie' => (string) ($app['config']->get('leeside.tag.cookie') ?: '_lsd'),
            ],
            $app[SurfaceClassifier::class],
            $app->bound(CredentialVerifier::class) ? $app[CredentialVerifier::class] : null,
            $app['config']
        ));

        $this->app->singleton(Transport::class, function ($app) {
            $config = $app['config'];

            return match ($config->get('leeside.transport', 'udg')) {
                'log' => new LogTransport($app['log'], $this->stringOrNull($config->get('leeside.log_channel'))),
                'null' => new NullTransport,
                default => new UnixDatagramTransport(
                    $this->socketPath((string) $config->get('leeside.events_socket', '/run/leeside/events.sock'))
                ),
            };
        });

        $this->app->singleton(RuleClient::class, function ($app) {
            $config = $app['config'];

            if (! $config->get('leeside.check.enabled', true)) {
                return new NullRuleClient;
            }

            return new UnixRuleClient(
                $this->socketPath((string) $config->get('leeside.check.socket', '/run/leeside/check.sock')),
                (int) $config->get('leeside.check.timeout_ms', 2)
            );
        });
    }

    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/leeside.php' => config_path('leeside.php'),
        ], 'leeside-config');

        $this->commands([TapCommand::class]);

        $this->registerExceptionHook();
        $this->registerAuthListeners();
        $this->registerRouteListener();

        if ($this->app['config']->get('leeside.register_middleware', true)) {
            $this->registerMiddleware();
        }
    }

    private function registerExceptionHook(): void
    {
        $handler = $this->app[ExceptionHandler::class];

        if (! method_exists($handler, 'renderable')) {
            return;
        }

        $handler->renderable(function (Throwable $exception) {
            try {
                $this->app[TurnContext::class]->recordException($exception);
            } catch (Throwable) {
                // Recording must never break rendering.
            }

            return null;
        });
    }

    private function registerAuthListeners(): void
    {
        $events = $this->app['events'];

        foreach ([
            Login::class => 'login',
            Failed::class => 'login_failed',
            Logout::class => 'logout',
            Registered::class => 'registered',
            PasswordReset::class => 'password_reset',
            Lockout::class => 'lockout',
            Verified::class => 'verified',
        ] as $event => $name) {
            $events->listen($event, function () use ($name) {
                try {
                    $this->app[TurnContext::class]->recordAuthEvent($name);
                } catch (Throwable) {
                    // Recording must never break auth.
                }
            });
        }
    }

    private function registerRouteListener(): void
    {
        $this->app['events']->listen(RouteMatched::class, function (RouteMatched $event) {
            try {
                $this->app[TurnContext::class]->recordRoute(RouteName::fromRoute($event->route));
            } catch (Throwable) {
                // Recording must never break routing.
            }
        });
    }

    private function registerMiddleware(): void
    {
        $router = $this->app['router'];
        $groups = (array) $this->app['config']->get('leeside.gate_groups', ['web', 'api']);

        $pushGate = function () use ($router, $groups) {
            // The tag lives on the web surface only; pushed before the gate so
            // the host's EncryptCookies (outer) still sees the Set-Cookie on the
            // way out, excepted or not.
            $router->pushMiddlewareToGroup('web', TagTurn::class);
            foreach ($groups as $group) {
                $router->pushMiddlewareToGroup($group, GateTurn::class);
            }
            // The app's webhook verifier never aborts; the 401 comes after the
            // gate, so a forgery is probed and recorded as rejected.
            if (in_array('webhook', $groups, true)) {
                $router->pushMiddlewareToGroup('webhook', RequireWebhookSigner::class);
            }
        };

        $onKernel = function ($kernel) use ($pushGate) {
            $kernel->pushMiddleware(CaptureTurn::class);

            if (method_exists($kernel, 'addToMiddlewarePriorityBefore')) {
                // The gate probes ahead of SubstituteBindings so a binding
                // failure (an enumeration 404) is still gated; the tag reads
                // ahead of the gate so the probe carries a valid tag_id. Both
                // stay after Authenticate and StartSession, which sort before
                // SubstituteBindings in the default priority list.
                $kernel->addToMiddlewarePriorityBefore(SubstituteBindings::class, GateTurn::class);
                $kernel->addToMiddlewarePriorityBefore(GateTurn::class, TagTurn::class);
            }

            // Kernel mutators re-sync (overwrite) the router groups, so the
            // gate is re-applied after every sync.
            $pushGate();
        };

        if ($this->app->resolved(Kernel::class)) {
            $onKernel($this->app[Kernel::class]);
        } else {
            $this->app->afterResolving(Kernel::class, $onKernel);
        }

        $pushGate();
    }

    private function socketPath(string $path): string
    {
        if ($path === '' || str_starts_with($path, '/')) {
            return $path;
        }

        return $this->app->basePath($path);
    }

    private function stringOrNull(mixed $value): ?string
    {
        if ($value === null || $value === '') {
            return null;
        }

        return (string) $value;
    }
}
