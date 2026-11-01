<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Session\Middleware\StartSession;
use Leeside\Laravel\Check\NullRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Check\UnixRuleClient;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Middleware\CaptureTurn;
use Leeside\Laravel\Middleware\GateTurn;
use Leeside\Laravel\Middleware\TagTurn;
use Leeside\Laravel\Tests\TestCase;
use Leeside\Laravel\Transport\LogTransport;
use Leeside\Laravel\Transport\NullTransport;
use Leeside\Laravel\Transport\Transport;
use Leeside\Laravel\Transport\UnixDatagramTransport;
use ReflectionProperty;

class ProviderWiringTest extends TestCase
{
    public function test_config_is_merged_with_brief_defaults(): void
    {
        $this->assertTrue($this->app['config']->get('leeside.enabled'));
        $this->assertTrue($this->app['config']->get('leeside.register_middleware'));
        $this->assertSame(['web', 'api', 'webhook'], $this->app['config']->get('leeside.gate_groups'));
        $this->assertSame(1.0, $this->app['config']->get('leeside.sample_rate'));
        $this->assertSame('udg', $this->app['config']->get('leeside.transport'));
        $this->assertSame('/run/leeside/events.sock', $this->app['config']->get('leeside.events_socket'));
        $this->assertTrue($this->app['config']->get('leeside.check.enabled'));
        $this->assertSame(2, $this->app['config']->get('leeside.check.timeout_ms'));
        $this->assertSame(
            ['up', 'telescope*', 'horizon*', '_debugbar*', 'livewire*'],
            $this->app['config']->get('leeside.ignore')
        );
    }

    public function test_transport_selection(): void
    {
        $this->assertInstanceOf(UnixDatagramTransport::class, $this->app[Transport::class]);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('transports')]
    public function test_transport_selection_from_config(string $name, string $expected): void
    {
        $this->app['config']->set('leeside.transport', $name);

        $this->assertInstanceOf($expected, $this->app[Transport::class]);
    }

    /** @return array<string, array{string, string}> */
    public static function transports(): array
    {
        return [
            'log' => ['log', LogTransport::class],
            'null' => ['null', NullTransport::class],
            'unknown falls back to udg' => ['bogus', UnixDatagramTransport::class],
        ];
    }

    public function test_rule_client_selection(): void
    {
        $this->assertInstanceOf(UnixRuleClient::class, $this->app[RuleClient::class]);

        $this->refreshApplication();
        $this->app['config']->set('leeside.check.enabled', false);

        $this->assertInstanceOf(NullRuleClient::class, $this->app[RuleClient::class]);
    }

    public function test_context_is_shared_within_a_request(): void
    {
        $this->assertSame($this->app[TurnContext::class], $this->app[TurnContext::class]);
    }

    public function test_gate_is_pushed_to_configured_groups(): void
    {
        $groups = $this->app['router']->getMiddlewareGroups();

        $this->assertContains(GateTurn::class, $groups['web']);
        $this->assertContains(GateTurn::class, $groups['api']);
    }

    public function test_kernel_registration_is_deferred_until_resolved(): void
    {
        $this->assertFalse($this->app->resolved(Kernel::class));

        $kernel = $this->app[Kernel::class];

        $this->assertContains(CaptureTurn::class, $this->kernelProperty($kernel, 'middleware'));

        $priority = $this->kernelProperty($kernel, 'middlewarePriority');
        $this->assertContains(GateTurn::class, $priority);
        $this->assertContains(TagTurn::class, $priority);
        $at = fn (string $middleware) => array_search($middleware, $priority);
        // Session, then auth, then the tag read, then the gate, all ahead of
        // SubstituteBindings, so binding failures still probe with principal,
        // session and tag present.
        $this->assertLessThan($at(GateTurn::class), $at(StartSession::class));
        $this->assertLessThan($at(GateTurn::class), $at(AuthenticatesRequests::class));
        $this->assertLessThan($at(GateTurn::class), $at(TagTurn::class));
        $this->assertLessThan($at(SubstituteBindings::class), $at(GateTurn::class));

        $groups = $this->app['router']->getMiddlewareGroups();
        $this->assertContains(GateTurn::class, $groups['web']);
    }

    public function test_relative_socket_paths_resolve_against_base_path(): void
    {
        $this->app['config']->set('leeside.events_socket', 'storage/leeside/events.sock');

        $transport = $this->app[Transport::class];
        $path = (new ReflectionProperty(UnixDatagramTransport::class, 'path'))->getValue($transport);

        $this->assertSame($this->app->basePath('storage/leeside/events.sock'), $path);
    }

    public function test_absolute_socket_paths_are_untouched(): void
    {
        $transport = $this->app[Transport::class];
        $path = (new ReflectionProperty(UnixDatagramTransport::class, 'path'))->getValue($transport);

        $this->assertSame('/run/leeside/events.sock', $path);
    }

    /** @return array<int, string> */
    private function kernelProperty(object $kernel, string $name): array
    {
        return (new ReflectionProperty($kernel, $name))->getValue($kernel);
    }
}
