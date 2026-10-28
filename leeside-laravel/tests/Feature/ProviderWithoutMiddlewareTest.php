<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Contracts\Http\Kernel;
use Leeside\Laravel\Middleware\CaptureTurn;
use Leeside\Laravel\Middleware\GateTurn;
use Leeside\Laravel\Tests\TestCase;
use ReflectionProperty;

class ProviderWithoutMiddlewareTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        $app['config']->set('leeside.register_middleware', false);
    }

    public function test_nothing_is_registered(): void
    {
        $groups = $this->app['router']->getMiddlewareGroups();

        $this->assertNotContains(GateTurn::class, $groups['web'] ?? []);
        $this->assertNotContains(GateTurn::class, $groups['api'] ?? []);
        $this->assertFalse($this->app->resolved(Kernel::class));

        $kernel = $this->app[Kernel::class];

        $this->assertNotContains(
            CaptureTurn::class,
            (new ReflectionProperty($kernel, 'middleware'))->getValue($kernel)
        );
        $this->assertNotContains(
            GateTurn::class,
            (new ReflectionProperty($kernel, 'middlewarePriority'))->getValue($kernel)
        );
    }
}
