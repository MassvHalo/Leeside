<?php

namespace Leeside\Laravel\Tests;

use Leeside\Laravel\LeesideServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LeesideServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        // Tests define routes after boot; an auto-registered catch-all would
        // shadow them all. FallbackTest registers it explicitly, last.
        $app['config']->set('leeside.capture.fallback', false);
    }
}
