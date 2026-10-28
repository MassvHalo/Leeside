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
}
