<?php

namespace Leeside\Laravel\Tests\Unit;

use Illuminate\Routing\Route;
use Leeside\Laravel\Event\RouteName;
use PHPUnit\Framework\TestCase;

class RouteNameTest extends TestCase
{
    public function test_prefers_route_name(): void
    {
        $route = new Route(['GET'], 'venues/{venue}', ['as' => 'venues.show', 'uses' => fn () => null]);

        $this->assertSame('venues.show', RouteName::fromRoute($route));
    }

    public function test_falls_back_to_uri_pattern(): void
    {
        $route = new Route(['GET'], 'venues/{venue}', fn () => null);

        $this->assertSame('venues/{venue}', RouteName::fromRoute($route));
    }

    public function test_unrouted(): void
    {
        $this->assertSame('_unrouted', RouteName::fromRoute(null));
    }

    public function test_ignore_matches_names_and_uri_patterns(): void
    {
        $named = new Route(['GET'], 'telescope/entries', ['as' => 'telescope.index', 'uses' => fn () => null]);
        $unnamed = new Route(['GET'], 'livewire/update', fn () => null);
        $plain = new Route(['GET'], 'portal/login', ['as' => 'portal.login', 'uses' => fn () => null]);

        $this->assertTrue(RouteName::isIgnored($named, ['up', 'telescope*']));
        $this->assertTrue(RouteName::isIgnored($unnamed, ['livewire*']));
        $this->assertTrue(RouteName::isIgnored($plain, ['portal/*']));
        $this->assertFalse(RouteName::isIgnored($plain, ['up', 'telescope*']));
        $this->assertFalse(RouteName::isIgnored(null, ['*']));
        $this->assertFalse(RouteName::isIgnored($plain, []));
    }
}
