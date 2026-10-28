<?php

namespace Leeside\Laravel\Event;

use Illuminate\Routing\Route;

class RouteName
{
    public static function fromRoute(?Route $route): string
    {
        if ($route === null) {
            return '_unrouted';
        }

        $name = $route->getName();
        if (is_string($name) && $name !== '') {
            return $name;
        }

        return $route->uri();
    }

    /** @param  string[]  $patterns */
    public static function isIgnored(?Route $route, array $patterns): bool
    {
        if ($route === null || $patterns === []) {
            return false;
        }

        $candidates = [$route->uri()];
        $name = $route->getName();
        if (is_string($name) && $name !== '') {
            $candidates[] = $name;
        }

        foreach ($patterns as $pattern) {
            foreach ($candidates as $candidate) {
                if (fnmatch($pattern, $candidate)) {
                    return true;
                }
            }
        }

        return false;
    }
}
