<?php

namespace Leeside\Laravel\Shape;

use Illuminate\Http\Request;
use Leeside\Laravel\Hash\Hasher;

/**
 * A JA4H-style fingerprint of how the request was formed: method, HTTP
 * version, which headers in which order, which cookie names. Names only,
 * never values, so it says what kind of client sent it and nothing about
 * whom. The components ride along so leesided can re-derive with another
 * recipe.
 */
final class RequestShape
{
    /** Headers nginx adds on the way in; they are not the client's. */
    private const PROXY_ADDED = [
        'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-prefix',
        'x-real-ip', 'x-leeside-ja4', 'x-leeside-ja4t', 'x-leeside-h2',
    ];

    /**
     * @return array{shape_hash: string, shape: array<string, mixed>}
     */
    public static function build(Request $request, Hasher $hasher, bool $orderReliable): array
    {
        $names = self::headerNames($request);
        if (! $orderReliable) {
            sort($names);
        }
        $cookies = self::cookieNames($request);

        $shape = [
            'method' => $request->getMethod(),
            'http_version' => (string) $request->server->get('SERVER_PROTOCOL', ''),
            'has_cookie' => $cookies !== [],
            'has_referer' => $request->headers->has('Referer'),
            'header_count' => count($names),
            'accept_language' => self::acceptLanguage($request),
            'header_names_hash' => $hasher->shapeHash(implode(',', $names)),
            'cookie_names_hash' => $hasher->shapeHash(implode(',', $cookies)),
            'order_reliable' => $orderReliable,
        ];

        $composite = implode('_', [
            $shape['method'],
            $shape['http_version'],
            $shape['has_cookie'] ? '1' : '0',
            $shape['has_referer'] ? '1' : '0',
            (string) $shape['header_count'],
            $shape['accept_language'],
            $shape['header_names_hash'],
            $shape['cookie_names_hash'],
        ]);

        return ['shape_hash' => $hasher->shapeHash($composite), 'shape' => $shape];
    }

    /**
     * Lowercased client header names in received order. Symfony builds the
     * bag from $_SERVER in its order, which FastCGI preserves (checked by
     * leeside-sample/deploy/header-order-check.sh).
     *
     * @return string[]
     */
    public static function headerNames(Request $request): array
    {
        $names = [];
        foreach (array_keys($request->headers->all()) as $name) {
            $name = strtolower((string) $name);
            if (in_array($name, self::PROXY_ADDED, true)) {
                continue;
            }
            $names[] = $name;
        }

        return $names;
    }

    /** Sorted cookie names, from the raw superglobal when it has them. */
    public static function cookieNames(Request $request): array
    {
        $names = array_keys($_COOKIE);
        if ($names === []) {
            $names = $request->cookies->keys();
        }
        $names = array_values(array_map('strval', $names));
        sort($names);

        return $names;
    }

    /** First four characters of the primary language tag, lowercased; `0000` when absent. */
    public static function acceptLanguage(Request $request): string
    {
        $header = (string) $request->headers->get('Accept-Language', '');
        $primary = strtolower(trim(explode(';', explode(',', $header)[0])[0]));

        return $primary === '' ? '0000' : substr($primary, 0, 4);
    }
}
