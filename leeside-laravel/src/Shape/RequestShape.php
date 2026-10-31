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
    /** How header order arrives on this host, from deploy/header-order-check.sh. */
    public const ORDER_RECEIVED = 'received';
    public const ORDER_REVERSED = 'reversed';
    public const ORDER_UNKNOWN = 'unknown';

    /** What the header-names hash was taken over. */
    public const RECIPE_RECEIVED = 'received';
    public const RECIPE_SORTED = 'sorted';

    /** Headers nginx adds on the way in; they are not the client's. */
    private const PROXY_ADDED = [
        'x-forwarded-for', 'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-prefix',
        'x-real-ip', 'x-leeside-ja4', 'x-leeside-ja4t', 'x-leeside-h2',
    ];

    /**
     * `$order` is the host's transform: `received` and `reversed` are both
     * recoverable, so the names are canonicalised to received order and
     * hashed; only `unknown` falls back to sorted names.
     *
     * @return array{shape_hash: string, shape: array<string, mixed>}
     */
    public static function build(Request $request, Hasher $hasher, string $order = self::ORDER_UNKNOWN): array
    {
        $names = self::canonicalHeaderNames($request, $order);
        $orderReliable = $order === self::ORDER_RECEIVED || $order === self::ORDER_REVERSED;
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
            'order_recipe' => $orderReliable ? self::RECIPE_RECEIVED : self::RECIPE_SORTED,
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
     * Header names in the order the client sent them, as far as this host
     * lets us know: `reversed` undoes php-fpm's prepend into $_SERVER,
     * `received` is already right, `unknown` sorts.
     *
     * @return string[]
     */
    public static function canonicalHeaderNames(Request $request, string $order): array
    {
        $names = self::headerNames($request);

        return match ($order) {
            self::ORDER_RECEIVED => $names,
            self::ORDER_REVERSED => array_reverse($names),
            default => self::sorted($names),
        };
    }

    private static function sorted(array $names): array
    {
        sort($names);

        return $names;
    }

    /**
     * Lowercased client header names in the order PHP exposed them. Symfony
     * builds the bag from $_SERVER in its order; whether that is the client's
     * order is what leeside-sample/deploy/header-order-check.sh measures.
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
