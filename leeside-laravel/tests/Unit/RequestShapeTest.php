<?php

namespace Leeside\Laravel\Tests\Unit;

use Illuminate\Http\Request;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Shape\RequestShape;
use PHPUnit\Framework\TestCase;

class RequestShapeTest extends TestCase
{
    private Hasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();
        $this->hasher = new Hasher('test-key');
        $_COOKIE = [];
    }

    protected function tearDown(): void
    {
        $_COOKIE = [];
        parent::tearDown();
    }

    private function request(array $headers, string $method = 'GET', array $cookies = []): Request
    {
        $server = ['SERVER_PROTOCOL' => 'HTTP/1.1'];
        foreach ($headers as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        $request = Request::create('/page', $method, [], $cookies, [], $server);
        foreach (['Accept', 'Accept-Language', 'Accept-Charset', 'User-Agent'] as $default) {
            if (! array_key_exists($default, $headers)) {
                $request->headers->remove($default);
            }
        }

        return $request;
    }

    /** A request whose $_SERVER has exactly these headers in exactly this order. */
    private function rawRequest(array $names): Request
    {
        $server = ['SERVER_PROTOCOL' => 'HTTP/1.1', 'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/page'];
        foreach ($names as $name) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = 'x';
        }

        return new Request([], [], [], [], [], $server);
    }

    public function test_components_and_composite(): void
    {
        $request = $this->request([
            'Host' => 'example.test',
            'User-Agent' => 'curl/8.5.0',
            'Accept' => '*/*',
            'Accept-Language' => 'fr-CH, fr;q=0.9, en;q=0.8',
            'Referer' => 'https://example.test/',
            'X-Forwarded-For' => '203.0.113.1',
            'X-Real-IP' => '203.0.113.1',
        ], 'POST', ['b' => '1', 'a' => '2']);

        $built = RequestShape::build($request, $this->hasher, RequestShape::ORDER_RECEIVED);
        $shape = $built['shape'];

        $this->assertSame('POST', $shape['method']);
        $this->assertSame('HTTP/1.1', $shape['http_version']);
        $this->assertTrue($shape['has_cookie']);
        $this->assertTrue($shape['has_referer']);
        // host, user-agent, accept, accept-language, referer, plus the content-type a POST carries;
        // the two nginx-added headers are not counted.
        $this->assertSame(6, $shape['header_count']);
        $this->assertSame('fr-c', $shape['accept_language']);
        $this->assertTrue($shape['order_reliable']);
        $this->assertSame('received', $shape['order_recipe']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $shape['header_names_hash']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $shape['cookie_names_hash']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $built['shape_hash']);

        $names = RequestShape::headerNames($request);
        $this->assertSame(['host', 'user-agent', 'accept', 'accept-language', 'referer', 'content-type'], $names);
        $this->assertSame(['a', 'b'], RequestShape::cookieNames($request), 'cookie names sorted');
        $this->assertSame($this->hasher->shapeHash('a,b'), $shape['cookie_names_hash']);

        foreach (['203.0.113.1', 'example.test', 'curl', 'https://example.test/'] as $value) {
            $this->assertStringNotContainsString($value, json_encode($built), 'names and hashes only');
        }
    }

    public function test_order_matters_when_known_and_not_when_unknown(): void
    {
        $a = $this->request(['X-Alpha' => '1', 'X-Zeta' => '2', 'Accept' => 'text/html']);
        $b = $this->request(['X-Zeta' => '2', 'X-Alpha' => '1', 'Accept' => 'text/html']);

        $this->assertNotSame(
            RequestShape::build($a, $this->hasher, RequestShape::ORDER_RECEIVED)['shape_hash'],
            RequestShape::build($b, $this->hasher, RequestShape::ORDER_RECEIVED)['shape_hash']
        );
        $unknown = RequestShape::build($a, $this->hasher)['shape'];
        $this->assertSame(
            $unknown['header_names_hash'],
            RequestShape::build($b, $this->hasher, RequestShape::ORDER_UNKNOWN)['shape']['header_names_hash'],
            'unknown: names are hashed sorted'
        );
        $this->assertFalse($unknown['order_reliable']);
        $this->assertSame('sorted', $unknown['order_recipe']);
        $this->assertSame($this->hasher->shapeHash('accept,host,x-alpha,x-zeta'), $unknown['header_names_hash']);
    }

    public function test_reversed_arrival_canonicalises_to_the_received_hash(): void
    {
        // What the client sent, in order, and what php-fpm would hand us (reversed).
        foreach ([
            ['Host', 'X-Zeta', 'X-Alpha', 'X-Mid', 'Accept-Language', 'X-Omega'],
            ['Host', 'X-Omega', 'X-Mid', 'X-Zeta', 'Accept-Language', 'X-Alpha'],
            ['Host', 'Accept-Language', 'X-Alpha', 'X-Omega', 'X-Zeta', 'X-Mid'],
        ] as $sent) {
            // Built without Request::create's defaults, so the whole order,
            // Host included, is under the test's control.
            $received = $this->rawRequest($sent);
            $arrived = $this->rawRequest(array_reverse($sent));

            $want = RequestShape::build($received, $this->hasher, RequestShape::ORDER_RECEIVED)['shape'];
            $got = RequestShape::build($arrived, $this->hasher, RequestShape::ORDER_REVERSED)['shape'];
            $this->assertSame($want['header_names_hash'], $got['header_names_hash'], implode(',', $sent));
            $this->assertTrue($got['order_reliable']);
            $this->assertSame('received', $got['order_recipe']);
            $this->assertNotSame($want['header_names_hash'], RequestShape::build($arrived, $this->hasher, RequestShape::ORDER_RECEIVED)['shape']['header_names_hash'], 'without the transform the hash differs');
        }
    }

    public function test_accept_language_and_empty_cases(): void
    {
        $this->assertSame('0000', RequestShape::acceptLanguage($this->request([])));
        $this->assertSame('en', RequestShape::acceptLanguage($this->request(['Accept-Language' => 'EN'])));
        $this->assertSame('en-u', RequestShape::acceptLanguage($this->request(['Accept-Language' => 'en-US,en;q=0.5'])));
        $this->assertSame('de', RequestShape::acceptLanguage($this->request(['Accept-Language' => ' de ; q=1'])));

        $bare = RequestShape::build($this->request([]), $this->hasher, true);
        $this->assertFalse($bare['shape']['has_cookie']);
        $this->assertFalse($bare['shape']['has_referer']);
        $this->assertSame(1, $bare['shape']['header_count'], 'only Host');
    }

    public function test_raw_cookie_superglobal_wins_over_the_bag(): void
    {
        $_COOKIE = ['_lsd' => 'x', 'laravel_session' => 'y'];
        $request = $this->request([], 'GET', ['other' => '1']);

        $this->assertSame(['_lsd', 'laravel_session'], RequestShape::cookieNames($request));
    }
}
