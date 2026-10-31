<?php

namespace Leeside\Laravel\Tests\Unit;

use Illuminate\Http\Request;
use Leeside\Laravel\Shape\Flags;
use PHPUnit\Framework\TestCase;

class FlagsTest extends TestCase
{
    private const CHROME = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';

    private function request(array $headers, string $method = 'GET'): Request
    {
        $server = [];
        foreach ($headers as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        $request = Request::create('/page', $method, [], [], [], $server);
        foreach (['Accept', 'Accept-Language', 'Accept-Charset', 'User-Agent'] as $default) {
            if (! array_key_exists($default, $headers)) {
                $request->headers->remove($default);
            }
        }

        return $request;
    }

    private function flags(Request $request, string $surface, string $ua, ?string $tag = null, array $cookies = [], bool $untrusted = false): array
    {
        return Flags::compute($request, $surface, $ua, $tag, $cookies, 'laravel_session', '_lsd', $untrusted);
    }

    public function test_real_chrome_page_load_raises_nothing(): void
    {
        $request = $this->request([
            'User-Agent' => self::CHROME,
            'Sec-CH-UA' => '"Chromium";v="130"',
            'Sec-Fetch-Mode' => 'navigate',
            'Accept-Language' => 'en-GB,en;q=0.9',
            'Accept' => 'text/html,application/xhtml+xml,*/*;q=0.8',
        ]);

        $this->assertSame([], $this->flags($request, 'web', 'chromium'));
    }

    public function test_spoofed_chrome_from_a_script_raises_the_browser_flags(): void
    {
        $request = $this->request(['User-Agent' => self::CHROME, 'Accept' => 'application/json']);

        $this->assertSame(
            [Flags::UA_CHROMIUM_NO_CH, Flags::BROWSER_NO_SEC_FETCH, Flags::BROWSER_NO_ACCEPT_LANGUAGE, Flags::HTML_GET_NO_HTML_ACCEPT],
            $this->flags($request, 'web', 'chromium')
        );
    }

    public function test_firefox_without_client_hints_is_fine_and_safari_without_sec_fetch_is_weak(): void
    {
        $request = $this->request(['Sec-Fetch-Mode' => 'navigate', 'Accept-Language' => 'de', 'Accept' => '*/*']);
        $this->assertSame([], $this->flags($request, 'web', 'firefox'), 'no client hints expected from Firefox');

        $request = $this->request(['Accept-Language' => 'de', 'Accept' => 'text/html']);
        $this->assertSame([Flags::BROWSER_NO_SEC_FETCH], $this->flags($request, 'web', 'safari'));
    }

    public function test_html_accept_rule_applies_to_browser_get_on_web_only(): void
    {
        $base = ['Sec-Fetch-Mode' => 'navigate', 'Accept-Language' => 'en', 'Accept' => 'image/avif'];
        $this->assertSame([Flags::HTML_GET_NO_HTML_ACCEPT], $this->flags($this->request($base), 'web', 'firefox'));
        $this->assertSame([], $this->flags($this->request($base, 'POST'), 'web', 'firefox'), 'POST');
        $this->assertSame([Flags::BEARER_WITH_SEC_FETCH], $this->flags($this->request($base), 'api', 'firefox'), 'api surface: a browser-shaped API call, not an Accept problem');
        $this->assertSame([], $this->flags($this->request(['Sec-Fetch-Mode' => 'navigate', 'Accept-Language' => 'en']), 'web', 'firefox'), 'no Accept at all');
        $this->assertSame([Flags::LIBRARY_UA_ON_WEB], $this->flags($this->request($base), 'web', 'library'), 'not a browser: no Accept rule, but a library on web');
    }

    public function test_library_on_web_and_cookies_or_sec_fetch_on_api(): void
    {
        $this->assertSame([Flags::LIBRARY_UA_ON_WEB], $this->flags($this->request([]), 'web', 'library'));
        $this->assertSame([Flags::LIBRARY_UA_ON_WEB], $this->flags($this->request([]), 'web', 'empty'));
        $this->assertSame([], $this->flags($this->request([]), 'api', 'library'));

        $this->assertSame([Flags::COOKIES_ON_API], $this->flags($this->request([]), 'api', 'library', null, ['laravel_session']));
        $this->assertSame([Flags::COOKIES_ON_API], $this->flags($this->request([]), 'api', 'library', null, ['_lsd']));
        $this->assertSame([], $this->flags($this->request([]), 'api', 'library', null, ['other']));
        $this->assertSame([], $this->flags($this->request([]), 'web', 'library', null, ['laravel_session']) === [Flags::LIBRARY_UA_ON_WEB] ? [] : ['x'], 'cookies on web are normal');

        $this->assertSame([Flags::BEARER_WITH_SEC_FETCH], $this->flags($this->request(['Sec-Fetch-Mode' => 'cors']), 'api', 'library'));
    }

    public function test_tag_bad_mac_and_proxy_header_untrusted(): void
    {
        $this->assertSame([Flags::TAG_BAD_MAC], $this->flags($this->request([]), 'api', 'library', 'bad_mac'));
        $this->assertSame([], $this->flags($this->request([]), 'api', 'library', 'valid'));
        $this->assertSame([Flags::PROXY_HEADER_UNTRUSTED], $this->flags($this->request([]), 'api', 'library', null, [], true));
    }
}
