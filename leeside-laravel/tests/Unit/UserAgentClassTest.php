<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Surface\UserAgentClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class UserAgentClassTest extends TestCase
{
    /** @return array<string, array{string|null, string}> */
    public static function agents(): array
    {
        return [
            'chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36', 'chromium'],
            'edge' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0', 'chromium'],
            'chrome ios' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.0.0 Mobile/15E148 Safari/604.1', 'chromium'],
            'headless' => ['Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/130.0.0.0 Safari/537.36', 'chromium'],
            'firefox' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14.0; rv:131.0) Gecko/20100101 Firefox/131.0', 'firefox'],
            'firefox ios' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/131.0 Mobile/15E148 Safari/605.1.15', 'firefox'],
            'safari' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15', 'safari'],
            'googlebot' => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'other_browser'],
            'old opera' => ['Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.18', 'other_browser'],
            'curl' => ['curl/8.5.0', 'library'],
            'requests' => ['python-requests/2.32.3', 'library'],
            'go' => ['Go-http-client/2.0', 'library'],
            'okhttp' => ['okhttp/4.12.0', 'library'],
            'traffic script' => ['leeside-traffic/1.0', 'library'],
            'empty' => ['', 'empty'],
            'spaces' => ['   ', 'empty'],
            'null' => [null, 'empty'],
        ];
    }

    #[DataProvider('agents')]
    public function test_classifies(?string $ua, string $expected): void
    {
        $this->assertSame($expected, UserAgentClass::classify($ua));
    }

    public function test_browser_classes(): void
    {
        foreach (['chromium', 'firefox', 'safari', 'other_browser'] as $class) {
            $this->assertTrue(UserAgentClass::isBrowser($class));
        }
        $this->assertFalse(UserAgentClass::isBrowser('library'));
        $this->assertFalse(UserAgentClass::isBrowser('empty'));
    }
}
