<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Http\Middleware\TrustProxies;

/** Schema v2, sections 4, 5 and 7: the request shape, the flags, the proxy fingerprints. */
class ShapeFlagsTest extends SampleAppTestCase
{
    protected function tearDown(): void
    {
        TrustProxies::flushState();
        parent::tearDown();
    }

    public function test_event_carries_shape_and_flags(): void
    {
        $this->withHeaders([
            'User-Agent' => 'python-requests/2.32.3',
            'Accept-Language' => 'en-US',
            'Referer' => 'https://example.test/',
        ])->get('/venues/1')->assertOk();

        $event = $this->lastEvent();
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $event['shape_hash']);
        $shape = $event['shape'];
        $this->assertSame('GET', $shape['method']);
        $this->assertSame('HTTP/1.1', $shape['http_version']);
        $this->assertTrue($shape['has_referer']);
        $this->assertSame('en-u', $shape['accept_language']);
        $this->assertIsInt($shape['header_count']);
        $this->assertFalse($shape['order_reliable'], 'the default: php-fpm reverses header order');
        $this->assertSame(['library_ua_on_web'], $event['flags']);
        $this->assertNull($event['ja4']);
        $this->assertNull($event['ja4t']);
        $this->assertNull($event['h2_fp']);
        $this->assertStringNotContainsString('python-requests', $this->eventsJson());
        $this->assertStringNotContainsString('example.test', $this->eventsJson());
    }

    public function test_header_order_config_picks_the_recipe(): void
    {
        $this->withHeaders(['X-Zeta' => '1', 'X-Alpha' => '2'])->get('/venues/1')->assertOk();
        $first = $this->lastEvent()['shape'];
        $this->flushHeaders()->withHeaders(['X-Alpha' => '2', 'X-Zeta' => '1'])->get('/venues/1')->assertOk();
        $second = $this->lastEvent()['shape'];
        $this->assertFalse($first['order_reliable']);
        $this->assertSame($first['header_names_hash'], $second['header_names_hash'], 'unreliable: sorted names, order ignored');

        $this->app['config']->set('leeside.fingerprint.header_order_reliable', true);
        $this->flushHeaders()->withHeaders(['X-Zeta' => '1', 'X-Alpha' => '2'])->get('/venues/1')->assertOk();
        $third = $this->lastEvent()['shape'];
        $this->flushHeaders()->withHeaders(['X-Alpha' => '2', 'X-Zeta' => '1'])->get('/venues/1')->assertOk();
        $fourth = $this->lastEvent()['shape'];
        $this->assertTrue($third['order_reliable']);
        $this->assertNotSame($third['header_names_hash'], $fourth['header_names_hash'], 'reliable: order matters');
    }

    public function test_bad_mac_tag_raises_its_flag(): void
    {
        $this->app['router']->get('/page', fn () => new \Illuminate\Http\Response('<p>x</p>', 200, ['Content-Type' => 'text/html']))
            ->middleware('web')->name('page');
        \Illuminate\Cookie\Middleware\EncryptCookies::except(['_lsd']);

        $this->withUnencryptedCookie('_lsd', 'AAAAAAAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBB')->get('/page')->assertOk();

        $event = $this->lastEvent();
        $this->assertSame('bad_mac', $event['tag_status']);
        $this->assertContains('tag_bad_mac', $event['flags']);
    }

    public function test_proxy_fingerprints_from_an_untrusted_hop_are_dropped_and_flagged(): void
    {
        $this->withHeaders(['X-Leeside-JA4' => 't13d1516h2_8daaf6152771_b0da82dd1658', 'X-Leeside-H2' => '1:65536;3:1000'])
            ->get('/venues/1')->assertOk();

        $event = $this->lastEvent();
        $this->assertNull($event['ja4']);
        $this->assertNull($event['h2_fp']);
        $this->assertContains('proxy_header_untrusted', $event['flags']);
        $this->assertStringNotContainsString('t13d1516h2', $this->eventsJson());
    }

    public function test_proxy_fingerprints_from_a_trusted_proxy_are_stored(): void
    {
        TrustProxies::at('127.0.0.1');

        $this->withHeaders([
            'X-Leeside-JA4' => 't13d1516h2_8daaf6152771_b0da82dd1658',
            'X-Leeside-JA4T' => '65535_2-1-3-1-1-4_1460_8',
            'X-Forwarded-For' => '203.0.113.9',
        ])->get('/venues/1')->assertOk();

        $event = $this->lastEvent();
        $this->assertSame('t13d1516h2_8daaf6152771_b0da82dd1658', $event['ja4']);
        $this->assertSame('65535_2-1-3-1-1-4_1460_8', $event['ja4t']);
        $this->assertNull($event['h2_fp']);
        $this->assertNotContains('proxy_header_untrusted', $event['flags']);
        $this->assertSame('forwarded', $event['ip_trust']);
    }
}
