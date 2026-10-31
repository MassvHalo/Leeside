<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Testing\TestResponse;
use Leeside\Laravel\Middleware\TagTurn;
use Leeside\Laravel\Tag\TagCookie;

/** Schema v2, section 3 of the identity brief: the Leeside tag cookie. */
class TagTest extends SampleAppTestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // The install step every host app performs.
        EncryptCookies::except(['_lsd']);
        TagTurn::resetWarning();
        unset($_COOKIE['_lsd']);
    }

    protected function tearDown(): void
    {
        unset($_COOKIE['_lsd']);
        parent::tearDown();
    }

    protected function defineSampleRoutes(): void
    {
        parent::defineSampleRoutes();

        $router = $this->app['router'];
        $router->get('/page', fn () => new Response('<h1>page</h1>', 200, ['Content-Type' => 'text/html; charset=UTF-8']))
            ->middleware('web')->name('page');
        $router->get('/build/app.css', fn () => new Response('body{}', 200, ['Content-Type' => 'text/css']))
            ->middleware('web')->name('asset.css');
        $router->post('/webhooks/demo', fn () => new Response('<p>thanks</p>', 200, ['Content-Type' => 'text/html']))
            ->middleware('web')->name('webhooks.demo');
    }

    private function tagCookie(TestResponse $response): ?string
    {
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === '_lsd') {
                return $cookie->getValue();
            }
        }

        return null;
    }

    public function test_html_web_page_issues_a_tag_and_the_event_says_so(): void
    {
        $response = $this->get('/page');
        $response->assertOk();

        $value = $this->tagCookie($response);
        $this->assertNotNull($value, 'a tag was set');
        $cookie = collect($response->headers->getCookies())->first(fn ($c) => $c->getName() === '_lsd');
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertSame('lax', $cookie->getSameSite());
        $this->assertSame('/', $cookie->getPath());
        $this->assertFalse($cookie->isSecure(), 'plain http request');
        $this->assertGreaterThan(time() + TagCookie::MAX_AGE - 60, $cookie->getExpiresTime());

        $parsed = $this->app[TagCookie::class]->parse($value);
        $this->assertSame(TagCookie::VALID, $parsed['status']);

        $event = $this->lastEvent();
        $this->assertSame('issued', $event['tag_status']);
        $this->assertSame($this->hasher()->tagHash($parsed['id']), $event['tag_id']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $event['tag_id']);
        $this->assertStringNotContainsString($value, $this->eventsJson(), 'the cookie value never leaves');
        $this->assertStringNotContainsString($parsed['id'], $this->eventsJson(), 'nor the raw id');
    }

    public function test_secure_follows_the_request(): void
    {
        $response = $this->get('https://localhost/page');
        $cookie = collect($response->headers->getCookies())->first(fn ($c) => $c->getName() === '_lsd');
        $this->assertTrue($cookie->isSecure());
    }

    public function test_no_tag_on_json_api_asset_or_webhook_responses(): void
    {
        $this->assertNull($this->tagCookie($this->get('/venues/1')->assertOk()), 'JSON on web');
        $this->assertSame('absent', $this->lastEvent()['tag_status']);
        $this->assertNull($this->lastEvent()['tag_id']);

        $this->assertNull($this->tagCookie($this->getJson('/api/venues')->assertOk()), 'api surface');
        $this->assertNull($this->lastEvent()['tag_status'], 'the tag middleware is not in the api group');

        $this->assertNull($this->tagCookie($this->get('/build/app.css')->assertOk()), 'asset');
        $this->assertSame('absent', $this->lastEvent()['tag_status']);

        $this->assertNull($this->tagCookie($this->post('/webhooks/demo')->assertOk()), 'webhook surface, even as HTML');
        $this->assertSame('absent', $this->lastEvent()['tag_status']);
    }

    public function test_valid_tag_presented_back_is_valid_and_never_rotated(): void
    {
        $first = $this->tagCookie($this->get('/page'));
        $firstId = $this->lastEvent()['tag_id'];

        $second = $this->withUnencryptedCookie('_lsd', $first)->get('/page');
        $second->assertOk();

        $this->assertNull($this->tagCookie($second), 'no new Set-Cookie');
        $event = $this->lastEvent();
        $this->assertSame('valid', $event['tag_status']);
        $this->assertSame($firstId, $event['tag_id'], 'the same id links the two turns');

        $probes = $this->rules->probes;
        $this->assertCount(2, $probes);
        $this->assertNull($probes[0]['tag_id'], 'issued after the probe: not on it');
        $this->assertSame($firstId, $probes[1]['tag_id'], 'a valid tag is on the probe, so leesided can find the actor');
        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $probes[1]['turn_id']);
        $this->assertSame($probes[1]['turn_id'], $event['turn_id'], 'probe and event share the turn id');
        $this->assertNotSame($probes[0]['turn_id'], $probes[1]['turn_id']);
    }

    public function test_tampered_tag_is_bad_mac_and_a_fresh_tag_is_issued(): void
    {
        $value = $this->tagCookie($this->get('/page'));
        [$payload, $mac] = explode('.', $value);
        $tampered = $payload.'.'.($mac[0] === 'A' ? 'B' : 'A').substr($mac, 1);

        $response = $this->withUnencryptedCookie('_lsd', $tampered)->get('/page');
        $response->assertOk();

        $fresh = $this->tagCookie($response);
        $this->assertNotNull($fresh);
        $this->assertNotSame($value, $fresh);
        $event = $this->lastEvent();
        $this->assertSame('bad_mac', $event['tag_status']);
        $this->assertSame($this->hasher()->tagHash($this->app[TagCookie::class]->parse($fresh)['id']), $event['tag_id']);
    }

    public function test_encrypted_looking_tag_is_malformed_and_warns_once(): void
    {
        $spy = Log::spy();
        $_COOKIE['_lsd'] = base64_encode(json_encode(['iv' => base64_encode(random_bytes(16)), 'value' => 'x', 'mac' => 'y', 'tag' => '']));

        $this->get('/page')->assertOk();
        $this->assertSame('malformed', $this->lastEvent()['tag_status']);
        $this->get('/page')->assertOk();
        $this->assertSame('malformed', $this->lastEvent()['tag_status']);

        $spy->shouldHaveReceived('warning')->once()->withArgs(fn (string $message) => str_contains($message, 'encryptCookies'));
    }

    public function test_disabled_tag_sets_nothing_and_records_nothing(): void
    {
        $this->app['config']->set('leeside.tag.enabled', false);

        $this->assertNull($this->tagCookie($this->get('/page')->assertOk()));
        $this->assertNull($this->lastEvent()['tag_status']);
    }
}
