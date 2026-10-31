<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Tag\TagCookie;
use PHPUnit\Framework\TestCase;

class TagCookieTest extends TestCase
{
    private TagCookie $tag;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tag = new TagCookie('tag-secret');
    }

    public function test_issue_then_parse_round_trips(): void
    {
        $issued = $this->tag->issue(1_761_600_000);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $issued['id']);
        $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/', $issued['value']);
        $this->assertStringNotContainsString('=', $issued['value']);

        $parsed = $this->tag->parse($issued['value']);
        $this->assertSame(TagCookie::VALID, $parsed['status']);
        $this->assertSame($issued['id'], $parsed['id']);
        $this->assertSame(1_761_600_000, $parsed['issued_at']);
        $this->assertFalse($parsed['encrypted']);

        $this->assertNotSame($issued['id'], $this->tag->issue()['id'], 'ids are random');
    }

    public function test_tampered_mac_and_payload_are_bad_mac(): void
    {
        $value = $this->tag->issue()['value'];
        [$payload, $mac] = explode('.', $value);

        $flipped = $mac[0] === 'A' ? 'B' : 'A';
        $this->assertSame(TagCookie::BAD_MAC, $this->tag->parse($payload.'.'.$flipped.substr($mac, 1))['status']);

        $flippedPayload = $payload[3] === 'A' ? 'B' : 'A';
        $this->assertSame(TagCookie::BAD_MAC, $this->tag->parse(substr($payload, 0, 3).$flippedPayload.substr($payload, 4).'.'.$mac)['status']);

        $this->assertSame(TagCookie::BAD_MAC, (new TagCookie('other-secret'))->parse($value)['status'], 'another install\'s tag');
        $this->assertNull($this->tag->parse($payload.'.'.$flipped.substr($mac, 1))['id'], 'no id from an unsigned tag');
    }

    public function test_malformed_and_absent(): void
    {
        $this->assertSame(TagCookie::ABSENT, $this->tag->parse(null)['status']);
        $this->assertSame(TagCookie::ABSENT, $this->tag->parse('')['status']);
        foreach (['nodot', 'a.b.c', 'AAAA.BBBB', '!!!.###', str_repeat('A', 26).'.'.str_repeat('B', 22), base64_encode('{"not":"ours"}')] as $raw) {
            $this->assertSame(TagCookie::MALFORMED, $this->tag->parse($raw)['status'], $raw);
            $this->assertFalse($this->tag->parse($raw)['encrypted'], $raw);
        }
        // Right lengths, wrong signature: that is bad_mac, not malformed.
        $this->assertSame(TagCookie::BAD_MAC, $this->tag->parse(str_repeat('A', 27).'.'.str_repeat('B', 22))['status']);
    }

    public function test_encrypted_payload_is_malformed_and_flagged(): void
    {
        $encrypted = base64_encode(json_encode(['iv' => base64_encode(random_bytes(16)), 'value' => 'xyz', 'mac' => 'abc', 'tag' => '']));

        $parsed = $this->tag->parse($encrypted);
        $this->assertSame(TagCookie::MALFORMED, $parsed['status']);
        $this->assertTrue($parsed['encrypted']);
        $this->assertTrue(TagCookie::looksEncrypted($encrypted));
        $this->assertFalse(TagCookie::looksEncrypted($this->tag->issue()['value']));
    }

    public function test_secret_derives_from_app_key_when_unset(): void
    {
        $appKey = 'base64:'.base64_encode(str_repeat('k', 32));
        $a = TagCookie::fromConfig(null, $appKey);
        $b = TagCookie::fromConfig('', $appKey);
        $value = $a->issue()['value'];

        $this->assertSame(TagCookie::VALID, $b->parse($value)['status'], 'same APP_KEY, same derived secret');
        $this->assertSame(TagCookie::BAD_MAC, TagCookie::fromConfig(null, 'base64:'.base64_encode(str_repeat('z', 32)))->parse($value)['status']);
        $this->assertSame(TagCookie::BAD_MAC, TagCookie::fromConfig('explicit', $appKey)->parse($value)['status'], 'an explicit secret wins');
        $this->assertSame('_lsd', $a->name());
        $this->assertSame('_tag', TagCookie::fromConfig(null, $appKey, '_tag')->name());
    }

    public function test_cookie_attributes(): void
    {
        $cookie = $this->tag->cookie('v.m', true, 1_000);

        $this->assertSame('_lsd', $cookie->getName());
        $this->assertSame('v.m', $cookie->getValue());
        $this->assertSame(1_000 + TagCookie::MAX_AGE, $cookie->getExpiresTime());
        $this->assertSame('/', $cookie->getPath());
        $this->assertTrue($cookie->isHttpOnly());
        $this->assertTrue($cookie->isSecure());
        $this->assertSame('lax', $cookie->getSameSite());
        $this->assertFalse($this->tag->cookie('v.m', false)->isSecure(), 'Secure follows the request');
    }
}
