<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Hash\Hasher;
use PHPUnit\Framework\TestCase;

class HasherTest extends TestCase
{
    private Hasher $hasher;

    protected function setUp(): void
    {
        parent::setUp();

        $this->hasher = new Hasher('test-key');
    }

    public function test_namespaces_differ_for_the_same_input(): void
    {
        $hashes = [
            $this->hasher->sessionKey('same'),
            $this->hasher->peerKey('same', 'same'),
            $this->hasher->principal('same'),
            $this->hasher->idHash('same'),
            $this->hasher->uaHash('same'),
        ];

        $this->assertSame($hashes, array_unique($hashes));
    }

    public function test_truncation_lengths_and_hex_format(): void
    {
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $this->hasher->sessionKey('s'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $this->hasher->peerKey('1.2.3.4', 'ua'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $this->hasher->principal('1'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{8}$/', $this->hasher->idHash('1'));
        $this->assertMatchesRegularExpression('/^[0-9a-f]{8}$/', $this->hasher->uaHash('ua'));
    }

    public function test_hashing_is_deterministic_and_input_sensitive(): void
    {
        $this->assertSame($this->hasher->sessionKey('a'), $this->hasher->sessionKey('a'));
        $this->assertNotSame($this->hasher->sessionKey('a'), $this->hasher->sessionKey('b'));
        $this->assertNotSame(
            $this->hasher->peerKey('1.1.1.1', 'ua'),
            $this->hasher->peerKey('1.1.1.2', 'ua')
        );
    }

    public function test_explicit_hash_key_wins_over_app_key(): void
    {
        $explicit = Hasher::fromConfig('explicit', 'app-key');

        $this->assertSame($explicit->sessionKey('s'), (new Hasher('explicit'))->sessionKey('s'));
    }

    public function test_missing_hash_key_derives_from_app_key(): void
    {
        $derived = Hasher::fromConfig(null, 'app-key');
        $expected = new Hasher(hash_hmac('sha256', 'leeside', 'app-key'));

        $this->assertSame($expected->sessionKey('s'), $derived->sessionKey('s'));
        $this->assertSame(
            Hasher::fromConfig('', 'app-key')->sessionKey('s'),
            $derived->sessionKey('s')
        );
    }

    public function test_sampling_is_deterministic_on_session_key(): void
    {
        $this->assertTrue(Hasher::sampled('00000000ffffffff', 0.5));
        $this->assertFalse(Hasher::sampled('ffffffffffffffff', 0.5));
        $this->assertTrue(Hasher::sampled('7fffffff00000000', 0.5));
        $this->assertFalse(Hasher::sampled('8000000000000000', 0.5));

        $this->assertSame(
            Hasher::sampled('a1b2c3d4e5f60718', 0.25),
            Hasher::sampled('a1b2c3d4e5f60718', 0.25)
        );
    }

    public function test_sampling_boundaries(): void
    {
        $this->assertTrue(Hasher::sampled('ffffffffffffffff', 1.0));
        $this->assertFalse(Hasher::sampled('0000000000000000', 0.0));
    }
}
