<?php

namespace Leeside\Laravel\Hash;

class Hasher
{
    public function __construct(private readonly string $key) {}

    public static function fromConfig(?string $hashKey, string $appKey): self
    {
        if ($hashKey !== null && $hashKey !== '') {
            return new self($hashKey);
        }

        return new self(hash_hmac('sha256', 'leeside', $appKey));
    }

    /** 16 hex. Falls back to peerKey() when the app has no session. */
    public function sessionKey(string $sessionId): string
    {
        return $this->truncate($this->hmac('session', $sessionId), 16);
    }

    /** 16 hex, always present. */
    public function peerKey(string $ip, string $userAgent): string
    {
        return $this->truncate($this->hmac('peer', $ip."\0".$userAgent), 16);
    }

    /** 16 hex. The factory maps "no resolved user" to `anon` instead. */
    public function principal(string $id): string
    {
        return $this->truncate($this->hmac('principal', $id), 16);
    }

    /** 8 hex, for route-model keys and scalar route params. */
    public function idHash(string $key): string
    {
        return $this->truncate($this->hmac('id', $key), 8);
    }

    /** 16 hex (8 before schema v2). The raw user agent never leaves the app. */
    public function uaHash(string $userAgent): string
    {
        return $this->truncate($this->hmac('ua', $userAgent), 16);
    }

    /** 16 hex, over request-shape components: header names, cookie names, the composite. */
    public function shapeHash(string $input): string
    {
        return $this->truncate($this->hmac('shape', $input), 16);
    }

    /** 16 hex, of the tag cookie's random id; the id itself is never written. */
    public function tagHash(string $tagId): string
    {
        return $this->truncate($this->hmac('tag', $tagId), 16);
    }

    /** 16 hex, of a bearer token, API key or verified webhook signer id. */
    public function credentialHash(string $credential): string
    {
        return $this->truncate($this->hmac('credential', $credential), 16);
    }

    /**
     * Deterministic sampling: the first 8 hex digits of the session key as a
     * draw in [0, 1), so a session is wholly in or out.
     */
    public static function sampled(string $sessionKey, float $rate): bool
    {
        if ($rate >= 1.0) {
            return true;
        }

        if ($rate <= 0.0) {
            return false;
        }

        return hexdec(substr($sessionKey, 0, 8)) / 4294967296 < $rate;
    }

    private function hmac(string $namespace, string $value): string
    {
        return hash_hmac('sha256', $namespace."\0".$value, $this->key);
    }

    private function truncate(string $hex, int $length): string
    {
        return substr($hex, 0, $length);
    }
}
