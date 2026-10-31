<?php

namespace Leeside\Laravel\Tag;

use Symfony\Component\HttpFoundation\Cookie;

/**
 * The Leeside tag: a random id the package itself mints, signed so a client
 * cannot forge one. Format `base64url(id || issued_at) . "." . base64url(mac)`
 * with a 16-byte id, a 4-byte big-endian unix time and the first 16 bytes
 * of HMAC-SHA256 over the payload. It carries nothing about the user; the
 * event stores a keyed hash of the id, never the cookie.
 */
final class TagCookie
{
    public const ABSENT = 'absent';
    public const MALFORMED = 'malformed';
    public const BAD_MAC = 'bad_mac';
    public const VALID = 'valid';
    public const ISSUED = 'issued';

    public const DEFAULT_NAME = '_lsd';
    public const MAX_AGE = 31536000;

    private const ID_BYTES = 16;
    private const MAC_BYTES = 16;

    public function __construct(
        private readonly string $secret,
        private readonly string $name = self::DEFAULT_NAME,
    ) {}

    /** The configured secret, else one derived from APP_KEY under a fixed label. */
    public static function fromConfig(?string $secret, string $appKey, ?string $name = null): self
    {
        if ($secret === null || $secret === '') {
            $secret = hash_hmac('sha256', 'leeside-tag', self::rawKey($appKey));
        }

        return new self($secret, ($name === null || $name === '') ? self::DEFAULT_NAME : $name);
    }

    public function name(): string
    {
        return $this->name;
    }

    /** @return array{value: string, id: string, issued_at: int} id as 32 hex */
    public function issue(?int $now = null): array
    {
        $now ??= time();
        $id = random_bytes(self::ID_BYTES);
        $payload = $id.pack('N', $now);

        return [
            'value' => self::b64url($payload).'.'.self::b64url($this->mac($payload)),
            'id' => bin2hex($id),
            'issued_at' => $now,
        ];
    }

    /**
     * @return array{status: string, id: ?string, issued_at: ?int, encrypted: bool}
     *   `encrypted` is true when the value looks like a Laravel encrypted
     *   cookie payload: the host forgot the encryptCookies except list.
     */
    public function parse(?string $raw): array
    {
        $none = ['status' => self::ABSENT, 'id' => null, 'issued_at' => null, 'encrypted' => false];
        if ($raw === null || $raw === '') {
            return $none;
        }

        if (self::looksEncrypted($raw)) {
            return ['status' => self::MALFORMED, 'id' => null, 'issued_at' => null, 'encrypted' => true];
        }

        $parts = explode('.', $raw);
        if (count($parts) !== 2) {
            return ['status' => self::MALFORMED] + $none;
        }

        $payload = self::b64urlDecode($parts[0]);
        $mac = self::b64urlDecode($parts[1]);
        if ($payload === null || strlen($payload) !== self::ID_BYTES + 4 || $mac === null || strlen($mac) !== self::MAC_BYTES) {
            return ['status' => self::MALFORMED] + $none;
        }

        if (! hash_equals($this->mac($payload), $mac)) {
            return ['status' => self::BAD_MAC] + $none;
        }

        return [
            'status' => self::VALID,
            'id' => bin2hex(substr($payload, 0, self::ID_BYTES)),
            'issued_at' => (int) unpack('N', substr($payload, self::ID_BYTES, 4))[1],
            'encrypted' => false,
        ];
    }

    /** HttpOnly, SameSite=Lax, Path=/, one year; Secure when the request was. */
    public function cookie(string $value, bool $secure, ?int $now = null): Cookie
    {
        return Cookie::create($this->name, $value, ($now ?? time()) + self::MAX_AGE, '/', null, $secure, true, false, Cookie::SAMESITE_LAX);
    }

    /** A Laravel encrypted cookie is base64 of JSON with iv and value. */
    public static function looksEncrypted(string $raw): bool
    {
        $decoded = base64_decode($raw, true);
        if ($decoded === false || $decoded === '' || $decoded[0] !== '{') {
            return false;
        }

        $json = json_decode($decoded, true);

        return is_array($json) && isset($json['iv'], $json['value']);
    }

    private function mac(string $payload): string
    {
        return substr(hash_hmac('sha256', $payload, $this->secret, true), 0, self::MAC_BYTES);
    }

    private static function rawKey(string $appKey): string
    {
        if (str_starts_with($appKey, 'base64:')) {
            $decoded = base64_decode(substr($appKey, 7), true);
            if ($decoded !== false) {
                return $decoded;
            }
        }

        return $appKey;
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $text): ?string
    {
        if ($text === '' || preg_match('/^[A-Za-z0-9_-]+$/', $text) !== 1) {
            return null;
        }

        $decoded = base64_decode(strtr($text, '-_', '+/').str_repeat('=', (4 - strlen($text) % 4) % 4), true);

        return $decoded === false ? null : $decoded;
    }
}
