<?php

namespace Leeside\Laravel\Surface;

/**
 * A cheap user-agent class: enough to know whether browser-shaped
 * expectations (cookies, Sec-Fetch, Accept-Language) apply. Regexes only,
 * no parser; the raw string never leaves the request.
 */
final class UserAgentClass
{
    public const CHROMIUM = 'chromium';
    public const FIREFOX = 'firefox';
    public const SAFARI = 'safari';
    public const OTHER_BROWSER = 'other_browser';
    public const LIBRARY = 'library';
    public const EMPTY = 'empty';

    public static function classify(?string $userAgent): string
    {
        $ua = trim((string) $userAgent);
        if ($ua === '') {
            return self::EMPTY;
        }

        // Chromium first: Chrome, Edge, Opera, Brave, Samsung all carry
        // "Chrome/" and "Safari/", so the Safari test must come after.
        if (preg_match('~\b(?:Chrome|Chromium|CriOS|Edg|EdgA|EdgiOS|OPR|Brave|Vivaldi|SamsungBrowser|HeadlessChrome)/\d~', $ua) === 1) {
            return self::CHROMIUM;
        }

        if (preg_match('~\b(?:Firefox|FxiOS)/\d~', $ua) === 1) {
            return self::FIREFOX;
        }

        if (str_contains($ua, 'Safari/') && preg_match('~\bVersion/\d~', $ua) === 1) {
            return self::SAFARI;
        }

        if (str_starts_with($ua, 'Mozilla/') || str_starts_with($ua, 'Opera/')) {
            return self::OTHER_BROWSER;
        }

        return self::LIBRARY;
    }

    public static function isBrowser(string $class): bool
    {
        return in_array($class, [self::CHROMIUM, self::FIREFOX, self::SAFARI, self::OTHER_BROWSER], true);
    }
}
