<?php

namespace Leeside\Laravel\Shape;

use Illuminate\Http\Request;
use Leeside\Laravel\Surface\SurfaceClassifier;
use Leeside\Laravel\Surface\UserAgentClass;
use Leeside\Laravel\Tag\TagCookie;

/**
 * Consistency flags, each from the current request alone. Features for
 * Windside, never verdicts: a browser that says Chrome but sends no client
 * hints, a library UA on a web page, cookies on an API call. Cross-request
 * logic lives in leesided.
 */
final class Flags
{
    public const UA_CHROMIUM_NO_CH = 'ua_chromium_no_ch';
    public const BROWSER_NO_SEC_FETCH = 'browser_no_sec_fetch';
    public const BROWSER_NO_ACCEPT_LANGUAGE = 'browser_no_accept_language';
    public const HTML_GET_NO_HTML_ACCEPT = 'html_get_no_html_accept';
    public const LIBRARY_UA_ON_WEB = 'library_ua_on_web';
    public const COOKIES_ON_API = 'cookies_on_api';
    public const BEARER_WITH_SEC_FETCH = 'bearer_with_sec_fetch';
    public const TAG_BAD_MAC = 'tag_bad_mac';
    public const PROXY_HEADER_UNTRUSTED = 'proxy_header_untrusted';

    /**
     * @param  string[]  $cookieNames  the request's cookie names (sorted, from RequestShape)
     * @return string[]
     */
    public static function compute(
        Request $request,
        string $surface,
        string $uaClass,
        ?string $tagStatus,
        array $cookieNames,
        string $sessionCookie,
        string $tagCookie,
        bool $proxyHeaderUntrusted,
    ): array {
        $flags = [];
        $browser = UserAgentClass::isBrowser($uaClass);
        $web = $surface === SurfaceClassifier::WEB;
        $api = $surface === SurfaceClassifier::API;

        if ($uaClass === UserAgentClass::CHROMIUM && ! $request->headers->has('Sec-CH-UA')) {
            $flags[] = self::UA_CHROMIUM_NO_CH;
        }
        if ($browser && ! $request->headers->has('Sec-Fetch-Mode')) {
            $flags[] = self::BROWSER_NO_SEC_FETCH;
        }
        if ($browser && ! $request->headers->has('Accept-Language')) {
            $flags[] = self::BROWSER_NO_ACCEPT_LANGUAGE;
        }
        if ($browser && $web && $request->isMethod('GET') && $request->headers->has('Accept')) {
            $accept = (string) $request->headers->get('Accept', '');
            if (! str_contains($accept, 'text/html') && ! str_contains($accept, '*/*')) {
                $flags[] = self::HTML_GET_NO_HTML_ACCEPT;
            }
        }
        if ($web && ($uaClass === UserAgentClass::LIBRARY || $uaClass === UserAgentClass::EMPTY)) {
            $flags[] = self::LIBRARY_UA_ON_WEB;
        }
        if ($api && (in_array($sessionCookie, $cookieNames, true) || in_array($tagCookie, $cookieNames, true))) {
            $flags[] = self::COOKIES_ON_API;
        }
        if ($api && $request->headers->has('Sec-Fetch-Mode')) {
            $flags[] = self::BEARER_WITH_SEC_FETCH;
        }
        if ($tagStatus === TagCookie::BAD_MAC) {
            $flags[] = self::TAG_BAD_MAC;
        }
        if ($proxyHeaderUntrusted) {
            $flags[] = self::PROXY_HEADER_UNTRUSTED;
        }

        return $flags;
    }
}
