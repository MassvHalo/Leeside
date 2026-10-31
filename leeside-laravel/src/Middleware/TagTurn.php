<?php

namespace Leeside\Laravel\Middleware;

use Closure;
use Illuminate\Config\Repository as Config;
use Illuminate\Http\Request;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Surface\SurfaceClassifier;
use Leeside\Laravel\Tag\TagCookie;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * Reads the Leeside tag on the way in and issues one on the way out of an
 * HTML page on the web surface. Lives in the `web` group because that is
 * where tags apply, and because setting a cookie has to happen in handle():
 * CaptureTurn's terminate() runs after the response has left. This is the
 * one place the package modifies a response other than a denial.
 */
class TagTurn
{
    private static bool $warnedEncrypted = false;

    public function __construct(
        private readonly TurnContext $context,
        private readonly TagCookie $tag,
        private readonly Hasher $hasher,
        private readonly SurfaceClassifier $surface,
        private readonly Config $config,
        private readonly LoggerInterface $log,
    ) {}

    public function handle(Request $request, Closure $next): mixed
    {
        if (! $this->config->get('leeside.enabled', true) || ! $this->config->get('leeside.tag.enabled', true)) {
            return $next($request);
        }

        $parsed = $this->tag->parse($this->rawCookie($request));
        if ($parsed['encrypted']) {
            $this->warnEncryptedOnce();
        }
        $this->context->recordTag(
            $parsed['status'],
            $parsed['id'] === null ? null : $this->hasher->tagHash($parsed['id'])
        );

        $response = $next($request);

        if ($parsed['status'] !== TagCookie::VALID && $this->shouldIssue($request, $response)) {
            try {
                $issued = $this->tag->issue();
                $response->headers->setCookie($this->tag->cookie($issued['value'], $request->isSecure()));
                // The incoming status stays (absent becomes issued); the id is
                // the one the client carries next, so leesided can link it.
                $this->context->recordTag(
                    $parsed['status'] === TagCookie::ABSENT ? TagCookie::ISSUED : $parsed['status'],
                    $this->hasher->tagHash($issued['id'])
                );
            } catch (Throwable) {
                // Tagging must never break the response.
            }
        }

        return $response;
    }

    /**
     * The raw superglobal first, so the host's EncryptCookies cannot
     * interfere; the cookie bag only when the superglobal has nothing (test
     * clients populate the bag, not $_COOKIE).
     */
    private function rawCookie(Request $request): ?string
    {
        $name = $this->tag->name();
        $raw = $_COOKIE[$name] ?? null;
        if (is_string($raw) && $raw !== '') {
            return $raw;
        }

        $bag = $request->cookies->get($name);

        return is_string($bag) && $bag !== '' ? $bag : null;
    }

    private function shouldIssue(Request $request, mixed $response): bool
    {
        if (! $response instanceof Response) {
            return false;
        }

        if ($this->surface->classify($request, $request->route()) !== SurfaceClassifier::WEB) {
            return false;
        }

        if ($this->surface->isAsset($request)) {
            return false;
        }

        $type = strtolower(trim(explode(';', (string) $response->headers->get('Content-Type', ''))[0]));

        return $type === 'text/html';
    }

    private function warnEncryptedOnce(): void
    {
        if (self::$warnedEncrypted) {
            return;
        }
        self::$warnedEncrypted = true;

        try {
            $this->log->warning(sprintf(
                'leeside: the %s tag cookie arrived as a Laravel encrypted payload; add it to encryptCookies(except: [...]) in bootstrap/app.php',
                $this->tag->name()
            ));
        } catch (Throwable) {
            // Logging must never break the request.
        }
    }

    /** For tests. */
    public static function resetWarning(): void
    {
        self::$warnedEncrypted = false;
    }
}
