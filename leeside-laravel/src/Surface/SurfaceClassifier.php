<?php

namespace Leeside\Laravel\Surface;

use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;

/**
 * Which kind of client a request belongs to (brief, schema v2). Evaluated in
 * order, first match wins: a forced override, the honeypot group, the
 * webhook list, anything carrying or routed as an API, else web. Everything
 * here is string work on the current request; no lookups.
 */
class SurfaceClassifier
{
    public const WEB = 'web';
    public const API = 'api';
    public const WEBHOOK = 'webhook';
    public const HONEYPOT = 'honeypot';

    public const SURFACES = [self::HONEYPOT, self::WEBHOOK, self::API, self::WEB];

    /** Request attribute an app's webhook verifier sets to the signer id it verified. */
    public const WEBHOOK_SIGNER_ATTRIBUTE = 'leeside.webhook_signer';

    /** Set by the app's verifier when the signature failed, to the claimed signer or the bare signature; never abort. */
    public const WEBHOOK_REJECTED_ATTRIBUTE = 'leeside.webhook_rejected';

    private const DEFAULTS = [
        'honeypot_group' => 'honeypot',
        'webhook' => ['/webhooks/'],
        'api_key_headers' => ['X-Api-Key', 'Api-Key'],
        'force' => [],
        'asset_extensions' => ['css', 'js', 'map', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'webp', 'woff', 'woff2', 'ttf'],
    ];

    public function __construct(private readonly ?Config $config = null) {}

    public function classify(Request $request, ?Route $route): string
    {
        $name = $this->routeName($route);
        $path = $this->path($request);

        foreach ($this->option('force') as $pattern => $surface) {
            if (in_array($surface, self::SURFACES, true) && $this->matches((string) $pattern, $name, $path)) {
                return $surface;
            }
        }

        $groups = $this->groups($route);

        if (in_array($this->option('honeypot_group'), $groups, true)) {
            return self::HONEYPOT;
        }

        foreach ($this->option('webhook') as $pattern) {
            if ($this->matches((string) $pattern, $name, $path)) {
                return self::WEBHOOK;
            }
        }

        $kind = $this->credential($request)['kind'];
        if ($kind === 'bearer' || $kind === 'api_key') {
            return self::API;
        }

        if (in_array('api', $groups, true) || $path === '/api' || str_starts_with($path, '/api/')) {
            return self::API;
        }

        return self::WEB;
    }

    /** Static-looking paths that reached PHP anyway, whatever the surface. */
    public function isAsset(Request $request): bool
    {
        $extension = strtolower(pathinfo($this->path($request), PATHINFO_EXTENSION));

        return $extension !== '' && in_array($extension, $this->option('asset_extensions'), true);
    }

    /**
     * The machine credential presented, if any. The value is for hashing
     * only; it never reaches the event.
     *
     * @return array{kind: ?string, value: ?string}
     */
    public function credential(Request $request): array
    {
        // An app sets the signer attribute only after verifying a webhook
        // signature, so it outranks whatever else the request carries.
        $signer = $request->attributes->get(self::WEBHOOK_SIGNER_ATTRIBUTE);
        if (is_string($signer) && $signer !== '') {
            return ['kind' => 'webhook_sig', 'value' => $signer];
        }

        $rejected = $request->attributes->get(self::WEBHOOK_REJECTED_ATTRIBUTE);
        if ($rejected !== null && $rejected !== false && $rejected !== '') {
            return ['kind' => 'webhook_sig', 'value' => is_string($rejected) ? $rejected : 'rejected'];
        }

        $authorization = (string) $request->headers->get('Authorization', '');
        if ($authorization !== '' && preg_match('/^\s*Bearer\s+(\S+)/i', $authorization, $m) === 1) {
            return ['kind' => 'bearer', 'value' => $m[1]];
        }

        foreach ($this->option('api_key_headers') as $header) {
            $value = $request->headers->get((string) $header);
            if (is_string($value) && $value !== '') {
                return ['kind' => 'api_key', 'value' => $value];
            }
        }

        return ['kind' => null, 'value' => null];
    }

    /** A pattern starting with "/" is a path prefix; anything else is a route name (fnmatch). */
    private function matches(string $pattern, ?string $name, string $path): bool
    {
        if ($pattern === '') {
            return false;
        }

        if (str_starts_with($pattern, '/')) {
            $prefix = rtrim($pattern, '/');

            return $prefix === '' ? true : ($path === $prefix || str_starts_with($path, $prefix.'/'));
        }

        return $name !== null && ($name === $pattern || fnmatch($pattern, $name));
    }

    /** @return string[] */
    private function groups(?Route $route): array
    {
        if ($route === null) {
            return [];
        }

        $middleware = $route->middleware();

        return array_values(array_filter(is_array($middleware) ? $middleware : [], 'is_string'));
    }

    private function routeName(?Route $route): ?string
    {
        $name = $route?->getName();

        return is_string($name) && $name !== '' ? $name : null;
    }

    private function path(Request $request): string
    {
        return '/'.ltrim($request->getPathInfo(), '/');
    }

    private function option(string $key): mixed
    {
        $value = $this->config?->get('leeside.surface.'.$key);

        return $value ?? self::DEFAULTS[$key];
    }
}
