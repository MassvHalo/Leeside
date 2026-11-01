<?php

namespace Leeside\Laravel\Event;

use BackedEnum;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Config\Repository as Config;
use Illuminate\Contracts\Routing\UrlRoutable;
use Illuminate\Http\Request;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Reduce\ShapeReducer;
use Leeside\Laravel\Shape\Flags;
use Leeside\Laravel\Shape\RequestShape;
use Leeside\Laravel\Stats;
use Leeside\Laravel\Surface\CredentialVerifier;
use Leeside\Laravel\Surface\SurfaceClassifier;
use Leeside\Laravel\Surface\UserAgentClass;
use Symfony\Component\HttpFoundation\BinaryFileResponse;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\StreamedResponse;
use Throwable;
use UnitEnum;

class TurnEventFactory
{
    private readonly float $sampleRate;
    /** @var string[] */
    private readonly array $guards;
    private readonly int $maxResponseBytes;
    private readonly SurfaceClassifier $surface;
    private readonly ?CredentialVerifier $verifier;
    private readonly ?Config $config;
    private readonly string $sessionCookie;
    private readonly string $tagCookie;

    /**
     * @param  array{sample_rate?: float, guards?: string[], max_response_bytes?: int}  $options
     */
    public function __construct(
        private readonly Hasher $hasher,
        private readonly ShapeReducer $reducer,
        private readonly AuthFactory $auth,
        private readonly Stats $stats,
        array $options = [],
        ?SurfaceClassifier $surface = null,
        ?CredentialVerifier $verifier = null,
        ?Config $config = null,
    ) {
        $this->surface = $surface ?? new SurfaceClassifier;
        $this->verifier = $verifier;
        $this->config = $config;
        $this->sessionCookie = (string) ($options['session_cookie'] ?? 'laravel_session');
        $this->tagCookie = (string) ($options['tag_cookie'] ?? '_lsd');
        $this->sampleRate = $options['sample_rate'] ?? 1.0;
        $this->guards = $options['guards'] ?? ['web'];
        $this->maxResponseBytes = $options['max_response_bytes'] ?? 65536;
    }

    /** The sync-check probe. Never sampled. */
    public function probe(Request $request, TurnContext $context): array
    {
        $userAgent = (string) $request->userAgent();
        $peerKey = $this->hasher->peerKey($request->ip() ?? 'unknown', $userAgent);

        $sessionId = $this->sessionId($request);
        $credential = $this->surface->credential($request);
        $principal = $this->principal();

        return [
            'v' => 2,
            'ts' => $context->tsUs ?? (int) (microtime(true) * 1_000_000),
            'turn_id' => $context->turnId ?? bin2hex(random_bytes(16)),
            'verb' => $request->getMethod(),
            'route' => $context->route ?? RouteName::fromRoute($request->route()),
            'surface' => $this->surface->classify($request, $request->route()),
            'session_key' => $sessionId === null ? $peerKey : $this->hasher->sessionKey($sessionId),
            'peer_key' => $peerKey,
            'principal' => $principal,
            'credential_hash' => $credential['value'] === null ? null : $this->hasher->credentialHash($credential['value']),
            'credential_status' => $this->credentialStatus($request, $credential['kind'], $credential['value'], $principal),
            // The tag outlives the session; only a valid one names an actor.
            'tag_id' => $context->tagStatus === 'valid' ? $context->tagId : null,
        ];
    }

    /**
     * @return array<string, mixed>|null Null when the session is sampled out.
     */
    public function build(Request $request, Response $response, TurnContext $context): ?array
    {
        $probe = $this->probe($request, $context);

        if (! Hasher::sampled($probe['session_key'], $this->sampleRate)) {
            return null;
        }

        $uaClass = UserAgentClass::classify($request->userAgent());
        $shape = RequestShape::build($request, $this->hasher, $this->headerOrder());
        $fingerprints = $this->proxyFingerprints($request);

        return [
            'v' => $probe['v'],
            'ts' => $probe['ts'],
            'turn_id' => $probe['turn_id'],
            'session_key' => $probe['session_key'],
            'peer_key' => $probe['peer_key'],
            'principal' => $probe['principal'],
            'verb' => $probe['verb'],
            'route' => $probe['route'],
            'status' => $response->getStatusCode(),
            'latency_ms' => round($context->latencyMs(), 1),
            'bytes_in' => (int) $request->headers->get('Content-Length', 0),
            'bytes_out' => $this->bytesOut($response),
            'req_shape' => $this->reducer->reduce($request->all()),
            'resp_shape' => $this->responseShape($response),
            'bound' => $this->bound($request),
            'validation_failed' => $context->validationFailed,
            'exception' => $context->exception,
            'auth_event' => $context->authEvent,
            'gate' => $context->gate,
            'ua_hash' => $this->hasher->uaHash((string) $request->userAgent()),
            'dropped_since_last' => $this->stats->pending(),
            // v2: identifiers and facts; leesided resolves actors from them.
            'surface' => $probe['surface'],
            'is_asset' => $this->surface->isAsset($request),
            'credential_kind' => $this->surface->credential($request)['kind'],
            'credential_hash' => $probe['credential_hash'],
            'credential_status' => $this->eventCredentialStatus($probe['credential_status'], $response->getStatusCode()),
            'tag_id' => $context->tagId,
            'tag_status' => $context->tagStatus,
            'shape_hash' => $shape['shape_hash'],
            'shape' => $shape['shape'],
            'flags' => Flags::compute(
                $request,
                $probe['surface'],
                $uaClass,
                $context->tagStatus,
                RequestShape::cookieNames($request),
                $this->sessionCookie,
                $this->tagCookie,
                $fingerprints['untrusted']
            ),
            'ja4' => $fingerprints['ja4'],
            'ja4t' => $fingerprints['ja4t'],
            'h2_fp' => $fingerprints['h2_fp'],
            // Socket transport only: log and array transports null this out.
            'ip' => $request->ip(),
            'ip_trust' => $this->ipTrust($request),
            'ua_class' => $uaClass,
            'remote_port' => $this->remotePort($request),
            'ts_ms' => intdiv($probe['ts'], 1000),
        ];
    }

    /**
     * Whether something vouched for the credential by the time Leeside looked:
     * a resolved principal (auth middleware ran ahead), a webhook signer set
     * by a verifying middleware ahead, or the app's CredentialVerifier.
     *
     * @return 'verified'|'unverified'|null  null without a credential
     */
    private function credentialStatus(Request $request, ?string $kind, ?string $value, string $principal): ?string
    {
        if ($kind === null || $value === null) {
            return null;
        }

        if ($principal !== 'anon') {
            return 'verified';
        }

        if ($kind === 'webhook_sig') {
            // A verifying middleware ahead of the gate named the signer; a
            // rejected signature carries the same kind but no signer.
            $signer = $request->attributes->get(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE);

            return is_string($signer) && $signer !== '' ? 'verified' : 'unverified';
        }

        if ($this->verifier !== null) {
            try {
                if ($this->verifier->verify($request, $kind, $value)) {
                    return 'verified';
                }
            } catch (Throwable) {
                // A failing verifier never vouches.
            }
        }

        return 'unverified';
    }

    /** An unverified credential that the app answered 401 or 403 was rejected. */
    private function eventCredentialStatus(?string $probeStatus, int $status): ?string
    {
        if ($probeStatus === 'unverified' && ($status === 401 || $status === 403)) {
            return 'rejected';
        }

        return $probeStatus;
    }

    /** How header order arrives on this host: received, reversed or unknown; set from deploy/header-order-check.sh. */
    private function headerOrder(): string
    {
        $order = strtolower((string) ($this->config?->get('leeside.fingerprint.header_order') ?? ''));

        return in_array($order, [RequestShape::ORDER_RECEIVED, RequestShape::ORDER_REVERSED], true)
            ? $order
            : RequestShape::ORDER_UNKNOWN;
    }

    /**
     * TLS/TCP/H2 fingerprints a trusted proxy may add. From any other hop
     * they are dropped and flagged, so a client cannot inject them.
     *
     * @return array{ja4: ?string, ja4t: ?string, h2_fp: ?string, untrusted: bool}
     */
    private function proxyFingerprints(Request $request): array
    {
        $headers = $this->config?->get('leeside.fingerprint.proxy_headers')
            ?? ['ja4' => 'X-Leeside-JA4', 'ja4t' => 'X-Leeside-JA4T', 'h2_fp' => 'X-Leeside-H2'];
        $trusted = $request->isFromTrustedProxy();
        $out = ['ja4' => null, 'ja4t' => null, 'h2_fp' => null, 'untrusted' => false];

        foreach (['ja4', 'ja4t', 'h2_fp'] as $field) {
            $value = $request->headers->get((string) ($headers[$field] ?? ''));
            if (! is_string($value) || $value === '') {
                continue;
            }
            if ($trusted) {
                $out[$field] = substr($value, 0, 128);
            } else {
                $out['untrusted'] = true;
            }
        }

        return $out;
    }

    /**
     * `forwarded` only when a trusted proxy resolved the client address: the
     * address Laravel reports then differs from the one that connected.
     */
    private function ipTrust(Request $request): string
    {
        try {
            $direct = (string) $request->server->get('REMOTE_ADDR', '');

            return $request->ip() !== null && $request->ip() !== $direct ? 'forwarded' : 'direct';
        } catch (Throwable) {
            return 'direct';
        }
    }

    private function remotePort(Request $request): ?int
    {
        $port = $request->server->get('REMOTE_PORT');

        return is_numeric($port) ? (int) $port : null;
    }

    private function sessionId(Request $request): ?string
    {
        try {
            if (! $request->hasSession()) {
                return null;
            }

            // No isStarted() check: StartSession saves (and unstarts) the
            // session on the way out, so it is always unstarted in terminate().
            $id = $request->getSession()->getId();

            return $id !== '' ? $id : null;
        } catch (Throwable) {
            return null;
        }
    }

    private function principal(): string
    {
        foreach ($this->guards as $guard) {
            try {
                $resolved = $this->auth->guard($guard);
            } catch (Throwable) {
                continue;
            }

            if (! is_object($resolved) || ! method_exists($resolved, 'hasUser')) {
                continue;
            }

            try {
                if (! $resolved->hasUser()) {
                    continue;
                }

                $user = $resolved->user();
            } catch (Throwable) {
                continue;
            }

            if ($user === null) {
                continue;
            }

            return $this->hasher->principal((string) $user->getAuthIdentifier());
        }

        return 'anon';
    }

    private function bytesOut(Response $response): int
    {
        if ($response instanceof StreamedResponse) {
            return -1;
        }

        $content = $response->getContent();
        if ($content === false) {
            $length = $response->headers->get('Content-Length');

            return $length !== null ? (int) $length : -1;
        }

        return strlen($content);
    }

    private function responseShape(Response $response): string
    {
        if ($response instanceof StreamedResponse) {
            return 'stream';
        }

        if ($response instanceof BinaryFileResponse) {
            return 'file';
        }

        if ($response instanceof RedirectResponse) {
            return 'redirect';
        }

        if ($response->isRedirection() && $response->headers->has('Location')) {
            return 'redirect';
        }

        $content = $response->getContent();
        if ($content === false || $content === '') {
            return 'empty';
        }

        $type = strtolower(trim(explode(';', (string) $response->headers->get('Content-Type', ''))[0]));

        if ($response instanceof JsonResponse || str_ends_with($type, 'json') || str_contains($type, '+json')) {
            if (strlen($content) <= $this->maxResponseBytes) {
                $decoded = json_decode($content, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    return $this->reducer->reduce($decoded);
                }
            }

            return $type !== '' ? $type : 'application/json';
        }

        return match ($type) {
            '', 'text/html' => 'html',
            'text/plain' => 'text',
            default => $type,
        };
    }

    /** @return array<int, array<string, string>> */
    private function bound(Request $request): array
    {
        $route = $request->route();
        if ($route === null) {
            return [];
        }

        $bound = [];
        foreach ($route->parameters() as $name => $value) {
            if ($value instanceof UrlRoutable) {
                $bound[] = ['model' => class_basename($value), 'id_hash' => $this->hasher->idHash((string) $value->getRouteKey())];
            } elseif ($value instanceof UnitEnum) {
                $key = $value instanceof BackedEnum ? (string) $value->value : $value->name;
                $bound[] = ['model' => class_basename($value), 'id_hash' => $this->hasher->idHash($key)];
            } elseif (is_object($value)) {
                $bound[] = ['model' => class_basename($value), 'id_hash' => $this->hasher->idHash((string) spl_object_id($value))];
            } else {
                $bound[] = ['param' => (string) $name, 'id_hash' => $this->hasher->idHash((string) $value)];
            }
        }

        return $bound;
    }
}
