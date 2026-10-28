<?php

namespace Leeside\Laravel\Middleware;

use Closure;
use Illuminate\Config\Repository as Config;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Check\Verdict;
use Leeside\Laravel\Event\RouteName;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Event\TurnEventFactory;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Throwable;

class GateTurn
{
    public function __construct(
        private readonly TurnContext $context,
        private readonly TurnEventFactory $factory,
        private readonly RuleClient $client,
        private readonly Config $config,
    ) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $route = $request->route();
        $this->context->recordRoute(RouteName::fromRoute($route));

        if (! $this->config->get('leeside.enabled', true)) {
            return $next($request);
        }

        if (! $this->config->get('leeside.check.enabled', true)) {
            return $next($request);
        }

        if (RouteName::isIgnored($route, (array) $this->config->get('leeside.ignore', []))) {
            return $next($request);
        }

        try {
            $verdict = $this->client->check($this->factory->probe($request, $this->context));
        } catch (Throwable) {
            $verdict = Verdict::allow();
        }

        if (! $verdict instanceof Verdict) {
            $verdict = Verdict::allow();
        }

        $applied = false;
        $denial = null;

        if ($verdict->mode === 'enforce') {
            if ($verdict->action === 'block') {
                $applied = true;
                $denial = $this->deny($request, 403, 'Forbidden');
            } elseif ($verdict->action === 'rate_limit') {
                $applied = true;
                $denial = $this->deny($request, 429, 'Too Many Requests', [
                    'Retry-After' => (string) max(1, $verdict->retryAfter),
                ]);
            } elseif ($verdict->action === 'challenge') {
                $applied = true;
                $request->attributes->set('leeside.challenge', $verdict->rule ?? 'challenge');
            }
        }

        $this->context->recordGate($verdict->action, $verdict->mode, $verdict->rule, $applied);

        return $denial ?? $next($request);
    }

    private function deny(Request $request, int $status, string $message, array $headers = []): SymfonyResponse
    {
        if ($request->expectsJson()) {
            return new JsonResponse(['message' => $message], $status, $headers);
        }

        return new Response($message, $status, $headers);
    }
}
