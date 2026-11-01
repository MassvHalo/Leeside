<?php

namespace Leeside\Laravel\Middleware;

use Closure;
use Illuminate\Config\Repository as Config;
use Illuminate\Http\Request;
use Leeside\Laravel\Event\RouteName;
use Leeside\Laravel\Event\TurnContext;
use Leeside\Laravel\Event\TurnEventFactory;
use Leeside\Laravel\Stats;
use Leeside\Laravel\Transport\Transport;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class CaptureTurn
{
    public function __construct(
        private readonly TurnContext $context,
        private readonly TurnEventFactory $factory,
        private readonly Transport $transport,
        private readonly Stats $stats,
        private readonly Config $config,
    ) {}

    public function handle(Request $request, Closure $next): mixed
    {
        $this->context->begin();

        return $next($request);
    }

    public function terminate(Request $request, Response $response): void
    {
        try {
            if (! $this->config->get('leeside.enabled', true)) {
                return;
            }

            if ($this->context->tsUs === null) {
                return;
            }

            if (RouteName::isIgnored($request->route(), (array) $this->config->get('leeside.ignore', []))) {
                return;
            }

            $event = $this->factory->build($request, $response, $this->context);
            if ($event === null) {
                return;
            }

            if ($this->transport->send($event)) {
                $this->stats->acknowledge($event['dropped_since_last']);
            } else {
                $this->stats->dropped();
            }
        } catch (Throwable) {
            // Capture must never break the response.
        }
    }
}
