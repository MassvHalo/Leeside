<?php

namespace Leeside\Laravel\Event;

use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

class TurnContext
{
    /** Integer microseconds since the epoch; the wire `ts` on v2 probes and events. */
    public ?int $tsUs = null;
    public ?int $hrtime = null;
    /** 32 hex (16 random bytes) minted per request: the probe/event join key and the seed of actor ids. */
    public ?string $turnId = null;
    public ?string $route = null;
    public ?string $exception = null;
    /** @var string[]|null */
    public ?array $validationFailed = null;
    public ?string $authEvent = null;
    /** @var array{action: string, mode: string, rule: ?string, applied: bool}|null */
    public ?array $gate = null;
    /** valid | absent | malformed | bad_mac | issued; null when the tag middleware did not run */
    public ?string $tagStatus = null;
    /** 16-hex keyed hash of the tag id the client carries after this turn */
    public ?string $tagId = null;

    public function begin(): void
    {
        $this->tsUs = (int) (microtime(true) * 1_000_000);
        $this->hrtime = hrtime(true);
        $this->turnId = bin2hex(random_bytes(16));
        $this->route = null;
        $this->exception = null;
        $this->validationFailed = null;
        $this->authEvent = null;
        $this->gate = null;
        $this->tagStatus = null;
        $this->tagId = null;
    }

    public function latencyMs(): float
    {
        if ($this->hrtime === null) {
            return 0.0;
        }

        return (hrtime(true) - $this->hrtime) / 1e6;
    }

    public function recordRoute(string $route): void
    {
        $this->route = $route;
    }

    public function recordException(Throwable $exception): void
    {
        $cause = $exception;
        if ($cause instanceof HttpExceptionInterface && $cause->getPrevious() !== null) {
            $cause = $cause->getPrevious();
        }

        $this->exception = class_basename($cause);

        if ($cause instanceof ValidationException) {
            $this->validationFailed = array_keys($cause->errors());
        }
    }

    public function recordAuthEvent(string $event): void
    {
        $this->authEvent = $event;
    }

    public function recordTag(string $status, ?string $idHash): void
    {
        $this->tagStatus = $status;
        $this->tagId = $idHash;
    }

    public function recordGate(string $action, string $mode, ?string $rule, bool $applied): void
    {
        $this->gate = ['action' => $action, 'mode' => $mode, 'rule' => $rule, 'applied' => $applied];
    }
}
