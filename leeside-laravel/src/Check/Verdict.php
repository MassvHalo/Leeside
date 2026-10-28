<?php

namespace Leeside\Laravel\Check;

class Verdict
{
    private const ACTIONS = ['allow', 'log', 'watch', 'rate_limit', 'challenge', 'block'];
    private const MODES = ['monitor', 'shadow', 'enforce'];

    public function __construct(
        public readonly string $action,
        public readonly string $mode,
        public readonly ?string $rule = null,
        public readonly int $retryAfter = 0,
    ) {}

    public static function allow(): self
    {
        return new self('allow', 'monitor');
    }

    /** Unknown actions decode to allow, unknown modes to monitor. */
    public static function fromArray(mixed $data): self
    {
        if (! is_array($data)) {
            return self::allow();
        }

        $action = $data['action'] ?? 'allow';
        if (! in_array($action, self::ACTIONS, true)) {
            $action = 'allow';
        }

        $mode = $data['mode'] ?? 'monitor';
        if (! in_array($mode, self::MODES, true)) {
            $mode = 'monitor';
        }

        $rule = $data['rule'] ?? null;
        if (! is_string($rule) || $rule === '') {
            $rule = null;
        }

        return new self($action, $mode, $rule, max(0, (int) ($data['retry_after'] ?? 0)));
    }
}
