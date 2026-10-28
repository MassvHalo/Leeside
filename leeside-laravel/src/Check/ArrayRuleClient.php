<?php

namespace Leeside\Laravel\Check;

use Throwable;

class ArrayRuleClient implements RuleClient
{
    /** @var array<int, array<string, mixed>> */
    public array $probes = [];
    private mixed $handler;

    /** @param  Verdict|callable(array<string, mixed>): Verdict|null  $handler */
    public function __construct(Verdict|callable|null $handler = null)
    {
        $this->handler = $handler ?? Verdict::allow();
    }

    public function check(array $probe): Verdict
    {
        $this->probes[] = $probe;

        if ($this->handler instanceof Verdict) {
            return $this->handler;
        }

        try {
            $verdict = ($this->handler)($probe);
        } catch (Throwable) {
            return Verdict::allow();
        }

        return $verdict instanceof Verdict ? $verdict : Verdict::allow();
    }
}
