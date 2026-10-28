<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Check\Verdict;
use PHPUnit\Framework\TestCase;

class VerdictTest extends TestCase
{
    public function test_decodes_full_verdict(): void
    {
        $verdict = Verdict::fromArray([
            'action' => 'block', 'mode' => 'enforce',
            'rule' => 'portal-otp-burst', 'retry_after' => 30,
        ]);

        $this->assertSame('block', $verdict->action);
        $this->assertSame('enforce', $verdict->mode);
        $this->assertSame('portal-otp-burst', $verdict->rule);
        $this->assertSame(30, $verdict->retryAfter);
    }

    public function test_unknown_values_decode_to_allow_and_monitor(): void
    {
        $verdict = Verdict::fromArray(['action' => 'nuke', 'mode' => 'strict']);

        $this->assertSame('allow', $verdict->action);
        $this->assertSame('monitor', $verdict->mode);
    }

    public function test_missing_values_decode_to_allow_and_monitor(): void
    {
        $verdict = Verdict::fromArray([]);

        $this->assertSame('allow', $verdict->action);
        $this->assertSame('monitor', $verdict->mode);
        $this->assertNull($verdict->rule);
        $this->assertSame(0, $verdict->retryAfter);
    }

    public function test_non_array_decodes_to_allow(): void
    {
        $this->assertSame('allow', Verdict::fromArray(null)->action);
        $this->assertSame('allow', Verdict::fromArray('block')->action);
        $this->assertSame('allow', Verdict::fromArray(42)->action);
    }

    public function test_rule_and_retry_after_are_sanitized(): void
    {
        $verdict = Verdict::fromArray(['action' => 'rate_limit', 'mode' => 'enforce', 'rule' => '', 'retry_after' => -5]);

        $this->assertNull($verdict->rule);
        $this->assertSame(0, $verdict->retryAfter);

        $verdict = Verdict::fromArray(['rule' => ['not-a-string'], 'retry_after' => '30']);

        $this->assertNull($verdict->rule);
        $this->assertSame(30, $verdict->retryAfter);
    }

    public function test_allow_helper(): void
    {
        $verdict = Verdict::allow();

        $this->assertSame('allow', $verdict->action);
        $this->assertSame('monitor', $verdict->mode);
    }
}
