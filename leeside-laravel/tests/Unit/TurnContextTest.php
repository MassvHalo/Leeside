<?php

namespace Leeside\Laravel\Tests\Unit;

use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Translation\ArrayLoader;
use Illuminate\Translation\Translator;
use Illuminate\Validation\ValidationException;
use Illuminate\Validation\Validator;
use Leeside\Laravel\Event\TurnContext;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

class TurnContextTest extends TestCase
{
    public function test_begin_stamps_clock_and_resets_state(): void
    {
        $context = new TurnContext;
        $context->recordRoute('portal.login');
        $context->recordException(new RuntimeException('boom'));
        $context->recordAuthEvent('login_failed');
        $context->recordGate('block', 'enforce', 'rule', true);

        $context->begin();

        $this->assertIsFloat($context->ts);
        $this->assertIsInt($context->hrtime);
        $this->assertNull($context->route);
        $this->assertNull($context->exception);
        $this->assertNull($context->validationFailed);
        $this->assertNull($context->authEvent);
        $this->assertNull($context->gate);
        $this->assertGreaterThanOrEqual(0.0, $context->latencyMs());
    }

    public function test_latency_before_begin_is_zero(): void
    {
        $this->assertSame(0.0, (new TurnContext)->latencyMs());
    }

    public function test_records_exception_basename_only(): void
    {
        $context = new TurnContext;
        $context->recordException(new RuntimeException('something secret'));

        $this->assertSame('RuntimeException', $context->exception);
        $this->assertNull($context->validationFailed);
    }

    public function test_unwraps_one_http_exception_level(): void
    {
        $context = new TurnContext;
        $context->recordException(new NotFoundHttpException('not here', new ModelNotFoundException));

        $this->assertSame('ModelNotFoundException', $context->exception);
    }

    public function test_records_validation_keys_never_messages(): void
    {
        $validator = new Validator(new Translator(new ArrayLoader, 'en'), [], ['otp' => 'required']);
        $validator->fails();

        $context = new TurnContext;
        $context->recordException(new ValidationException($validator));

        $this->assertSame('ValidationException', $context->exception);
        $this->assertSame(['otp'], $context->validationFailed);
    }

    public function test_last_auth_event_wins(): void
    {
        $context = new TurnContext;
        $context->recordAuthEvent('login');
        $context->recordAuthEvent('logout');

        $this->assertSame('logout', $context->authEvent);
    }

    public function test_records_gate_verdict(): void
    {
        $context = new TurnContext;
        $context->recordGate('rate_limit', 'shadow', 'portal-otp-burst', false);

        $this->assertSame(
            ['action' => 'rate_limit', 'mode' => 'shadow', 'rule' => 'portal-otp-burst', 'applied' => false],
            $context->gate
        );
    }
}
