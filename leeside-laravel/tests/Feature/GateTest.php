<?php

namespace Leeside\Laravel\Tests\Feature;

use Leeside\Laravel\Check\ArrayRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Check\UnixRuleClient;
use Leeside\Laravel\Check\Verdict;

class GateTest extends SampleAppTestCase
{
    private function scriptVerdict(Verdict $verdict): void
    {
        $this->rules = new ArrayRuleClient($verdict);
        $this->app->instance(RuleClient::class, $this->rules);
    }

    /** @return array{phone: string, otp: string} */
    private function credentials(): array
    {
        return ['phone' => '0123456789', 'otp' => '123456'];
    }

    public function test_probe_is_a_pre_auth_snapshot(): void
    {
        $this->postJson('/portal/login', $this->credentials())->assertOk();

        $this->assertCount(1, $this->rules->probes);
        $probe = $this->rules->probes[0];

        $this->assertSame(['v', 'ts', 'verb', 'route', 'surface', 'session_key', 'peer_key', 'principal', 'credential_hash'], array_keys($probe));
        $this->assertSame('portal.login', $probe['route']);
        $this->assertSame('POST', $probe['verb']);
        $this->assertSame('anon', $probe['principal']);
        $this->assertNotSame('anon', $this->lastEvent()['principal']);
    }

    public function test_block_returns_403_html(): void
    {
        $this->scriptVerdict(new Verdict('block', 'enforce', 'portal-otp-burst'));

        $response = $this->post('/portal/login', $this->credentials());
        $response->assertForbidden();
        $this->assertSame('Forbidden', $response->getContent());

        foreach (array_keys($response->headers->all()) as $name) {
            $this->assertStringStartsNotWith('x-leeside', strtolower($name));
        }

        $event = $this->lastEvent();

        $this->assertSame(403, $event['status']);
        $this->assertSame('portal.login', $event['route']);
        $this->assertSame(
            ['action' => 'block', 'mode' => 'enforce', 'rule' => 'portal-otp-burst', 'applied' => true],
            $event['gate']
        );
    }

    public function test_block_returns_403_json(): void
    {
        $this->scriptVerdict(new Verdict('block', 'enforce', 'portal-otp-burst'));

        $this->postJson('/portal/login', $this->credentials())
            ->assertForbidden()
            ->assertExactJson(['message' => 'Forbidden']);

        $this->assertSame('{message:str:9}', $this->lastEvent()['resp_shape']);
    }

    public function test_rate_limit_returns_429_with_retry_after(): void
    {
        $this->scriptVerdict(new Verdict('rate_limit', 'enforce', 'r', 30));

        $response = $this->postJson('/portal/login', $this->credentials());
        $response->assertStatus(429)->assertExactJson(['message' => 'Too Many Requests']);
        $this->assertSame('30', $response->headers->get('Retry-After'));

        $event = $this->lastEvent();

        $this->assertSame(429, $event['status']);
        $this->assertSame(
            ['action' => 'rate_limit', 'mode' => 'enforce', 'rule' => 'r', 'applied' => true],
            $event['gate']
        );
    }

    public function test_rate_limit_without_retry_after_defaults_to_one(): void
    {
        $this->scriptVerdict(new Verdict('rate_limit', 'enforce', 'r'));

        $response = $this->postJson('/portal/login', $this->credentials());
        $response->assertStatus(429);
        $this->assertSame('1', $response->headers->get('Retry-After'));
    }

    public function test_challenge_sets_attribute_and_continues(): void
    {
        $this->scriptVerdict(new Verdict('challenge', 'enforce', 'step-up-otp'));

        $this->getJson('/challenge-demo')
            ->assertOk()
            ->assertExactJson(['challenge' => 'step-up-otp']);

        $this->assertSame(
            ['action' => 'challenge', 'mode' => 'enforce', 'rule' => 'step-up-otp', 'applied' => true],
            $this->lastEvent()['gate']
        );
    }

    public function test_challenge_without_rule_still_signals(): void
    {
        $this->scriptVerdict(new Verdict('challenge', 'enforce'));

        $this->getJson('/challenge-demo')
            ->assertOk()
            ->assertExactJson(['challenge' => 'challenge']);
    }

    /** @return array<string, array{string, string}> */
    public static function passiveVerdicts(): array
    {
        return [
            'allow in enforce' => ['allow', 'enforce'],
            'log in enforce' => ['log', 'enforce'],
            'watch in enforce' => ['watch', 'enforce'],
            'block in shadow' => ['block', 'shadow'],
            'block in monitor' => ['block', 'monitor'],
            'rate_limit in shadow' => ['rate_limit', 'shadow'],
            'challenge in monitor' => ['challenge', 'monitor'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('passiveVerdicts')]
    public function test_non_enforcing_verdicts_change_nothing(string $action, string $mode): void
    {
        $this->scriptVerdict(new Verdict($action, $mode, 'r'));

        $this->postJson('/portal/login', $this->credentials())
            ->assertOk()
            ->assertExactJson(['ok' => true]);

        $this->assertSame(
            ['action' => $action, 'mode' => $mode, 'rule' => 'r', 'applied' => false],
            $this->lastEvent()['gate']
        );

        $this->getJson('/challenge-demo')->assertExactJson(['challenge' => null]);
    }

    public function test_check_disabled_skips_probe(): void
    {
        $this->app['config']->set('leeside.check.enabled', false);

        $this->postJson('/portal/login', $this->credentials())->assertOk();

        $this->assertSame([], $this->rules->probes);
        $this->assertNull($this->lastEvent()['gate']);
    }

    public function test_kill_switch_skips_probe_and_event(): void
    {
        $this->app['config']->set('leeside.enabled', false);

        $this->postJson('/portal/login', $this->credentials())->assertOk();

        $this->assertSame([], $this->rules->probes);
        $this->assertSame([], $this->transport->events);
    }

    public function test_read_timeout_fails_open(): void
    {
        $run = $this->startServer('slow', '500');

        try {
            $this->app->instance(RuleClient::class, new UnixRuleClient($run['path'], 2));

            $this->postJson('/portal/login', $this->credentials())->assertOk();

            $this->assertSame(
                ['action' => 'allow', 'mode' => 'monitor', 'rule' => null, 'applied' => false],
                $this->lastEvent()['gate']
            );
        } finally {
            $this->stopServer($run);
        }
    }

    public function test_missing_socket_fails_open(): void
    {
        $this->app->instance(
            RuleClient::class,
            new UnixRuleClient(sys_get_temp_dir().'/leeside-gate-missing-'.uniqid().'.sock', 2)
        );

        $this->postJson('/portal/login', $this->credentials())->assertOk();

        $this->assertSame(
            ['action' => 'allow', 'mode' => 'monitor', 'rule' => null, 'applied' => false],
            $this->lastEvent()['gate']
        );
    }

    /**
     * @return array{path: string, process: resource}
     */
    private function startServer(string $mode, string $arg = '{}'): array
    {
        $path = sys_get_temp_dir().'/leeside-check-'.uniqid().'.sock';
        $process = proc_open(
            [PHP_BINARY, __DIR__.'/../Fixtures/check-server.php', $path, $mode, $arg],
            [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        $this->assertIsResource($process);

        $deadline = microtime(true) + 5;
        while (! file_exists($path) && microtime(true) < $deadline) {
            usleep(10000);
        }
        $this->assertFileExists($path, 'check fixture server did not bind in time');

        return ['path' => $path, 'process' => $process];
    }

    /** @param  array{path: string, process: resource}  $run */
    private function stopServer(array $run): void
    {
        proc_close($run['process']);
        @unlink($run['path']);
    }
}
