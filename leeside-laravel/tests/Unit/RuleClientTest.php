<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Check\ArrayRuleClient;
use Leeside\Laravel\Check\NullRuleClient;
use Leeside\Laravel\Check\UnixRuleClient;
use Leeside\Laravel\Check\Verdict;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class RuleClientTest extends TestCase
{
    public function test_null_allows(): void
    {
        $verdict = (new NullRuleClient)->check(['v' => 1]);

        $this->assertSame('allow', $verdict->action);
    }

    public function test_array_records_probes_and_returns_fixed_verdict(): void
    {
        $client = new ArrayRuleClient(new Verdict('block', 'enforce', 'r', 10));

        $verdict = $client->check(['route' => 'portal.login']);

        $this->assertSame('block', $verdict->action);
        $this->assertSame([['route' => 'portal.login']], $client->probes);
    }

    public function test_array_defaults_to_allow_and_supports_callables(): void
    {
        $client = new ArrayRuleClient;

        $this->assertSame('allow', $client->check([])->action);

        $client = new ArrayRuleClient(fn (array $probe) => new Verdict('watch', 'shadow', $probe['route'] ?? null));

        $this->assertSame('watch', $client->check(['route' => 'x'])->action);
        $this->assertSame('x', $client->check(['route' => 'x'])->rule);
    }

    public function test_array_fails_open(): void
    {
        $throwing = new ArrayRuleClient(function () {
            throw new RuntimeException('boom');
        });
        $this->assertSame('allow', $throwing->check([])->action);

        $junk = new ArrayRuleClient(fn () => 'not-a-verdict');
        $this->assertSame('allow', $junk->check([])->action);
    }

    public function test_unix_round_trip(): void
    {
        $run = $this->startServer('verdict', '{"action":"rate_limit","mode":"enforce","rule":"r","retry_after":30}');

        try {
            $verdict = (new UnixRuleClient($run['path'], 2000))->check(['v' => 1]);

            $this->assertSame('rate_limit', $verdict->action);
            $this->assertSame('enforce', $verdict->mode);
            $this->assertSame('r', $verdict->rule);
            $this->assertSame(30, $verdict->retryAfter);
        } finally {
            $this->stopServer($run);
        }
    }

    public function test_unix_allows_on_bad_json(): void
    {
        $run = $this->startServer('badjson');

        try {
            $this->assertSame('allow', (new UnixRuleClient($run['path'], 2000))->check([])->action);
        } finally {
            $this->stopServer($run);
        }
    }

    public function test_unix_allows_when_server_closes(): void
    {
        $run = $this->startServer('close');

        try {
            $this->assertSame('allow', (new UnixRuleClient($run['path'], 2000))->check([])->action);
        } finally {
            $this->stopServer($run);
        }
    }

    public function test_unix_allows_on_read_timeout(): void
    {
        $run = $this->startServer('slow', '500');

        try {
            $start = microtime(true);
            $verdict = (new UnixRuleClient($run['path'], 2))->check([]);
            $elapsedMs = (microtime(true) - $start) * 1000;

            $this->assertSame('allow', $verdict->action);
            $this->assertLessThan(500, $elapsedMs);
        } finally {
            $this->stopServer($run);
        }
    }

    public function test_unix_allows_when_nobody_listens(): void
    {
        $client = new UnixRuleClient(sys_get_temp_dir().'/leeside-check-missing-'.uniqid().'.sock', 2);

        $this->assertSame('allow', $client->check([])->action);
        $this->assertSame('allow', $client->check([])->action);
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
