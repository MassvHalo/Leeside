<?php

namespace Leeside\Laravel\Tests\Feature;

use Illuminate\Support\Facades\Artisan;
use Leeside\Laravel\Check\UnixRuleClient;
use Leeside\Laravel\Tests\TestCase;
use Leeside\Laravel\Transport\UnixDatagramTransport;
use Symfony\Component\Console\Output\BufferedOutput;

class TapCommandTest extends TestCase
{
    private string $events;
    private string $check;
    private string $out;

    protected function setUp(): void
    {
        parent::setUp();

        if (! function_exists('pcntl_fork') || ! function_exists('socket_create')) {
            $this->markTestSkipped('pcntl and ext-sockets required');
        }

        $tag = uniqid();
        $this->events = sys_get_temp_dir()."/leeside-tap-events-{$tag}.sock";
        $this->check = sys_get_temp_dir()."/leeside-tap-check-{$tag}.sock";
        $this->out = sys_get_temp_dir()."/leeside-tap-out-{$tag}.txt";

        $this->app['config']->set('leeside.events_socket', $this->events);
        $this->app['config']->set('leeside.check.socket', $this->check);
    }

    protected function tearDown(): void
    {
        @unlink($this->events ?? '');
        @unlink($this->check ?? '');
        @unlink($this->out ?? '');

        parent::tearDown();
    }

    public function test_prints_pretty_event(): void
    {
        $pid = $this->forkTap(['--once' => true]);

        $this->waitForFile($this->events);
        $this->assertTrue((new UnixDatagramTransport($this->events))->send(['v' => 1, 'route' => 'home']));
        $this->waitForPid($pid);

        $output = file_get_contents($this->out);
        $this->assertStringContainsString('"route": "home"', $output);
        $this->assertStringContainsString('"v": 1', $output);
    }

    public function test_raw_prints_ndjson(): void
    {
        $pid = $this->forkTap(['--once' => true, '--raw' => true]);

        $this->waitForFile($this->events);
        $this->assertTrue((new UnixDatagramTransport($this->events))->send(['v' => 1, 'route' => 'home']));
        $this->waitForPid($pid);

        $this->assertStringContainsString('{"v":1,"route":"home"}', file_get_contents($this->out));
    }

    public function test_gate_answers_listed_routes_and_allows_otherwise(): void
    {
        $pid = $this->forkTap([
            '--once' => true, '--gate' => true,
            '--action' => 'block', '--mode' => 'enforce', '--route' => ['portal.login'],
        ]);

        $this->waitForFile($this->check);
        $verdict = (new UnixRuleClient($this->check, 2000))->check($this->probe('portal.login'));
        $this->waitForPid($pid);

        $this->assertSame('block', $verdict->action);
        $this->assertSame('enforce', $verdict->mode);

        $pid = $this->forkTap([
            '--once' => true, '--gate' => true,
            '--action' => 'block', '--mode' => 'enforce', '--route' => ['portal.login'],
        ]);

        $this->waitForFile($this->check);
        $verdict = (new UnixRuleClient($this->check, 2000))->check($this->probe('home'));
        $this->waitForPid($pid);

        $this->assertSame('allow', $verdict->action);
    }

    /** @return array<string, mixed> */
    private function probe(string $route): array
    {
        return [
            'v' => 1, 'ts' => microtime(true), 'verb' => 'POST', 'route' => $route,
            'session_key' => str_repeat('a', 16), 'peer_key' => str_repeat('b', 16), 'principal' => 'anon',
        ];
    }

    /** @param  array<string, mixed>  $options */
    private function forkTap(array $options): int
    {
        $out = $this->out;
        $pid = pcntl_fork();
        $this->assertNotSame(-1, $pid, 'fork failed');

        if ($pid === 0) {
            $buffer = new BufferedOutput;
            $code = 1;
            try {
                $code = Artisan::call('leeside:tap', $options, $buffer);
            } finally {
                file_put_contents($out, "exit:{$code}\n".$buffer->fetch());
            }
            exit($code);
        }

        return $pid;
    }

    private function waitForFile(string $path): void
    {
        $deadline = microtime(true) + 10;
        while (! file_exists($path) && microtime(true) < $deadline) {
            usleep(10000);
        }

        $this->assertFileExists($path, 'tap did not bind in time: '.@file_get_contents($this->out));
    }

    private function waitForPid(int $pid): void
    {
        $deadline = microtime(true) + 10;
        do {
            $done = pcntl_waitpid($pid, $status, WNOHANG);
            if ($done === $pid) {
                $this->assertSame(0, pcntl_wexitstatus($status), 'tap output: '.@file_get_contents($this->out));

                return;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);
        $this->fail('tap did not exit in time: '.@file_get_contents($this->out));
    }
}
