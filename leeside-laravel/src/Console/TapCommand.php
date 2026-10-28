<?php

namespace Leeside\Laravel\Console;

use Illuminate\Console\Command;
use Socket;
use Symfony\Component\Console\Output\OutputInterface;

class TapCommand extends Command
{
    protected $signature = 'leeside:tap
        {--raw : Print each event as a single NDJSON line}
        {--gate : Also serve the check socket with scripted verdicts}
        {--action=allow : Verdict action for listed routes}
        {--mode=monitor : Verdict mode for listed routes}
        {--route=* : Routes the verdict applies to (repeatable)}
        {--once : Exit after the first event or check}';

    protected $description = 'Print turn events from the events socket (stand-in for leesided).';

    public function handle(): int
    {
        if (! function_exists('socket_create')) {
            $this->error('leeside:tap requires ext-sockets.');

            return 1;
        }

        $eventsPath = $this->socketPath((string) config('leeside.events_socket'));
        $events = $this->bindDatagram($eventsPath);
        if ($events === null) {
            return 1;
        }

        $check = null;
        $checkPath = null;
        if ($this->option('gate')) {
            $checkPath = $this->socketPath((string) config('leeside.check.socket'));
            $check = $this->bindStream($checkPath);
            if ($check === null) {
                socket_close($events);
                @unlink($eventsPath);

                return 1;
            }
        }

        fwrite(STDERR, 'tapping '.$eventsPath.($check !== null ? ' + gate '.$checkPath : '').PHP_EOL);

        $stop = false;
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            $handler = function () use (&$stop) {
                $stop = true;
            };
            pcntl_signal(SIGINT, $handler);
            pcntl_signal(SIGTERM, $handler);
        }

        $raw = (bool) $this->option('raw');
        $once = (bool) $this->option('once');
        $routes = (array) $this->option('route');
        $verdictLine = json_encode(['action' => $this->option('action'), 'mode' => $this->option('mode')])."\n";
        $allowLine = '{"action":"allow","mode":"monitor"}'."\n";

        try {
            while (! $stop) {
                $read = [$events];
                if ($check !== null) {
                    $read[] = $check;
                }

                $write = null;
                $except = null;
                $ready = @socket_select($read, $write, $except, 1);
                if ($ready === false || $ready < 1) {
                    continue;
                }

                foreach ($read as $socket) {
                    if ($socket === $events) {
                        $bytes = @socket_recvfrom($events, $payload, 65536, 0, $peer);
                        if ($bytes === false || $bytes === 0) {
                            continue;
                        }

                        $this->printEvent($payload, $raw);
                    } else {
                        $client = @socket_accept($check);
                        if ($client === false) {
                            continue;
                        }

                        $this->answerCheck($client, $routes, $verdictLine, $allowLine);
                    }

                    if ($once) {
                        $stop = true;

                        break;
                    }
                }
            }
        } finally {
            socket_close($events);
            @unlink($eventsPath);

            if ($check !== null) {
                socket_close($check);
                @unlink((string) $checkPath);
            }
        }

        return 0;
    }

    private function printEvent(string $payload, bool $raw): void
    {
        if (! $raw) {
            $decoded = json_decode($payload, true);
            if (is_array($decoded)) {
                $payload = (string) json_encode(
                    $decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
                );
            }
        }

        $this->output->writeln($payload, OutputInterface::OUTPUT_RAW);
    }

    /** @param  string[]  $routes */
    private function answerCheck(Socket $client, array $routes, string $verdictLine, string $allowLine): void
    {
        socket_set_option($client, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 2, 'usec' => 0]);

        $request = '';
        while (! str_contains($request, "\n") && strlen($request) <= 65536) {
            $chunk = @socket_read($client, 4096);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $request .= $chunk;
        }

        $probe = json_decode($request, true);
        $route = is_array($probe) ? ($probe['route'] ?? null) : null;

        @socket_write($client, in_array($route, $routes, true) ? $verdictLine : $allowLine);
        socket_close($client);
    }

    private function bindDatagram(string $path): ?Socket
    {
        if (! $this->preparePath($path)) {
            return null;
        }

        $socket = @socket_create(AF_UNIX, SOCK_DGRAM, 0);
        if ($socket === false) {
            $this->error('cannot create datagram socket.');

            return null;
        }

        @unlink($path);
        if (! @socket_bind($socket, $path)) {
            $this->error("cannot bind {$path}.");
            socket_close($socket);

            return null;
        }

        return $socket;
    }

    private function bindStream(string $path): ?Socket
    {
        if (! $this->preparePath($path)) {
            return null;
        }

        $socket = @socket_create(AF_UNIX, SOCK_STREAM, 0);
        if ($socket === false) {
            $this->error('cannot create stream socket.');

            return null;
        }

        @unlink($path);
        if (! @socket_bind($socket, $path) || ! @socket_listen($socket, 128)) {
            $this->error("cannot bind {$path}.");
            socket_close($socket);

            return null;
        }

        return $socket;
    }

    private function preparePath(string $path): bool
    {
        if ($path === '') {
            $this->error('socket path is empty; check the leeside config.');

            return false;
        }

        $dir = dirname($path);
        if (! is_dir($dir) && ! @mkdir($dir, 0777, true)) {
            $this->error("cannot create directory {$dir}.");

            return false;
        }

        return true;
    }

    private function socketPath(string $path): string
    {
        if ($path === '' || str_starts_with($path, '/')) {
            return $path;
        }

        return $this->laravel->basePath($path);
    }
}
