<?php

namespace Leeside\Laravel\Check;

use Throwable;

class UnixRuleClient implements RuleClient
{
    private float $skipUntil = 0.0;

    public function __construct(
        private readonly string $path,
        private readonly int $timeoutMs = 2,
    ) {}

    public function check(array $probe): Verdict
    {
        try {
            $now = microtime(true);
            if ($now < $this->skipUntil) {
                return Verdict::allow();
            }

            $socket = @stream_socket_client(
                'unix://'.$this->path, $errno, $errstr, $this->timeoutSeconds(), STREAM_CLIENT_CONNECT
            );
            if ($socket === false) {
                $this->skipUntil = $now + 1.0;

                return Verdict::allow();
            }

            $line = json_encode($probe);
            if ($line === false) {
                fclose($socket);

                return Verdict::allow();
            }

            stream_set_blocking($socket, true);
            stream_set_timeout($socket, 0, max($this->timeoutMs, 1) * 1000);
            fwrite($socket, $line."\n");
            $response = fgets($socket, 65536);
            $timedOut = stream_get_meta_data($socket)['timed_out'] ?? false;
            fclose($socket);

            if ($response === false || $timedOut) {
                return Verdict::allow();
            }

            return Verdict::fromArray(json_decode(trim($response), true));
        } catch (Throwable) {
            return Verdict::allow();
        }
    }

    private function timeoutSeconds(): float
    {
        return max($this->timeoutMs, 1) / 1000.0;
    }
}
