<?php

namespace Leeside\Laravel\Transport;

use Throwable;

class UnixDatagramTransport implements Transport
{
    private float $skipUntil = 0.0;

    public function __construct(private readonly string $path) {}

    public function send(array $event): bool
    {
        $now = microtime(true);
        if ($now < $this->skipUntil) {
            return false;
        }

        try {
            $payload = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($payload === false) {
                return false;
            }

            $socket = @stream_socket_client('udg://'.$this->path, $errno, $errstr);
            if ($socket === false) {
                $this->skipUntil = $now + 1.0;

                return false;
            }

            stream_set_blocking($socket, false);
            $sent = @stream_socket_sendto($socket, $payload);
            fclose($socket);

            return $sent === strlen($payload);
        } catch (Throwable) {
            return false;
        }
    }
}
