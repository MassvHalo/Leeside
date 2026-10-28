<?php

namespace Leeside\Laravel\Transport;

use Illuminate\Log\LogManager;
use Throwable;

class LogTransport implements Transport
{
    public function __construct(
        private readonly LogManager $logs,
        private readonly ?string $channel = null,
    ) {}

    public function send(array $event): bool
    {
        try {
            $line = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($line === false) {
                return false;
            }

            $this->logs->channel($this->channel)->info($line);

            return true;
        } catch (Throwable) {
            return false;
        }
    }
}
