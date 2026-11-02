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
            // The address and the capture travel on the socket only; a log
            // line keeps the hash side.
            foreach (['ip', 'path', 'sample_query', 'body_slice'] as $socketOnly) {
                if (array_key_exists($socketOnly, $event)) {
                    $event[$socketOnly] = null;
                }
            }
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
