<?php

namespace Leeside\Laravel\Transport;

class ArrayTransport implements Transport
{
    /** @var array<int, array<string, mixed>> */
    public array $events = [];
    public bool $succeed = true;

    public function send(array $event): bool
    {
        if (! $this->succeed) {
            return false;
        }

        $this->events[] = $event;

        return true;
    }
}
