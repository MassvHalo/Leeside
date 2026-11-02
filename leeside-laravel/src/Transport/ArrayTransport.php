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

        foreach (['ip', 'path', 'sample_query', 'body_slice'] as $socketOnly) {
            if (array_key_exists($socketOnly, $event)) {
                $event[$socketOnly] = null;
            }
        }

        $this->events[] = $event;

        return true;
    }
}
