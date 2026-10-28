<?php

namespace Leeside\Laravel\Transport;

class NullTransport implements Transport
{
    public function send(array $event): bool
    {
        return true;
    }
}
