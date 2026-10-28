<?php

namespace Leeside\Laravel\Transport;

interface Transport
{
    /**
     * Never throws and never blocks the request. False means the event was
     * dropped and must be counted by the caller.
     */
    public function send(array $event): bool;
}
