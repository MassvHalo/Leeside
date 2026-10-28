<?php

namespace Leeside\Laravel;

class Stats
{
    private int $dropped = 0;

    public function dropped(): void
    {
        $this->dropped++;
    }

    /** Read without consuming; only a successful send acknowledges. */
    public function pending(): int
    {
        return $this->dropped;
    }

    public function acknowledge(int $count): void
    {
        $this->dropped = max(0, $this->dropped - $count);
    }
}
