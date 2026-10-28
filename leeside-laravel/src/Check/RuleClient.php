<?php

namespace Leeside\Laravel\Check;

interface RuleClient
{
    /** Never throws; returns allow on any failure. */
    public function check(array $probe): Verdict;
}
