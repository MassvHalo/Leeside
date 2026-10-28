<?php

namespace Leeside\Laravel\Check;

class NullRuleClient implements RuleClient
{
    public function check(array $probe): Verdict
    {
        return Verdict::allow();
    }
}
