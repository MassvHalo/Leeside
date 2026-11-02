<?php

namespace Leeside\Laravel\Tests\Feature;

use Leeside\Laravel\Tests\TestCase;
use Leeside\Laravel\Transport\LogTransport;

class LogTransportTest extends TestCase
{
    public function test_writes_one_json_line_per_event(): void
    {
        $marker = 'leeside-'.uniqid();
        $transport = new LogTransport($this->app['log'], 'single');

        $this->assertTrue($transport->send(['v' => 1, 'marker' => $marker]));

        $log = file_get_contents($this->app->storagePath('logs/laravel.log'));

        $this->assertStringContainsString('{"v":1,"marker":"'.$marker.'"}', $log);
    }

    public function test_rejects_unencodable_events(): void
    {
        $handle = fopen('php://memory', 'r');

        try {
            $transport = new LogTransport($this->app['log'], 'single');

            $this->assertFalse($transport->send(['v' => $handle]));
        } finally {
            fclose($handle);
        }
    }

    public function test_log_nulls_socket_only_fields(): void
    {
        $marker = 'leeside-'.uniqid();
        $transport = new LogTransport($this->app['log'], 'single');

        $transport->send([
            'v' => 1,
            'marker' => $marker,
            'ip' => '10.0.0.1',
            'path' => '/wp-login.php',
            'sample_query' => 'a=1',
            'body_slice' => '{}',
        ]);

        $log = file_get_contents($this->app->storagePath('logs/laravel.log'));

        $this->assertStringContainsString(
            '"marker":"'.$marker.'","ip":null,"path":null,"sample_query":null,"body_slice":null',
            $log
        );
    }
}
