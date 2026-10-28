<?php

namespace Leeside\Laravel\Tests\Unit;

use Leeside\Laravel\Transport\ArrayTransport;
use Leeside\Laravel\Transport\NullTransport;
use Leeside\Laravel\Transport\UnixDatagramTransport;
use PHPUnit\Framework\TestCase;

class TransportTest extends TestCase
{
    public function test_null_discards_as_success(): void
    {
        $this->assertTrue((new NullTransport)->send(['v' => 1]));
    }

    public function test_array_collects_events(): void
    {
        $transport = new ArrayTransport;

        $this->assertTrue($transport->send(['v' => 1]));
        $this->assertSame([['v' => 1]], $transport->events);

        $transport->succeed = false;

        $this->assertFalse($transport->send(['v' => 2]));
        $this->assertSame([['v' => 1]], $transport->events);
    }

    public function test_udg_sends_one_datagram_per_event(): void
    {
        if (! function_exists('socket_create')) {
            $this->markTestSkipped('ext-sockets required');
        }

        $path = sys_get_temp_dir().'/leeside-udg-'.uniqid().'.sock';
        $server = socket_create(AF_UNIX, SOCK_DGRAM, 0);
        $this->assertNotFalse($server);
        $this->assertTrue(socket_bind($server, $path));
        socket_set_option($server, SOL_SOCKET, SO_RCVTIMEO, ['sec' => 2, 'usec' => 0]);

        try {
            $transport = new UnixDatagramTransport($path);

            $this->assertTrue($transport->send(['v' => 1, 'route' => 'home']));

            $bytes = socket_recvfrom($server, $payload, 65536, 0, $peer);
            $this->assertNotFalse($bytes, 'timed out waiting for the datagram');
            $this->assertSame('{"v":1,"route":"home"}', $payload);
        } finally {
            socket_close($server);
            @unlink($path);
        }
    }

    public function test_udg_drops_when_nobody_listens(): void
    {
        $transport = new UnixDatagramTransport(sys_get_temp_dir().'/leeside-missing-'.uniqid().'.sock');

        $this->assertFalse($transport->send(['v' => 1]));
        $this->assertFalse($transport->send(['v' => 1]));
    }

    public function test_udg_rejects_unencodable_events(): void
    {
        $handle = fopen('php://memory', 'r');

        try {
            $transport = new UnixDatagramTransport(sys_get_temp_dir().'/leeside-udg-'.uniqid().'.sock');

            $this->assertFalse($transport->send(['v' => $handle]));
        } finally {
            fclose($handle);
        }
    }
}
