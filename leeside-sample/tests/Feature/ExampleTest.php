<?php

namespace Tests\Feature;

use App\Models\Venue;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_application_returns_a_successful_response(): void
    {
        Venue::create(['name' => 'Alpine Lodge', 'city' => 'Innsbruck']);
        Venue::create(['name' => 'Harbor Inn', 'city' => 'Bergen']);

        $response = $this->get('/');

        $response->assertStatus(200);
        $response->assertSee('Sample Portal');
        $response->assertSee('Alpine Lodge');
        $response->assertSee('Harbor Inn');
        $response->assertSee('login-form', false);
    }
}
