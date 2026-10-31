<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Leeside\Laravel\Check\ArrayRuleClient;
use Leeside\Laravel\Check\RuleClient;
use Leeside\Laravel\Hash\Hasher;
use Leeside\Laravel\Transport\ArrayTransport;
use Leeside\Laravel\Transport\Transport;
use Tests\TestCase;

/** The machine surfaces: a signed webhook and a keyed API, as Leeside sees them. */
class SurfacesTest extends TestCase
{
    use RefreshDatabase;

    private ArrayTransport $transport;
    private ArrayRuleClient $rules;

    protected function setUp(): void
    {
        parent::setUp();

        $this->transport = new ArrayTransport;
        $this->rules = new ArrayRuleClient;
        $this->app->instance(Transport::class, $this->transport);
        $this->app->instance(RuleClient::class, $this->rules);
    }

    public function test_signed_webhook_is_verified_before_the_gate(): void
    {
        $body = json_encode(['order' => 42]);
        $signature = hash_hmac('sha256', $body, config('leeside_demo.webhook_secret'));

        $this->call('POST', '/webhooks/demo', [], [], [], [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_X_SIGNATURE' => $signature,
            'HTTP_X_SIGNER' => 'acct_42',
        ], $body)->assertOk()->assertJson(['received' => true, 'signer' => 'acct_42']);

        $this->assertCount(1, $this->rules->probes, 'the webhook group is gated');
        $probe = $this->rules->probes[0];
        $this->assertSame('webhook', $probe['surface']);
        $this->assertSame($this->app[Hasher::class]->credentialHash('acct_42'), $probe['credential_hash']);
        $this->assertSame('verified', $probe['credential_status']);

        $event = end($this->transport->events);
        $this->assertSame('webhook_sig', $event['credential_kind']);
        $this->assertSame('verified', $event['credential_status']);
        $this->assertStringNotContainsString('acct_42', json_encode($this->transport->events));
    }

    public function test_forged_webhook_is_probed_then_refused(): void
    {
        $this->postJson('/webhooks/demo', ['order' => 42], ['X-Signature' => str_repeat('0', 64), 'X-Signer' => 'acct_evil'])
            ->assertStatus(401)->assertJson(['message' => 'Unauthorized']);

        $this->assertCount(1, $this->rules->probes, 'the forgery reaches leesided');
        $this->assertSame('unverified', $this->rules->probes[0]['credential_status']);
        $event = end($this->transport->events);
        $this->assertSame('webhook', $event['surface']);
        $this->assertSame('webhook_sig', $event['credential_kind']);
        $this->assertSame('rejected', $event['credential_status']);
        $this->assertStringNotContainsString('acct_evil', json_encode($this->transport->events));

        $this->postJson('/webhooks/demo', ['order' => 42])->assertStatus(401);
        $this->assertSame('rejected', end($this->transport->events)['credential_status']);
    }

    public function test_api_ping_with_the_demo_key_is_verified_and_without_it_rejected(): void
    {
        $this->withHeader('X-Api-Key', config('leeside_demo.api_key'))->getJson('/api/ping')->assertOk();
        $this->assertSame('api', $this->rules->probes[0]['surface']);
        $this->assertSame('verified', $this->rules->probes[0]['credential_status']);
        $this->assertSame('verified', end($this->transport->events)['credential_status']);

        $this->withHeader('X-Api-Key', 'not-the-key')->getJson('/api/ping')->assertStatus(401);
        $this->assertSame('unverified', $this->rules->probes[1]['credential_status']);
        $this->assertSame('rejected', end($this->transport->events)['credential_status']);
        $this->assertStringNotContainsString('not-the-key', json_encode($this->transport->events));

        $this->flushHeaders()->getJson('/api/ping')->assertStatus(401);
        $this->assertNull(end($this->transport->events)['credential_status']);
    }

    public function test_admin_backup_is_a_named_404_for_the_future_honeypot(): void
    {
        $this->get('/admin-backup')->assertNotFound();

        $this->assertSame('admin.backup', end($this->transport->events)['route']);
    }
}
