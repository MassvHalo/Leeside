<?php

namespace Leeside\Laravel\Tests\Feature;

use Closure;
use Illuminate\Auth\GenericUser;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Leeside\Laravel\Surface\CredentialVerifier;
use Leeside\Laravel\Surface\SurfaceClassifier;

/**
 * Schema v2: a presented credential is only an identity once something has
 * vouched for it. Verified sources: a resolved principal, a webhook signer
 * set by a verifying middleware ahead of the gate, or the app's
 * CredentialVerifier binding.
 */
class CredentialStatusTest extends SampleAppTestCase
{
    protected function defineSampleRoutes(): void
    {
        parent::defineSampleRoutes();

        $router = $this->app['router'];
        // The package already pushed GateTurn into the webhook group at boot;
        // the verifier goes in front of it.
        $router->prependMiddlewareToGroup('webhook', VerifySignatureDemo::class);
        $router->post('/webhooks/signed', fn () => new JsonResponse(['ok' => true]))
            ->middleware('webhook')->name('webhooks.signed');
        $router->get('/api/keyed', fn (Request $request) => $request->header('X-Api-Key') === 'good-key'
            ? new JsonResponse(['pong' => true])
            : new JsonResponse(['message' => 'Unauthorized'], 401))
            ->middleware('api')->name('api.keyed');
    }

    public function test_bare_bearer_is_unverified_on_probe_and_event(): void
    {
        $this->withHeader('Authorization', 'Bearer ZZZ-random')->get('/venues/1')->assertOk();

        $probe = $this->rules->probes[0];
        $this->assertSame('api', $probe['surface']);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $probe['credential_hash']);
        $this->assertSame('unverified', $probe['credential_status']);

        $event = $this->lastEvent();
        $this->assertSame('bearer', $event['credential_kind']);
        $this->assertSame('unverified', $event['credential_status'], 'a 200 does not verify a header');
    }

    public function test_no_credential_has_null_status(): void
    {
        $this->get('/venues/1')->assertOk();

        $this->assertNull($this->rules->probes[0]['credential_status']);
        $this->assertNull($this->lastEvent()['credential_status']);
    }

    public function test_unverified_key_answered_401_is_rejected(): void
    {
        $this->withHeader('X-Api-Key', 'ZZZ-wrong')->getJson('/api/keyed')->assertStatus(401);

        $this->assertSame('unverified', $this->rules->probes[0]['credential_status']);
        $event = $this->lastEvent();
        $this->assertSame('api_key', $event['credential_kind']);
        $this->assertSame('rejected', $event['credential_status']);
        $this->assertSame($this->hasher()->credentialHash('ZZZ-wrong'), $event['credential_hash']);

        $this->withHeader('X-Api-Key', 'ZZZ-wrong')->getJson('/secret')->assertStatus(403);
        $this->assertSame('rejected', $this->lastEvent()['credential_status'], '403 rejects too');
    }

    public function test_app_verifier_vouches_at_probe_time(): void
    {
        $this->app->instance(CredentialVerifier::class, new class implements CredentialVerifier
        {
            public function verify(Request $request, string $kind, string $value): bool
            {
                return $kind === 'api_key' && $value === 'good-key';
            }
        });

        $this->withHeader('X-Api-Key', 'good-key')->getJson('/api/keyed')->assertOk();
        $this->assertSame('verified', $this->rules->probes[0]['credential_status']);
        $this->assertSame('verified', $this->lastEvent()['credential_status']);

        $this->withHeader('X-Api-Key', 'ZZZ-wrong')->getJson('/api/keyed')->assertStatus(401);
        $this->assertSame('unverified', $this->rules->probes[1]['credential_status']);
        $this->assertSame('rejected', $this->lastEvent()['credential_status']);
    }

    public function test_throwing_verifier_never_vouches(): void
    {
        $this->app->instance(CredentialVerifier::class, new class implements CredentialVerifier
        {
            public function verify(Request $request, string $kind, string $value): bool
            {
                throw new \RuntimeException('ZZZ-verifier-boom');
            }
        });

        $this->withHeader('X-Api-Key', 'good-key')->getJson('/api/keyed')->assertOk();
        $this->assertSame('unverified', $this->rules->probes[0]['credential_status']);
        $this->assertStringNotContainsString('ZZZ-verifier-boom', $this->eventsJson());
    }

    public function test_webhook_signer_verified_by_middleware_ahead_of_the_gate_is_on_the_probe(): void
    {
        $this->postJson('/webhooks/signed', ['x' => 1], ['X-Signature' => 'good'])->assertOk();

        $this->assertCount(1, $this->rules->probes, 'the webhook group is gated');
        $probe = $this->rules->probes[0];
        $this->assertSame('webhook', $probe['surface']);
        $this->assertSame($this->hasher()->credentialHash('acct_42'), $probe['credential_hash']);
        $this->assertSame('verified', $probe['credential_status']);

        $event = $this->lastEvent();
        $this->assertSame('webhook_sig', $event['credential_kind']);
        $this->assertSame('verified', $event['credential_status']);
        $this->assertStringNotContainsString('acct_42', $this->eventsJson());
    }

    public function test_unsigned_webhook_is_refused_before_the_gate_and_has_no_credential(): void
    {
        $this->postJson('/webhooks/signed', ['x' => 1])->assertStatus(401);

        $this->assertCount(0, $this->rules->probes, 'the verifier answered before the gate ran');
        $event = $this->lastEvent();
        $this->assertSame('webhook', $event['surface']);
        $this->assertNull($event['credential_kind']);
        $this->assertNull($event['credential_status']);
    }

    public function test_resolved_principal_verifies_a_presented_credential(): void
    {
        $this->actingAs(new GenericUser(['id' => 7]), 'web');

        $this->withHeader('Authorization', 'Bearer session-backed')->get('/venues/1')->assertOk();

        $probe = $this->rules->probes[0];
        $this->assertSame($this->hasher()->principal('7'), $probe['principal']);
        $this->assertSame('verified', $probe['credential_status']);
        $this->assertSame('verified', $this->lastEvent()['credential_status']);
    }
}

/** Stands in for an app's signature check: runs ahead of the gate and names the signer. */
class VerifySignatureDemo
{
    public function handle(Request $request, Closure $next): mixed
    {
        if ($request->header('X-Signature') !== 'good') {
            return new JsonResponse(['message' => 'bad signature'], 401);
        }

        $request->attributes->set(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, 'acct_42');

        return $next($request);
    }
}
