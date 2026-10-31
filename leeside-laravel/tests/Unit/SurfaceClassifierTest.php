<?php

namespace Leeside\Laravel\Tests\Unit;

use Illuminate\Config\Repository;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Leeside\Laravel\Surface\SurfaceClassifier;
use PHPUnit\Framework\TestCase;

class SurfaceClassifierTest extends TestCase
{
    private function classifier(array $surface = []): SurfaceClassifier
    {
        return new SurfaceClassifier(new Repository(['leeside' => ['surface' => $surface]]));
    }

    private function route(string $uri, ?string $name = null, array $middleware = []): Route
    {
        $action = ['uses' => fn () => null, 'middleware' => $middleware];
        if ($name !== null) {
            $action['as'] = $name;
        }

        return new Route(['GET'], $uri, $action);
    }

    private function request(string $path, array $headers = []): Request
    {
        $server = [];
        foreach ($headers as $k => $v) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $k))] = $v;
        }

        return Request::create($path, 'GET', [], [], [], $server);
    }

    public function test_default_is_web(): void
    {
        $c = $this->classifier();
        $this->assertSame('web', $c->classify($this->request('/'), $this->route('/', 'home', ['web'])));
        $this->assertSame('web', $c->classify($this->request('/nope'), null));
    }

    public function test_api_by_group_prefix_bearer_or_key_header(): void
    {
        $c = $this->classifier();
        $this->assertSame('api', $c->classify($this->request('/venues'), $this->route('venues', 'v', ['api'])));
        $this->assertSame('api', $c->classify($this->request('/api/venues'), $this->route('api/venues')));
        $this->assertSame('api', $c->classify($this->request('/api'), null));
        $this->assertSame('web', $c->classify($this->request('/apiary'), null), 'prefix is a path segment');
        $this->assertSame('api', $c->classify($this->request('/', ['Authorization' => 'Bearer abc.def']), $this->route('/', 'home', ['web'])));
        $this->assertSame('web', $c->classify($this->request('/', ['Authorization' => 'Basic abc']), $this->route('/', 'home', ['web'])));
        $this->assertSame('api', $c->classify($this->request('/', ['X-Api-Key' => 'k']), $this->route('/', 'home', ['web'])));
        $this->assertSame('api', $c->classify($this->request('/', ['Api-Key' => 'k']), null));
    }

    public function test_webhook_by_prefix_or_route_name_beats_api(): void
    {
        $c = $this->classifier(['webhook' => ['/webhooks/', 'hooks.*']]);
        $this->assertSame('webhook', $c->classify($this->request('/webhooks/demo', ['Authorization' => 'Bearer t']), null));
        $this->assertSame('webhook', $c->classify($this->request('/webhooks'), null));
        $this->assertSame('web', $c->classify($this->request('/webhooksy'), null));
        $this->assertSame('webhook', $c->classify($this->request('/x'), $this->route('x', 'hooks.stripe', ['api'])));
        $this->assertSame('api', $c->classify($this->request('/x'), $this->route('x', 'hooks', ['api'])), 'fnmatch needs the dot');
    }

    public function test_honeypot_group_beats_webhook_and_api(): void
    {
        $c = $this->classifier();
        $route = $this->route('webhooks/demo', 'admin.backup', ['web', 'honeypot']);
        $this->assertSame('honeypot', $c->classify($this->request('/webhooks/demo', ['Authorization' => 'Bearer t']), $route));
        $c = $this->classifier(['honeypot_group' => 'traps']);
        $this->assertSame('webhook', $c->classify($this->request('/webhooks/demo'), $route), 'renamed group no longer matches');
    }

    public function test_force_overrides_win_by_route_name_or_prefix(): void
    {
        $c = $this->classifier(['force' => ['home' => 'api', '/partner/' => 'api', 'hooks.*' => 'webhook', 'bad' => 'nonsense']]);
        $this->assertSame('api', $c->classify($this->request('/'), $this->route('/', 'home', ['web'])));
        $this->assertSame('api', $c->classify($this->request('/partner/v1/ping'), $this->route('partner/v1/ping', null, ['web'])));
        $this->assertSame('webhook', $c->classify($this->request('/x'), $this->route('x', 'hooks.github', ['api'])));
        $this->assertSame('web', $c->classify($this->request('/'), $this->route('/', 'bad')), 'an unknown surface is ignored');
    }

    public function test_credential_kind_and_value(): void
    {
        $c = $this->classifier();
        $this->assertSame(['kind' => 'bearer', 'value' => 'tok.en'], $c->credential($this->request('/', ['Authorization' => 'bearer   tok.en'])));
        $this->assertSame(['kind' => 'api_key', 'value' => 'k1'], $c->credential($this->request('/', ['X-Api-Key' => 'k1'])));
        $this->assertSame(['kind' => null, 'value' => null], $c->credential($this->request('/')));
        $request = $this->request('/webhooks/demo');
        $request->attributes->set(SurfaceClassifier::WEBHOOK_SIGNER_ATTRIBUTE, 'acct_42');
        $this->assertSame(['kind' => 'webhook_sig', 'value' => 'acct_42'], $c->credential($request));
        $this->assertSame('webhook', $c->classify($request, null), 'a signer alone does not make it api');
    }

    public function test_is_asset_by_extension(): void
    {
        $c = $this->classifier();
        $this->assertTrue($c->isAsset($this->request('/build/app.CSS')));
        $this->assertTrue($c->isAsset($this->request('/favicon.ico')));
        $this->assertFalse($c->isAsset($this->request('/venues/1')));
        $this->assertFalse($c->isAsset($this->request('/')));
        $c = $this->classifier(['asset_extensions' => ['pdf']]);
        $this->assertFalse($c->isAsset($this->request('/app.css')));
        $this->assertTrue($c->isAsset($this->request('/report.pdf')));
    }
}
