<?php

namespace App\Providers;

use App\Leeside\StaticApiKeyVerifier;
use Illuminate\Support\ServiceProvider;
use Leeside\Laravel\Surface\CredentialVerifier;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Leeside calls this while building the probe, so a genuine demo API
        // key counts as a verified credential before the controller runs.
        $this->app->bind(CredentialVerifier::class, StaticApiKeyVerifier::class);
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        //
    }
}
