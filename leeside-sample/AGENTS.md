# leeside-sample

Stock Laravel app that uses leeside/laravel through a path repository
(../leeside-laravel). It exists to produce real session-shaped events, to
measure the package's overhead and to prove no PII leaves the app. Deployed at
https://webapp.leeside.halowifi.com by deploy/install.sh and deploy/deploy.sh.
Read ../docs/brief.md (Sample app spec and Deploy) first.

## Non-negotiables
- The package is used, never modified from here. Package fixes go to
  ../leeside-laravel, reported to me, not made here.
- Routes stay portal-shaped and small. No auth scaffolding, no starter kits.
- deploy/ scripts are idempotent and run with sudo by me, never by the
  agent. install.sh is the only thing that touches /etc. deploy.sh updates
  the production checkout in /var/www/leeside and drops to www-data for
  composer and artisan. This working copy is never served directly.
- Never commit .env, database.sqlite, storage/ or anything under /var/log.

## Stack
- PHP 8.3, Laravel 13, SQLite. nginx + PHP-FPM and certbot in production.

## Done means
- bin/traffic.sh produces events in the tap; the PII grep is empty; added
  latency is under 1 ms.
- No commit, no push.
