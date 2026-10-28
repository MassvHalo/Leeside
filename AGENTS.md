# Leeside

Monorepo for Leeside, an application-level firewall built for the Meta Global
AI Developer Hackathon (startup track). Names: Leeside is the product,
leesided the Rust engine, Windside the fast classifier inside leesided,
Glimmer and Spark the Meta models at the scoring and reasoning tiers.

## Layout
- docs/brief.md: the contract. Event schema v1, sync check protocol, sample
  app spec, deploy. A change to the schema or the protocol is written here
  before any code changes.
- docs/architecture.md: the solution architecture.
- leeside-laravel/: Composer package leeside/laravel, the capture layer.
- leeside-sample/: Laravel app that uses the package; serves at
  https://webapp.leeside.halowifi.com.
- leesided/: the Rust engine.
Each directory has its own AGENTS.md with its own rules and stack.

## Shared rules
- Start a session inside the directory being worked on (cd leesided && muse).
  That directory's AGENTS.md loads on top of this one; this one applies
  everywhere.
- One directory per session. A fix needed in another directory is reported
  to me, not made.
- Nothing identifying is stored unhashed and nothing valued unreduced, in any
  directory. Hashes and shapes only.
- No model call on any request path. Models run async, off a queue, from
  leesided only.
- No commit, no push, no deploy from the agent. I review and commit. I run
  the deploy/ scripts myself with sudo.
- Never read or write .env files, storage/, *.sqlite, /var/www or /etc.
