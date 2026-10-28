# leesided

Rust daemon for Leeside. One binary: ingests turn events from the Laravel
package over a Unix datagram socket, answers the package's synchronous rule
check over a Unix stream socket, keeps conversations and rules in SQLite,
runs Windside inference, queues conversations for Glimmer and Spark, and
serves a local HTTP API and the review UI as static files.
Read ../docs/architecture.md and ../docs/brief.md before any non-trivial
task. The brief's event schema v1 and sync check protocol are the contract:
leesided implements the other end of both sockets exactly as written there.

## Non-negotiables
- No model call on the request path. The check server answers from rules
  and Windside only, within 1 ms; Glimmer and Spark run async off a queue.
- Never store PII. Events arrive as shapes and hashes and stay that way.
  Reject and count any event that fails schema validation; never log its
  contents.
- Mode ladder: monitor -> shadow -> enforce. Default monitor. Per-rule
  overrides go downward only (a rule can be shadow under enforce, never
  the reverse). enforce:false in config or one API call drops to monitor.
- Windside `yes` with no matching enforce rule = flag + rate_limit, never
  block.
- A model file whose feature names or count differ from the extractor's
  fails the load loudly at start.
- leesided is the single source of truth for feature extraction. The lab
  consumes rows leesided wrote; it never re-implements the extractor.
- Sockets: events.sock is a datagram socket, check.sock a stream socket,
  both in /run/leeside (or the configured dir), mode 0660, group www-data,
  so PHP-FPM can write and connect.

## Stack
- Rust stable. tokio, axum, rusqlite (bundled), serde, serde_json, tracing.
- `cargo fmt`, `cargo clippy -D warnings`, `cargo test` all pass before a
  task is done. Say why before adding a dependency.
- One cargo build at a time; no parallel subagents that compile.

## Layout
src/ingest  src/check  src/store  src/rules  src/modes  src/windside
src/queue  src/api  ui/ (Vue 3, built assets embedded)

## Done means
- Tests for the behaviour, including the mode ladder edge cases and the
  contract's example event and probe.
- `/health` still answers.
- No commit, no push. I review the diff and commit.
