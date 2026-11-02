# Rule grammar excerpt (for the draft envelope)

One rule is one JSON object. Unknown fields are rejected at every level.

- `id`: `^[a-z0-9][a-z0-9-]{2,63}$`, the primary key.
- `note`: 1..=200 chars, what the rule is for.
- `mode`: `monitor` | `shadow` | `enforce`; the rule's own ceiling, effective mode is min(global, rule).
- `action`: `log` | `watch` | `rate_limit` | `challenge` | `block`. `allow` is never written.
- `retry_after_s`: 1..=86400, required with `rate_limit`, rejected otherwise.
- `block_min`: 1..=1440, minutes a `block` sticks; rejected with other actions; absent = 1440.
- `match`: which probes the rule evaluates for: `route` (1..=16 templates, exact match; `"*"` alone means any), `verb` (1..=8 of GET POST PUT PATCH DELETE HEAD OPTIONS), `principal` (`any` | `anon` | `authenticated`), `surface` (optional list of honeypot webhook api web).
- `when`: optional; absent means the rule fires on every matching probe. One condition or `{"all": [...]}`. Exactly one of `count`, `distinct`, `sequence`, `score`:
  - `scope`: session (default) | peer | principal | credential | actor. `principal` on an anon probe and `credential` without a presented credential read as empty.
  - `window_s`: 1..=86400, optional; absent means the whole held window (64 turns).
  - `count`: a turn filter; with `gte` and/or `lte`.
  - `distinct`: `{"field": "bound_id" | "route" | "credential", "model"?, "where"?}` with `gte` 1..=64.
  - `sequence`: 2..=8 route templates; rejects `scope` and `window_s`.
  - `score`: `{"gte": 0..=1}`; needs `scope: actor`, rejects `window_s`; holds only while Windside is active.
- Turn filter fields (all optional, OR in a list, AND across): `route`, `verb`, `status` (ints or "4xx"/"5xx"), `validation_failed`, `exception` (basenames), `auth_event`, `req_shape`, `bound_model`, `credential_status` (verified rejected unverified).
- `origin`: `{"kind": "install" | "operator" | "spark", "model"?}`. Drafts use `spark` with the model name.
- The check for turn N runs before turn N is handled: `count`/`distinct` see turns 1..N-1, `match` sees the probe, `sequence` joins them.
