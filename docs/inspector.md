# Windside console v0

Save as `docs/inspector.md`. A quick, read-mostly web view inside leesided so the operator can see everything the system holds and every step between a request and a decision, with the LLM exchanges in full. It comes before `docs/console.md`: the designed SPA follows on the same data layer. Speed matters more than polish; what matters most is that nothing is hidden.

## 1. Shape

- Server-rendered HTML from leesided, served at `LEESIDED_CONSOLE_PATH` (default `/windside`) by the existing HTTP server, behind nginx with no rewrite. No build step, no JavaScript beyond `<details>` toggles and a copy button. One stylesheet inlined, dark, using the tokens in `console.md` section 5.
- Auth: `GET {prefix}/login` shows a form; posting the operator token sets an admin session, posting `LEESIDED_VIEWER_TOKEN` a viewer session (random cookie, 12 h, `HttpOnly; SameSite=Strict`, cookie path the prefix). Every page requires the session; the header shows the role. Mutations are plain `<form method="post">` protected by `SameSite=Strict` and a per-session token in a hidden field. Viewer sessions render no mutation form and get 403 on every POST.
- Allowlist: `LEESIDED_CONSOLE_ALLOW` holds optional CIDRs, applied to the client IP on the console paths; empty allows all. Behind `LEESIDED_TRUSTED_PROXY` the client is the leftmost `X-Forwarded-For` entry, otherwise the peer.
- One data layer, `src/console/queries.rs`, used by these pages now and by the JSON API in `console.md` later. Pages call queries; they never run SQL of their own.
- Every page shows ids in full with a copy button, times as UTC with microseconds beside the ISO form, and links to every related object. Nothing is summarised away; where a list is long it pages at 100 rows.
- `app_id` on every query with `default` as the value, per the handoff rule.

## 2. Pages

Paths take the console prefix (default `/windside`).

| Path | Shows | Mutations |
| --- | --- | --- |
| `/` | health as a table, counts per table, today's LLM calls and tokens per point, the last 20 events (turns, decisions, proposals, labels) | none |
| `/llm` | every `llm_calls` row, newest first: time, point, subject, model, json mode, effort, finish reason, prompt, completion and reasoning tokens, latency, outcome (parsed, validation failed, transport error, dropped), link | none |
| `/llm/{id}` | the exchange in three columns: **Sent** (the system prompt, then the envelope pretty-printed, then the full request body as sent), **Received** (`content` pretty-printed, `reasoning_content` in full, `finish_reason`, usage), **Interpreted** (the parsed result, the schema validation outcome with the error when it failed, the faithfulness result per signal once it exists, the retry history with each attempt's budget, and the row it produced: the label, the explanation, the payload class or the draft, with a link). Then **What happened next**: the review decision if any, the operator label, the rule draft's status | re-send (admin) |
| `/jobs` | `llm_jobs`: queued, running, done, failed, with attempts, enqueued by, and the call it produced | retry a failed job; cancel a queued one |
| `/labels` | every label: time, subject, scope, source, label, confidence, kind, signals, note; filters by source and label | none |
| `/actors` | actors by latest score: id, kind, surfaces, confirmed, turns held, score, state, cluster | none |
| `/actors/{id}` | everything `console.md` section 3 lists, in plain tables: header fields, bindings, client, cluster, activity, scores with the explanation, labels, the pending proposal with a link to its exchange, decisions, similar actors; then the full turn list with verdicts | label verdicts; block and unblock |
| `/clusters` and `/clusters/{key}` | the same for the cluster scope | label verdicts |
| `/turns/{turn_id}` | one turn: every stored column, the probe and the verdict, the actor or cluster it resolved to, its feature row, its score, the tap join (ja4, ja4t, class), the rule hits | none |
| `/trace/{turn_id}` | the chain for one request as a vertical list: turn → resolution (which identifier decided, provisional or confirmed) → feature row (the 38 values) → score (value, threshold, top3) → proposal (link) → label → decision. Each step says where it came from and when | none |
| `/review` | the queue in its current order with `why_in_queue`, each row with the proposal's label, confidence, signals, reason and a link to the exchange | confirm, benign, malicious, unknown |
| `/rules` | the install set and overrides with enabled flags and 24 h hit counts; `rule_drafts` with reason, parse status and a link to the exchange | approve or discard a draft; enable or disable |
| `/model` | version, mode, thresholds, features version, manifest metrics, the shadow report | none in v0 |
| `/features` | the current feature names in order with a one-line description each, read from the code's table | none |

## 3. The exchange page is the point

`{prefix}/llm/{id}` is why this exists. Requirements:

- The request shown is the bytes sent, not a reconstruction: `llm_calls.request` as stored, pretty-printed, with the envelope's JSON decoded one level so it reads as a document, not as an escaped string.
- `reasoning_content` is shown whole when stored, with its length; the 2 KB cap is noted when it was hit.
- The validation step shows the schema used (by point) and the exact error on failure.
- When the call produced a label, the page shows the label row and whether an operator has since confirmed or rejected it, and if rejected, what they chose instead.
- A "re-send" button appears for admin sessions: it makes one new live call with the same envelope and the current prompt, logged as a new row linked to the old one, so a prompt change can be checked on a known case.

## 4. Build order

1. `queries.rs` and the session login.
2. `/ui/llm`, `/ui/llm/{id}`, `/ui/jobs`.
3. `/ui/turns/{id}`, `/ui/trace/{id}`, `/ui/actors`, `/ui/actors/{id}`, clusters.
4. `/ui/review`, `/ui/labels`, `/ui/rules`, `/ui/model`, `/ui/features`, `/ui/`.

Report after step 2 with a screenshot of one exchange page from the e2e store, then after step 4.

## 5. Tests

- Every console page without a session redirects to login; a wrong token is refused.
- `{prefix}/llm/{id}` for the e2e scanner-cluster call renders the stored request and response verbatim (a byte comparison of the pretty-printed request against `llm_calls.request`).
- `{prefix}/trace/{turn_id}` for a turn of the scraper actor lists all seven steps with non-empty content.
- A review decision through the form writes the operator label and the page reflects it on reload.
- Pages render with an empty store without errors.
- A viewer session gets 200 on every page with no mutation form, and 403 on every POST.
- A custom prefix moves the routes, the cookie path and the redirects together.
- The allowlist admits a listed client, denies an unlisted one, and ignores `X-Forwarded-For` from an untrusted peer.

## 6. Do not

- No SQL in page code; queries only.
- No truncation of ids, prompts, envelopes or responses except the stored 2 KB reasoning cap.
- No JavaScript framework; this is replaced by the designed console, not grown into it.
- No LLM call from a page except the explicit re-send.
