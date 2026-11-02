# Application outcomes

Save as `docs/outcomes.md`. A small capture addition to leeside-laravel and leesided that makes business-flow abuse visible: promo-code guessing, gift-card balance checks, OTP guessing, booking-slot hoarding. At the HTTP layer these look like legitimate use (signed-in user, real browser, 200 responses); the only fact that separates them is one the application already knows and Leeside never recorded: the request was rejected by the app.

## 1. The hook (package)

One call an app makes anywhere during a request:

```php
Leeside::outcome(string $kind, string $result, ?string $ref = null);
// Leeside::outcome('promo_code', 'rejected', $code);
// Leeside::outcome('booking', 'accepted');
```

- `kind`: app-defined, short, lower case (`promo_code`, `otp`, `gift_card`, `booking`, `login`).
- `result`: `accepted`, `rejected`, or an app-defined word; features and rules read `accepted` and `rejected`.
- `ref`: optional value the attempt was about (the code tried, the slot id). Stored only as a keyed hash in the `outcome` namespace, so distinct refs can be counted without the values being kept.

Last call wins per turn; the event carries `app_outcome_kind`, `app_outcome_result`, `app_outcome_ref_hash`. The call is a no-op without a capture context (CLI, queue jobs). A route in `LEESIDED_BUSINESS_ROUTES` with no explicit outcome and a sub-400 status still counts as `accepted` for the `verified_business` labeler, so nothing already configured changes.

## 2. Store and features (leesided)

- Three columns on `turns` (additive migration), indexed on `(app_id, app_outcome_kind, app_outcome_result)`.
- Features v3 adds `rejected_actions`, `accepted_actions`, `rejected_ratio`, `distinct_rejected_refs`, `distinct_outcome_kinds`. This is the v3 bump (the fingerprint group waits for a dataset that has JA4, and becomes v4). `features_version: 3` on `/health`; the training manifest refuses a mismatch as today.
- `verified_business` labels only on `accepted`; a verified credential with rejected outcomes is not benign evidence.

## 3. Rules

- Turn filters gain `app_outcome_kind` and `app_outcome_result`; `distinct.field` accepts `app_outcome_ref`.
- Install set gains one observe-only rule, off by default: scope principal (session when no principal), surface any, `distinct app_outcome_ref where app_outcome_result = rejected` at or above 5 in 60 minutes, decision `observe`. An operator escalates it to 429 per app once the shadow report shows what it would have hit. Observe hits on an actor whose score is below threshold are a disagreement and go to the front of the review queue.

## 4. LLM

- The label envelope's turns carry `app_outcome` as `kind:result`; the window carries the v3 counts.
- The signals enum gains `rejected_actions`. Faithfulness check: the cited turns must carry rejected outcomes, otherwise the proposal is downgraded to `unknown` and logged.
- `prompts/label.md` gains two sentences on what an outcome means and that a run of rejections followed by an acceptance is guessing until it hits.

## 5. Sample app and generators

- Checkout gets a promo-code field with three valid codes in config; `/checkout/apply-code` calls the hook with the code as `ref`. A booking confirmation calls `Leeside::outcome('booking', 'accepted')`.
- `attack-promo`: a logged-in Playwright session that walks two venue pages, then tries 40 codes from a list at a 2 s cadence, then the valid one. Every HTTP-layer witness says customer; only the outcomes say otherwise.
- `benign-checkout`: a logged-in session that applies one wrong code, then the right one, then books.
- Both land in the dataset with manifests like the others; `attack-promo` must produce at least 50 rows.

## 6. Tests

- Package: the hook writes the three fields on the event; no-op outside a request; `ref` never appears raw anywhere; the last call wins.
- leesided: v3 features computed from a fixture with mixed outcomes; the observe rule fires on the sixth distinct rejected ref inside the hour and not on five repeats of one ref; `verified_business` does not label a rejected turn.
- Label assistant: the faithfulness check rejects a `rejected_actions` signal whose cited turns carry no rejection.
- Dataset: `attack-promo` scores near zero on model 0.1.0 (features v2, no outcomes) and is separable on v3; both numbers in the report.

## 7. Do not

- Do not store the raw `ref`. Do not infer outcomes from status codes beyond the existing sub-400 business-route rule. Do not let an outcome block anything by itself; it is a feature and a rule input, nothing more.
