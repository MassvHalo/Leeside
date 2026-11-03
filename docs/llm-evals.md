# LLM evals and the human loop

Companion to `docs/llm.md`. Nothing about a prompt or a model choice changes without a number; this file defines the numbers and the two mechanisms that make the LLM's output checkable: cited evidence and queue order.

## 1. Golden sets

Under `windside/evals/`, one JSONL file per point, built from the generator stores and operator labels, never from the model's own proposals:

- `label.jsonl`: the envelope as the worker builds it, plus `expected_label` and `allowed_signals`. At least 100 rows across kinds and both scopes, including the hard ones: the cookie-keeping scraper, the benign api client, cold-start windows, `attack-promo` once outcomes exist. Each envelope pairs its window with exactly the turns up to that window's turn id; any row with `turns_held` under 10 expects `unknown`, except on a subject holding a verified credential with no rejections, where `benign` is also accepted (`also_accept`).
- `classify.jsonl`: `{method, path_pattern, sample_query, body_slice, expected_category}`, at least 200, half of them `none`.
- `explain.jsonl`: `{score, threshold, top3, window, must_mention}` where `must_mention` lists the feature names an explanation has to reference; at least 50.
- `draft.jsonl`: `{cluster summary, expected_scope, expected_surface, must_parse: true}`; at least 20.

`leesided llm eval-build --point label --out …` exports candidate rows from a store for hand labelling, with the operator's labels prefilled where they exist.

## 2. The eval command

`leesided llm eval --point label [--prompt <file>] [--model <slug>] [--limit N]` runs the set in dry-send mode (live calls, nothing written to `labels`, `payload_classes` or `rule_drafts`) and writes one `llm_evals` row per run: prompt hash, model, json mode, rows, agreement, agreement_raw, calibration bins, faithfulness failures, parse failures, tokens per row, latency per row, cost estimate. It prints the summary and the ten worst rows. `leesided llm eval --compare <hashA> <hashB>` prints the two side by side.

Per point:

| Point | Agreement | Also |
| --- | --- | --- |
| label | post-faithfulness label against the accepted set, per kind and per scope; `agreement_raw` beside it; confidence calibration in five bins | faithfulness failures, dropped signals per name, `unknown` rate, signal violations as a count (a known signal outside the row's list on an agreed row is not a worst row) |
| classify | expected category; per category precision and recall | cache hit rate on real traffic |
| explain | every `must_mention` feature named; length within limit | operator rating when the console has one |
| draft | parses; scope and surface as expected | dry-run match count against the cluster it came from |

Every prompt change runs the eval before it goes live, and the `llm_evals` row for the live prompt hash is linked from `/health`.

## 3. Cited evidence and faithfulness

Each claimed signal carries its own cited turns (at most 6 per signal, at most 5 signals); the union is derived, never sent. Each signal has a programmatic check against its own turns; every failed signal is dropped, the whole failed list is logged as `faithfulness_failed`, and the label stands only when a surviving signal sits on its side, else the proposal lands as `unknown` with the reason kept.

| Signal | Check on its own cited turns |
| --- | --- |
| attack_payload | at least one cited turn with a non-null `payload_hint` |
| scanner_paths | at least 3 distinct paths and a 404 share above 0.5, or paths in the scanner wordlist |
| high_404_rate | 404 share above 0.5 across the cited turns |
| machine_cadence | window `iri_cv` below 0.2, or `turns_last_60s` at least 30 |
| ua_inconsistent | a browser-family `ua_class` (chromium, firefox, safari, other_browser) with `ua_chromium_no_ch`, or a library JA4 class, on the cited turns |
| credential_stuffing | at least 5 distinct rejected credentials in the window |
| webhook_forgery | cited turns are `webhook` with `credential_status` rejected |
| honeytoken_hit | a cited turn's route is in the honeytoken list |
| rejected_actions | cited turns carry `app_outcome` ending in `:rejected` (fails closed until the outcomes round adds the field; see `docs/outcomes.md`) |
| normal_browsing | browser-family `ua_class` on the cited turns, no flag rate above 0.2 across the window, `ratio_404` below 0.2, `turns_held` at least 10 |
| verified_partner | the actor holds a verified credential and `rejected_credentials` is 0 |
| human_cadence | window `iri_cv` above 0.5 and `turns_last_60s` at most 30 |
| client_consistent | UA family and JA4 class agree where known (browser with browser, library with library), none of `ua_chromium_no_ch`, `library_ua_on_web`, `browser_no_accept_language`, on the cited turns |
| insufficient_data | `turns_held` below 10 |

Checks are deterministic and cheap; they run before anything is written.

## 4. Review queue order

Active learning: the rows whose labels move the next model most come first.

1. Rule-versus-score disagreements (a rule or observe hit on a subject below threshold, or a score above threshold with no rule hit).
2. Uncertain scores, by distance from 0.5 ascending.
3. Subjects with a proposal and no operator label, newest first.
4. Everything else by score descending.

Each queue row carries `why_in_queue` as a short enum so the CLI and the console can show it. Confirmed or rejected subjects leave the queue; a subject re-enters only on a new disagreement or a new proposal.

## 5. Metrics on the dashboard

Per prompt hash and model, over a window: proposals agreed by the operator (precision of proposals), coverage (proposals per subject above 0.5), seconds per confirmed label (from queue entry to decision), calibration, faithfulness failures per hundred, parse failures per hundred, tokens and reasoning tokens per confirmed label, classify agreement with the golden set, drafts parsed and drafts approved, false positives in shadow for approved drafts.

## 6. Later levers, in order

Few-shot retrieval (the three nearest confirmed windows by feature distance attached to each envelope); per-point model choice from the eval numbers; borderline ensembling (three samples at higher temperature on the 0.3 to 0.7 band, majority vote); envelope compression (the ten most deviating features and a path histogram above 20 turns); fine-tuning a small model on confirmed labels and classified paths once a few thousand exist.

## 7. Tests

- `llm eval` on a fixture set writes an `llm_evals` row with the expected agreement for a stubbed endpoint.
- Each faithfulness check has a positive and a negative fixture.
- Queue order on a fixture store matches section 4 exactly, with `why_in_queue` set.
- A proposal with a failed check lands with that signal dropped and the failed list logged; it lands as `unknown` only when no surviving signal sits on the label's side.
