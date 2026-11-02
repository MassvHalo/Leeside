# Golden sets (docs/llm-evals.md section 1)

One JSONL file per point. Nothing here comes from the model's own
proposals: label rows are built from generator stores with run-kind
ground truth, explain rows from the e2e store's scored subjects,
draft rows from attack-run clusters, and classify rows are
hand-written test vectors.

- `label.jsonl` (138): `llm eval-build --point label` (latest and
  `--early` windows) across all 20 generator runs, deduped and
  spread-sampled. `expected_label` is prefilled from the window's
  labels (operator, then tool_run/synthetic_benign/verified_business);
  the 44 cold-start cluster windows with no label were hand-labelled
  from run-kind ground truth (`prefilled_from: hand`). The attack
  rows expect `malicious`, the benign rows `benign`. `allowed_signals`
  follows the label: malicious rows allow the nine malicious signals
  plus `insufficient_data`, benign rows the two benign signals plus
  `insufficient_data`. Covers both scopes, 13 kinds, the cookie-
  keeping scraper, the benign api client, and 98 cold-start windows.
  No attack-promo rows: outcomes do not exist yet.
- `classify.jsonl` (203): hand-written, 103 `none`. The `creds`
  rows carry per-row tells only (default pairs, forged sigs, dead
  keys): a single normal-looking login is `none`, since volume is
  invisible in one sample.
- `explain.jsonl` (50): 39 scored e2e windows via `eval-build`
  (`must_mention` prefilled from the top-3 names) plus 11 rows that
  reuse e2e windows with varied scores for coverage (marked
  `derived_from`; grading checks mentions and length, not the score).
- `draft.jsonl` (22): one row per attack shape per run timestamp
  (near-duplicate reruns kept: they are distinct clusters).
  `expected_scope`/`expected_surface` hand-set from the cluster's
  traffic; `any` means the rule should carry no surface filter.
