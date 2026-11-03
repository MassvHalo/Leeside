# Golden sets (docs/llm-evals.md section 1)

One JSONL file per point. Nothing here comes from the model's own
proposals: label rows are built from generator stores with run-kind
ground truth, explain rows from the e2e store's scored subjects,
draft rows from attack-run clusters, and classify rows are
hand-written test vectors.

- `label.jsonl` (148): `llm eval-build --point label` (latest,
  `--early`, `--sample 3`, and `--sample 5` on the small pools)
  across 23 generator run stores, minus pre-watermark windows on
  the unpurged stores (each row carries `window_turn_id` for the
  filter), deduped on the envelope, then stratified to 8 warm and
  up to 4 cold rows per kind, round-robin over subjects (latest
  windows first, coldest first). Browser rows come from the
  locale-fixed reruns only. `eval-build` anchors its clock to the
  store's last turn, so the same recipe byte-reproduces the set.
  Two rules hold on every row: the envelope pairs its window with
  exactly the turns up to that window's turn id
  (`len(turns) == min(turns_held, 30)`), and any row with
  `turns_held` under 10 expects `unknown`. `expected_label` is
  prefilled from the window's labels (operator, then
  tool_run/synthetic_benign/verified_business), or the cold-start
  rule (`prefilled_from: insufficient_data`); warm windows with no
  label would be hand-labelled from run-kind ground truth
  (`prefilled_from: hand`), of which this set needed none. The
  attack rows expect `malicious`, the benign rows `benign`, the 44
  cold rows `unknown`; the 8 cold rows on verified-clean subjects
  also accept `benign` (`also_accept`). `allowed_signals` follows
  the label: malicious rows allow the nine malicious signals plus
  `insufficient_data`, benign rows the four benign signals plus
  `insufficient_data`, unknown rows `insufficient_data` alone.
  Each turn carries `payload_hint`, null across this set: the
  attack runs predate sample capture, so no sqli/xss/traversal
  evidence survives in them. Covers both scopes, 13 kinds, the
  cookie-keeping scraper, and the benign api client. No
  attack-promo rows: outcomes do not exist yet.
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
