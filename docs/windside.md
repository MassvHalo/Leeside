# Windside: actor scoring

Brief for leesided (features, labels, export, scoring), leeside-sample (traffic generators), and a new `windside/` training project. Follows docs/actor-identity.md; the unit of analysis here is the actor that brief produces.

## Why this exists

A request on its own carries almost no signal. Bots and humans differ over time: cadence, path spread, what they load, how consistent their fingerprints stay, what they do when challenged. Windside scores actors over rolling windows, writes the score back onto the actor, and the existing rules engine decides what to do with it. The score is an input to rules, never a verdict by itself.

## 0. Prerequisites (all landed as of 31 Oct 2026)

- Actor resolution from actor-identity section 8: `actor_id` per turn for confirmed actors, null for turns with no strong identifier, `cluster_key` on every turn with net and shape (commits `285b9b2`, `a593863`).
- The tag cookie (actor-identity section 3) and `credential_status` (from the step 2 review), since several features read them.
- Features v2 in leesided (commit `20358ca`): 38 names in `src/rules/features.rs`, rows in `feature_vectors` (migration 0007), `features_version` on `/health`, denylist and determinism tests. Section 1 below describes that vector and the target set it grows into.

Naming: the repo's features v1 is the pre-Windside vector that the rule windows used. Features v2 is the Windside vector. Everywhere this brief, the training manifest and `/health` say a version, it is the repo's numbering.

## 1. Feature windows (leesided)

Features v2 is per-turn rows over a count window. Each scope holds the newest 64 turns in ingest order, oldest-ingested evicted first, with no expiry by time; every ingested turn recomputes the window it touched and writes one row to `feature_vectors`. One row per (`scope`, `key`, `turn_id`), plus the triggering turn's `surface` (migration 0008, null for v1 turns) so eval and the precision threshold can run per surface. Window order, eviction and restart replay all go by ingest sequence, never by stamp, so a backward clock step cannot reorder or evict rows; inter-request intervals clamp at zero and the window's count of negative intervals rides each row as `clock_anomalies` provenance (migration 0010), never as a feature. Two scopes:

- `actor`: a row only when the resolved actor is `confirmed`. A provisional actor holds one turn and is noise as a feature row; when an actor confirms, its earlier turns already carry its id, so its first window is complete without a backfill.
- `cluster`: a row for every turn that has a `cluster_key`, provisional or not. This is how cookie-less traffic stays scorable.

Windows mix surfaces: one actor on `web` and `api` shares a single window, and the four surface indicators name the newest turn's surface. Per-surface window separation stays deferred until eval on real traffic shows contamination; the indicators carry the mix until then.

Schema version `features_version: 2`, reported by `/health` the same way as schema and model versions. Adding a feature is a version bump; the training manifest refuses a mismatch (section 6).

Features v2 as built: the 30 names of the repo's v1 plus `cluster_actors_net`, `shape_cluster_size`, `tag_dropped` (issued on this window, then a tagless turn on the same window), `credential_moved` (one credential from two networks inside the window), and four surface indicators. The table below is the target set the vector grows into; names already in v2 stay as they are, the Fingerprint group arrives once the tap (leesided/docs/tap.md) has produced enough JA4 and JA4T to train on, and the Honeypot group with the honeypot route group.

Target set (all per window; counts are integers, rates and ratios are floats, flags-as-rates are fractions of requests in the window):

| Group | Features |
|---|---|
| Volume | `req_count`, `req_rate_per_min`, `bytes_in_total`, `bytes_out_total` |
| Paths | `distinct_paths`, `path_entropy`, `distinct_methods`, `post_ratio`, `query_param_ratio`, `max_path_depth` |
| Status | `rate_2xx`, `rate_3xx`, `rate_404`, `rate_401_403`, `rate_429`, `rate_5xx` |
| Timing | `iri_median_ms`, `iri_p10_ms`, `iri_cv` (coefficient of variation of inter-request intervals), `burst_max_per_10s`, `active_seconds` |
| Assets | `asset_ratio`, `html_without_assets_count` |
| Consistency | one rate per flag from actor-identity section 5: `f_ua_chromium_no_ch`, `f_browser_no_sec_fetch`, `f_browser_no_accept_language`, `f_html_get_no_html_accept`, `f_library_ua_on_web`, `f_cookies_on_api`, `f_bearer_with_sec_fetch`, `f_tag_bad_mac`, `f_proxy_header_untrusted` |
| Identity | `distinct_ua_hash`, `distinct_shape_hash`, `distinct_net_hash`, `distinct_asn`, `tag_dropped_count`, `tag_moved_count`, `session_count`, `has_auth_id` |
| Credentials | `distinct_credentials`, `rejected_credentials`, `credential_moved_count`, `credential_status_rate_verified` |
| Fingerprint | `ja4_present`, `ja4_class_mismatch_rate` (browser UA class with a library JA4), `distinct_ja4`, `ja4t_os_mismatch_rate` |
| Honeypot | `honeytoken_hits`, `hidden_link_follows` |
| Context | `surface` (categorical), `ua_class` (categorical, majority), `window_kind` |

Three rules on features:

- Rule outcomes are never features. No "was 429'd", no sticky state, no decision counts. A test (section 9) checks the feature schema against a denylist.
- Raw identifiers are never features. Hashes identify; counts of distinct hashes describe. `distinct_net_hash` is a feature, `net_hash` is not.
- Store raw counts and rates, not transformed values. Scaling and log transforms belong in training.

Target for v3: time windows (5 minutes and 60 minutes per scope) replacing the 64-turn count window, a row written every 60 seconds while the scope is active plus once when it goes idle — one row per (`scope`, `scope_id`, `surface`, `window_kind`, `window_end_ts`) — and per-surface window separation if eval shows the mixed windows contaminate. v3 is a version bump with a migration, taken only with JA4 data worth training on.

## 2. Export

`leesided export --since <unix_s> --run-id <id> --out <csv>` (plus `bin/export-runs.sh`, which concatenates every run database into one dataset) reads `feature_vectors` and `labels` and writes one CSV row per labeled window: the v2 feature names in order, then the split keys (`scope`, `scope_id`, `surface`, `kind`, `run_id`, `ts_us`, `ingest_seq`), then the chosen label with its source and confidence. The run id comes from the manifest (the store holds no run); the ingest sequence comes from the row's turn and is the split order within a run. The chosen label is the window's highest-confidence one; windows with no label are not training rows and are excluded, as are rows from an older vector version. `clock_anomalies` is excluded: provenance, not a feature.

A manifest lands next to the CSV with `features_version`, the `feature_names`, row counts per scope and per kind, label counts by source, and the time range. `train.py` builds the feature matrix from the manifest's feature names and never from the key columns. Switch to Parquet before the dataset passes a few hundred thousand rows. Export is the only path from leesided to training; the training project never queries the database.

## 3. Labels

`labels` table: `id`, `scope` (`actor` or `cluster`), `scope_id`, `surface`, `window_end_ts`, `label` (`benign`, `malicious`, `unknown`), `source`, `confidence` (0 to 1), `kind`, `note`, `created_at`. Labels attach to windows, not actors, because an actor can turn malicious mid-life; cluster windows take labels the same way, which is how tool runs that never return a cookie get labelled. `kind` is the manifest's run kind (e.g. `attack-nuclei`, `benign-api`), set by label-import; it is the key for per-kind sampling and per-kind eval (section 5), and NULL for labels with no run behind them (operator, llm_proposed, rule_decision).

Sources, with the confidence they carry:

| Source | How it's produced | Confidence | In test set |
|---|---|---|---|
| `operator` | review view or CLI (section 7) | 1.0 | yes |
| `tool_run` | generator manifest import (section 4) | 0.95 | yes |
| `synthetic_benign` | generator manifest import | 0.95 | yes |
| `honeytoken` | automatic: honeytoken hit labels the actor's windows for the following hour | 0.9 | yes |
| `verified_business` | automatic: verified credential plus a completed business action on the live app (app-defined route list) | 0.8 | no |
| `llm_proposed` | label assistant (section 8), pending operator confirmation | 0.6 | no |
| `rule_decision` | automatic from install-set block verdicts (blocks and sticky block replays; watch/log/rate-limit/challenge and proposed rules never label) | 0.5 | never |

Rule-decision labels bootstrap training and are excluded from evaluation without exception, otherwise the model is graded on how well it reproduces the rules. The exclusion is a view, `labels_test_eligible`, over the four test sources (operator, tool_run, synthetic_benign, honeytoken); train.py splits from the view, not the table.

Generator labels are applied by run membership, not by header and not by wall-clock interval: the generator records a warmup watermark (`warmup_last_turn_id`, once its two warmup turns have landed) and `leesided label-import <manifest>` labels every window in the fresh run store after it, whatever the turns' stamps say — a backward clock step cannot exclude a turn. The interval stays in the manifest for the record, and benign and malicious runs never overlap in time on the same instance.

## 4. Traffic generators (leeside-sample/bin)

All runs target the e2e instance on 7391, never the deployed 7390. Each run writes its manifest to `runs/`.

Benign (`bin/benign.sh`, Playwright under Chromium, Firefox and WebKit):
- page walks with asset loads, think time between 2 and 20 seconds, back navigation, a login and a logged-in session
- partner API calls with a valid key at a steady cadence (one every 5 to 30 seconds, occasional bursts of 20)
- webhooks with valid signatures, bursty (a dozen within a second, then quiet)

Malicious (`bin/attack.sh`, one kind per run):
- directory brute force (ffuf against the sample app wordlist)
- parameter injection (sqlmap on one query parameter)
- template scan (nuclei with a small template set)
- scraper: Python `requests` with a spoofed Chrome UA, no assets, fixed 300 ms cadence, in two variants: cookie-keeping and `--no-cookie` (fresh client per request, tag-dropping)
- partner API at 210 turns and signed webhooks at 204 turns per run; the machine surfaces need volume because the surface work exists to not flag partners
- generator traffic goes through `artisan serve`, so the tap sees none of it and `ja4` is null across the dataset; fine for v2 (no fingerprint features), but v3 runs generators through the private nginx TLS listener
- credential stuffing: random bearers and API keys from one address
- webhook forgery: bad signatures at high rate
- honeytoken crawl: follows the hidden link and hits `/admin-backup`

Each malicious kind should produce at least 50 windows; each benign browser at least 100. That's the first dataset.

## 5. Training project (`windside/`)

Python with uv. Dependencies: polars, lightgbm, scikit-learn, onnxmltools (LightGBM to ONNX), shap.

Scripts:
- `train.py`: reads the export, joins labels to windows, splits, trains a LightGBM binary classifier, writes `models/<version>/model.onnx`, the native LightGBM text model as fallback, and `manifest.json`.
- `eval.py`: precision, recall and PR-AUC per surface, per run kind, and overall, every earlier run of the same kind as a separate holdout block, confusion matrix at the chosen threshold, feature importance, the 20 highest-confidence errors with their run_id, kind, scope_id and top three features by |SHAP| for review.
- `inspect.py`: scores one feature row and prints SHAP contributions, for debugging a verdict.

Split: one run per kind is the training set and the rest are held out. Reruns of a seeded generator are near-duplicates, so `train.py` takes the latest run per kind for train and test, and `eval.py` reports every earlier run of the same kind as a separate holdout block ("same generator, different run"); the holdout numbers are the honest estimate of generalisation, not the in-run test split. Within the training runs the split groups by (`run_id`, `scope_id`) and cuts by `ingest_seq` within the group at the 80th percentile — by ingest sequence, not `ts_us`, since the clock work made stamps untrustworthy as an order — so the test side is strictly later-ingested than the train side. Whole-group splitting is infeasible: single-scope runs would leave some kinds with no test rows at all. Test set is operator, tool_run, synthetic_benign and honeytoken labels only.

Class imbalance: `scale_pos_weight` from the train split, and the decision threshold chosen on the pooled holdouts for precision at or above 0.98 per surface: the midpoint of the separation gap when the slice separates (maximum margin — a curve-only rule pins t at 1.0 on saturated outputs), else maximum recall subject to P ≥ 0.98. The in-run split is leaky by construction (sliding windows share content across the cut) and is a smoke check only; the holdout blocks are the evaluation. The api and webhook thresholds were chosen on the holdouts that contained the false positives, so the resulting zero counts are not estimates; the shadow report is. Recall is whatever that yields and is reported, not targeted. Accuracy is not reported anywhere.

Per-kind sampling: generation volume is not balanced (a nuclei run yields ~1700 rows, a honeytoken run 60), so balance happens in training, not in generation. `train.py` samples per run kind with a cap per kind, the kind read from `labels.kind`; rows whose kind is NULL (operator, llm_proposed) are never capped. The cap value is recorded in `manifest.json` next to the per-kind row counts before and after sampling.

Multiple labels per window: a window carries up to one label per source, so a machine row can hold both `synthetic_benign` and `verified_business`. `train.py` takes the highest-confidence label per window (the export's chosen label); any window whose labels disagree on benign versus malicious is reported by `eval.py` and excluded from the test set.

`manifest.json`: `model_version` (semver), `features_version`, `trained_at`, data time range, label counts by source, metrics per surface, `threshold`, `top_features`.

## 6. Scoring in leesided

Config: `LEESIDED_WINDSIDE_MODEL` (path to a model directory), `LEESIDED_WINDSIDE_MODE` (`off`, `shadow`, `active`). **Resolution, step F: the brief named `ort` as the loader with the native text model as fallback, but no stable `ort` exists (the 1.x line is yanked on crates.io; only a 2.0 release candidate installs), so leesided loads the native LightGBM text model directly (`leesided/src/windside.rs`) and there is no ONNX path until `ort` stables. The native predictor matches the booster to 3e-9 on the 7666-row dataset.** A manifest whose `features_version` does not match leesided's refuses to load, with the reason on `/health`. `/health` reports `windside.model_version`, `windside.mode`, `windside.features_version`.

On every feature row update: score the row, write to a `scores` table (`scope`, `scope_id`, `surface`, `ts`, `score`, `model_version`, `top3` as JSON). Actor rows also set `actor.score`, `actor.score_ts`, `actor.score_top3`, and only actor rows feed rule matching (rules reading cluster scores remain in H). The floor applies per scope: rows below five held turns are not scored and the skipped count is reported per scope. `top3` is split gain along the row's taken paths (path gain, not SHAP); training-side inspection keeps true SHAP.

Shadow mode: nothing reads the score. `leesided report shadow --since <ts>` prints agreement between score-above-threshold and rule decisions, the disagreements ranked by score, and the per-surface distribution of scores. Run shadow for at least a week of real traffic before active.

Active mode: rules may match `actor.score >= <x>` with actor scope. Install-set additions, all off by default:
- `windside-observe`: score at or above 0.7, decision `observe` (log only)
- `windside-challenge`: score at or above the manifest threshold, decision as configured (429 today, challenge later)
- `windside-honeypot`: score at or above 0.9 and `honeytoken_hits > 0`, decision `divert` once the honeypot group exists

Sticky decisions apply as today. Rollback is a config change to the previous model directory and a restart; keep the last three model directories on the box.

## 7. Review view

Minimum for the hackathon: `leesided review --top 20` prints actors by score with window summary and top features and accepts `b`, `m`, `u` per row, writing operator labels. Better, if time allows: a single HTML page served by leesided on localhost with the same list, the actor's recent turns, and three buttons. Every operator label is immediately exportable; retraining is a scheduled job, not triggered by labelling.

## 8. LLM roles

Never on the probe path. Outputs are proposals or text, never decisions.

- Label assistant: given a window's feature row and the actor's last 30 turns as JSON, propose `benign`, `malicious` or `unknown` with a one-paragraph reason. Stored as `llm_proposed` at 0.6 until confirmed in the review view, which upgrades it to `operator`.
- Verdict explanation: turn `top3` and the window summary into a sentence for the dashboard.
- Payload classifier, async: map a request path and body to a category (`sqli`, `traversal`, `enumeration`, `scanner_signature`, `none`), cached by a hash of the path pattern; the category counts join a later features version.
- Rule drafting: given a cluster of malicious windows, propose a match block for the rules file, for review.
- Honeypot responses: later, once the honeypot group exists.

Log every prompt and response with the model name, so a proposal can be audited.

## 9. Tests

Done in `20358ca`: determinism across a restart and a replay into a fresh store; the name denylist (rule-outcome and identifier tokens); 100 tagless turns give zero actor rows and one cluster window; an issued-then-valid pair gives one actor row covering both turns. Done with migration 0008: the 65th turn evicts the first (`turns_held` caps at 64 while `turns_total` grows); a row's `surface` equals its triggering turn's. The count window has no time boundary to test and v2 windows mix surfaces by decision (section 1), so the window-boundary and per-surface tests are dropped, not deferred. Still to add:

- Done with step D: export round-trip — CSV plus manifest, chosen label per window, header and row counts match the manifest, unlabeled and older-version rows excluded.
- Done with step C, updated for membership: label import from a manifest labels every window after the warmup watermark (a backward-stepped turn included), none before it.
- Shadow mode writes scores and changes no decision (a rule on score is present and does not fire).
- Active mode: the same rule fires on a score above threshold.
- A model manifest with the wrong `features_version` refuses to load and `/health` says why.
- In `windside/`: a split test proving the test side is strictly later-ingested than the train side within every (`run_id`, `scope_id`) group.

## 10. Do not

- Do not use rule outcomes or raw identifiers as features.
- Do not put an LLM call on the probe path, or anywhere a request waits on it.
- Do not evaluate on rule-decision labels, or report accuracy.
- Do not switch to active mode without a shadow report.
- Do not run generators against 7390.
- Do not retrain on every new label; retrain on a schedule from an export.

## Order of work

1. Features v2 and the `feature_vectors` table, with the determinism and denylist tests (leesided). Done, `20358ca`.
2. Generators and manifests (leeside-sample), run once to produce the first dataset.
3. `labels` table, automatic labelers, `label-import` (leesided).
4. Export, CSV first if needed, then Parquet (leesided).
5. `windside/` with `train.py` and `eval.py`; first model on generated data; report metrics per surface.
6. Shadow scoring, `scores` table, `report shadow` (leesided).
7. Review CLI, then the LLM label assistant.
8. Active mode and the three install-set rules, off by default, after a shadow report on real traffic.
