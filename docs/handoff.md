# Leeside: working notes for the coding agent

Save as `docs/handoff.md`. Read this first in every session, then the brief that covers the piece you are working on. This file is the state of the project and the queue of work as of 31 Oct 2026; the briefs are the contracts. When code and a brief disagree, change the brief in the same commit and mark the resolution inline in bold, as `docs/actor-identity.md` already does.

## 1. The repo and the box

- One repo, `~/meta-hackathon/Leeside`, on an Ubuntu EC2 box that also serves the sample app. Directories: `leeside-laravel` (Composer package), `leesided` (Rust daemon), `leeside-sample` (Laravel app, deploy scripts, e2e harness), `docs/` (contracts).
- Ports: 7390 is the deployed leesided and is never touched by anything synthetic. 7391 is the e2e instance. `bin/e2e.sh` refuses to start when something already answers on its port.
- Deployed sample app: webapp.leeside.halowifi.com behind nginx 1.28 + php-fpm 8.5 with Let's Encrypt.
- Nothing is pushed to a remote. Commits are local, one per component per step (contract, package, leesided, sample), tree clean at the end of every step.
- Context: Meta Global AI Developer Hackathon, startup track, Oct to Nov 2026. The product is a request-security layer for Laravel apps with a honeypot ambition: attackers get diverted into decoy responses, so attacker traffic must stay visible, never refused early.

## 2. How we work

1. **Design note before big pieces.** Anything the size of the actor resolver gets a note in `leesided/docs/` (hard rules, worked cases the tests will encode, schema, open choices at the end) and waits for a go-ahead. `actors.md` and `tap.md` are the pattern.
2. **Tests gate every step.** fmt and clippy clean, the package suite green, the e2e green on 7391, before a step is reported done. Numbers go in the report.
3. **Briefs are contracts.** `docs/brief.md` (event schema v2), `docs/actor-identity.md`, `docs/windside.md`, `leesided/docs/actors.md`, `rules.md`, `tap.md`, the package README and AGENTS.md. Update them in the same commit as the code they describe.
4. **Report format.** Numbered against the points in the last note, a numbers table, a "for other directories" section for anything you need the operator to do, and open choices at the end with your recommendation. Flag anything that reverses an earlier instruction and say what forced it.
5. **Directory boundary.** You edit the repo. Deploy of the daemon, env secrets, GeoIP credentials, systemd units on the live box and pushing are the operator's. Report them, do not do them.
6. **Stop and ask** before: a migration that drops or loses rows, a change to a join key or an identifier recipe once data exists under it, anything that would touch 7390 or its database, anything outside the repo.
7. **Versioning rule.** Event schema, features, shape recipe and model manifests carry versions. Once real data exists under a version, bump rather than mutate. `a50732b` (the sorted shape recipe) could be replaced in place only because it never deployed.
8. **sudo rule.** A documented one-time dev step from `DEPLOY.md`, scoped to a build artifact (the `setcap` on the dev binary for the e2e tap act), is yours to run; anything else with sudo is not. Deploy scripts stay the operator's.
9. **Handoff maintenance.** Each step's commit also updates this file's sections 3 and 6 (state and queue).

## 3. Where things stand

| Component | State | Tests |
| --- | --- | --- |
| `leeside-laravel` | Event schema v2: surface classifier, UA class, keyed hashes, credential status (verified, rejected, unverified), webhook group `verifier → gate → RequireWebhookSigner`, tag cookie `_lsd`, request shape with header order canonicalised (`LEESIDE_HEADER_ORDER`), nine flags, proxy fingerprint headers from trusted proxy only, 32-hex `turn_id` on probe and event, `tag_id` on the probe when valid; gate probes ahead of `SubstituteBindings` (binding 404s gated), tag reads ahead of the gate; v2 `ts` is integer microseconds (`TurnContext::$tsUs`, `ts_ms` by intdiv), v1 keeps float seconds | 218 |
| `leesided` | v1 and v2 accepted, v3 rejected; rules grammar with `match.surface`, scopes peer/session/credential/actor, `credential_status` filter, `distinct.field` with `where`; peer suppression only for verified credentials; actor resolution (per-kind identity rule, provisional bindings, sweep, `cluster_key`, deterministic ids from `turn_id`); enrichment via `maxminddb` (null until files exist); features v2 (38 names, `feature_vectors` with the triggering turn's `surface`, actor rows for confirmed actors only, cluster rows for all turns); passive tap (`leesided tap`, JA4/JA4T fill with 60 s deferred fill, curated JA4 classes, `ja4+asn` weak bindings); labels (migration 0009: `labels` with `kind`, `honeytoken_hits`, `labels_test_eligible` view; auto-labelers honeytoken/verified_business in the engine, rule_decision on the check join; `leesided label-import <manifest>` by warmup watermark); clock hardening (migration 0010: `feature_vectors` keyed by `turn_id`, `turns.ingest_seq` replay order, `clock_anomalies` provenance, tap join ±1 s); training export (`leesided export --since --run-id --out`: run_id split key, `ingest_seq` order, per-run counts under kind in the manifest, chosen label per window); wire `ts` is `TsWire` (v2 integer µs required, v1 float seconds with its `(peer_key, ts_us)` join bitwise untouched, mismatches are bad lines; v1 ts lookups keep a ±1µs tolerance for the float hop); shadow scoring (migration 0011: `scores` plus actor score columns; native LightGBM predictor matching the booster to 3e-9; `score` rule conditions gated on active mode; `report shadow` with the verified-credential FP headline; `/health` windside section); cluster-row scoring (migration 0012: `scores` keyed by scope/scope_id, per-scope floor and counts, headline stays actor-only); review CLI (`leesided review`, operator labels); `/health` migration_version); `scores` keyed (`scope`, `scope_id`, `turn_id`) folded into 0012; labels append with latest-wins reads (0013); LLM module (0014: `llm_jobs`, `llm_calls`, `labels.signals`; off/dry/live, JSON-mode probe, prompt registry, queue worker on a 30 s tick, `llm show` and `llm send`); point 1 wired (scorer and review enqueue, proposal beside each row, `c` confirms); e2e runs the daemon in shadow and asserts scored rows for both scopes; model 0.1.0 manifest + text model committed; migrations 0001 to 0014 | 111 unit, proptest, 34 integration |
| `leeside-sample` | Routes for every surface (`/`, `/about` with assets, `/api/ping`, `/webhooks/demo`, hidden link, `/admin-backup`); `encryptCookies(except: ['_lsd'])`; `VerifyWebhookSignature`; `deploy/deploy.sh`, `install.sh`, `header-order-check.sh` (result on this box: `reversed`); env examples with the tag secret; `bin/traffic.sh`; generators `bin/benign.sh`, `bin/attack.sh`, `bin/tools.sh`, `bin/label-runs.sh`, `bin/export-runs.sh` (23 green runs in `runs/`: second runs of all 8 attack kinds plus api and webhook for holdout blocks; manifests carry the warmup watermark plus sent/stored/received/bad/dropped with a tripwire; runs checkpoint the WAL before copying and clean the work dir on success; browser sent derives from the artisan log; work dir on disk via `LEESIDE_RUN_TMP`, default `runs/tmp`, sockets stay on /tmp); dataset `runs/dataset.csv`, 7666 rows × 48 cols, 13 kinds; `bin/offbox-api.sh` (off-box partner client for the shadow week); tap stand-in unit renamed `leeside-artisan-tap.service` | 6 |
| `windside/` | Training project: `train.py` (latest run per kind, (run_id, scope_id) groups cut by ingest_seq at the 80th percentile, per-kind cap, LightGBM + ONNX), `eval.py` (per surface/kind/holdout-block, top-20 errors with run_id/kind/scope_id/top-3 SHAP), `inspect.py`; model 0.1.0: thresholds on pooled holdouts (api t=0.785, web t=0.5 met-False on a single-class holdout, webhook t=0.797; gap midpoint kept), holdouts lead, in-run split labeled smoke check, 5 holdout errors; eval notes the threshold circularity | train + eval runs |
| Last e2e | 65 turns, 65 probes joined, 65 cluster rows, 3 with ja4, 0 rejected, 0 unjoined | |

Latest commits: `ecf3b8f` (contract and package: int ts), `77eb0e6` (leesided: int ts, shadow), `2f1f0c9` (sample: offbox client), `37461ba` (windside: holdout thresholds), `76138a9` (docs: runbook, windside, handoff), all pushed. Uncommitted at this tick: this step's per-component sets (leesided cluster scoring + review CLI; sample unit rename; windside eval note; docs DEPLOY/brief/windside/handoff).

## 4. Standing rules (invariants, do not relitigate)

- Raw IP, raw UA, tokens, session ids and cookie ids are never stored. The IP travels over the local socket only and is hashed on receipt; the tag's event field is a keyed hash of the cookie id. The tap (section 6) inherits the same exception.
- The package records facts; leesided resolves identity. No `actor_id` is ever minted in PHP.
- The probe path has a sub-millisecond budget: no database lookups of the package's own, and an app-bound `CredentialVerifier` must be cheap.
- Verified, not presented: a credential suppresses per-IP rules only when verified. Unverified credentials are rated per peer; a 401 or 403 marks them rejected.
- Forged webhooks reach leesided. The verifier marks, the gate probes, refusal happens after.
- Surfaces decide expectations. Browser-shaped checks run on `web` and `honeypot`; never compute rate per IP on `api` or `webhook` when a verified credential is present.
- Identity: principals and verified credentials identify a person or system; sessions and tags identify a browser. Per-kind test (principals decide when both sides hold one; otherwise a shared credential; sessions and tags never partition). Weak keys never merge. No actor without a strong identifier; session and tag bindings are provisional for 24 h until they return. Turns keep the `actor_id` they were ingested with; merges keep the older id canonical.
- Features: rule outcomes and raw identifiers are never features; counts of distinct hashes are. Actor rows only for confirmed actors; cluster rows for every turn with a `cluster_key`.
- The LLM is never on the probe path and never decides. See `docs/llm.md`.
- Everything synthetic (generators, e2e, header-order check) runs on 7391 or private ports, never 7390.

## 5. Decisions already given, not yet applied

1. **`docs/windside.md` is in the repo** with the repo's numbering (v1 pre-Windside, v2 the Windside vector). Check the features v2 work against its sections 1 and 9 as they stand; the only tests it still lists as open are window boundaries and per-surface separation. Then proceed from its step 2.
2. **e2e probe count.** It dropped from 43 to 30 on the same 62 turns between the actor-resolution run and the features v2 run. Determine whether the acts or the counting changed and make the e2e output say which.
3. **Tap note (`leesided/docs/tap.md`): go-ahead with these answers to its open choices.**
   - Interface: the real one in production, `LEESIDED_TAP_IFACE`, default the default-route interface; `lo` allowed for the e2e. The e2e's private nginx gets a TLS listener with a self-signed certificate so curl `--insecure` produces a real JA4 fixture.
   - JA4T on port 80: yes. SYNs on 80 and 443; a plain-HTTP or redirect request has no JA4 but has JA4T.
   - Connection lifetime: map entry from SYN until FIN or RST plus 30 s grace, 5 minute idle cap, bounded size with LRU eviction. Join on `(ip, remote_port)` with the turn's `ts_ms` inside `[syn_ts, close_ts + grace]`.
   - Add before code: the race (event may arrive before the tap's ClientHello message; keep a deferred fill that retries unmatched turns for 60 s, then leaves the columns null; test by delivering the tap message after the event) and the privacy statement (the tap sends `(ip, port)` over the socket under the same exception as the package; leesided hashes on receipt; nothing raw is written).
   - `ua_vs_ja4_mismatch`: classify JA4 against a curated data file (FoxIO's public JA4 database at ja4db.io maps fingerprints to applications), default class `unknown`; the flag fires only on a known library JA4 under a browser UA. No heuristics from cipher counts.
   - `h2_fp` stays null; the HTTP/2 SETTINGS frame is inside TLS.

## 6. Work queue, in order

Each item ends with a report. Items A and B can interleave if the tap is waiting on anything.

**A. Tap** — DONE (`c26a882`, `536b333`). Landed per the acceptance: own unit with `CAP_NET_RAW`, e2e TLS fill `3|3|3`, deferred-fill test, `ja4+asn` weak bindings, `/health` tap state, nothing raw; features stay v2.

**B. Generators and manifests** (`docs/windside.md` section 4) — DONE, 13/13 runs. `bin/benign.sh` (Playwright page walks with assets and think time, a login, partner API calls with a valid key at 210 turns, signed webhooks at 204 turns) and `bin/attack.sh` (ffuf, sqlmap, nuclei, scraper with and without cookies, credential stuffing, webhook forgery, honeytoken crawl), one kind per run with a fresh store on 7391, each writing a manifest to `runs/`. 12 green runs: every attack kind ≥89 turns, every benign ≥102. Manifests carry sent/stored plus the daemon's received/bad/dropped, and the run fails loudly on sent≠stored or any bad/dropped event. Forensics closed: the count clock is the request's `ts_ms`; shortfalls were backward clock steps (100–700 ms, this box's CLOCK_REALTIME jumps; host-side, chrony clean) and transport/undercount artifacts (4 MB SO_RCVBUF, nuclei connection aborts invisible to the artisan log, memory-cached goBacks). Operator ran `bin/tools.sh`; chromium/firefox reran green on system libs (102/102 each) and webkit landed first try (114/114). The user-space sysroot (`~/.playwright-sysroot`) is retired, not deleted. Environment note: `/tmp` is a 918M tmpfs — a full tmpfs once failed a run with SQLite IOERR batches, so green runs now delete their work dir; `/tmp/pwdebs` (145M, not the agent's) is the operator's to judge.

**C. Labels** (section 3) — DONE. `labels` table plus `kind` (the manifest's run kind, NULL for run-less sources), `honeytoken_hits`, and the `labels_test_eligible` view enforcing the test-set contract; automatic labelers (`honeytoken` with the following hour, restart-safe; `verified_business` on verified credential + business route + sub-400; `rule_decision` at 0.5 from block verdicts and sticky replays only, blocks only until eval says otherwise); `leesided label-import <manifest>` labelling by warmup-watermark membership (clock-step-proof; pre-watermark DBs keep their verified interval labels). Acceptance met: import labels exactly the interval (2 new unit tests), auto-labelers covered by 3 integration tests, `rule_decision` excluded from the view by construction. All 12 run DBs imported (`bin/label-runs.sh`); counts by source and kind in the step-C report below.

**D. Export** (section 2) — DONE, then extended with the run_id split key: `--run-id`, `ingest_seq` in the CSV, per-run counts under each kind in the manifest. `leesided export --since <unix_s> --run-id <id> --out <csv>` writes one row per labeled window (38 feature names, split keys, chosen highest-confidence label; unlabeled and older-version rows excluded, `clock_anomalies` excluded). `bin/export-runs.sh` concatenates all runs. Acceptance met: round-trip test green; dataset now 7666 rows over 23 runs, zero benign/malicious disagreements.

**E. Training project** `windside/` (section 5) — DONE. `train.py` (latest run per kind trains/tests, per-kind cap 250, `scale_pos_weight` from train), `eval.py`, `inspect.py`; split groups by (`run_id`, `scope_id`) cut by `ingest_seq` at the 80th percentile (whole-group infeasible: single-scope runs would leave kinds with no test rows); earlier runs are holdout blocks; threshold is the gap midpoint when separable else max-R at P≥0.98, per surface. Model 0.1.0: t≈0.5 all surfaces, test P=R=1.0, 8/8 attack holdouts R≥0.99, benign fpr≈0.005, 9 errors total (set exhausted). Also in this step: second runs of all 8 attack kinds + api + webhook (23 runs), `LEESIDE_RUN_TMP` work dir on disk (default `runs/tmp`, sockets stay on /tmp for the 108-char `sun_path` limit), §5 rewritten for one-run-per-kind + ingest_seq split. Acceptance met: metrics per surface/kind/holdout in the step-E report below; the 9 errors carry run_id, kind, scope_id and top-3 SHAP features. Revised after acceptance: thresholds on the pooled holdouts (gap midpoint kept), eval leads with the holdout blocks and labels the in-run split leaky-by-construction smoke check; web threshold unset (t=0.5, met False, single-class holdout: no benign web second run).

**F. Shadow scoring** (section 6) — DONE. `WINDSIDE_MODEL` + `WINDSIDE_MODE`, migration 0011 (`scores`, actor score columns), native LightGBM predictor (no ONNX path: `ort` 1.x yanked, only a 2.0 RC installs — bold resolution in §6; parity 3e-9 on 7666 rows), `score` rule conditions pre-resolved on the probe and gated on active mode, cold-start floor `turns_held >= 5`, `report shadow` (verified-credential FP headline per surface, per-actor agreement, disagreements ranked, decile distribution, scored/skipped), `/health` windside section with the refusal reason. Actor rows only; cluster scoring deferred; top3 is path gain, not SHAP. Acceptance met: shadow writes scores with a score rule present and decides nothing (2 scored, 5 skipped in the fixture), mismatch refuses with the reason on `/health`. Also in this step: v2 `ts` to integer microseconds (package + daemon + brief; strict per-version parsing, v1 path bitwise untouched), `bin/offbox-api.sh` + production key/route docs, and the first-v2-deploy runbook (0005–0014, mutual-incompatibility warning) in DEPLOY.md. Extended after acceptance: cluster rows score (migration 0012, per-scope floor and counts in the report and `/health`), verified-credential headline stays actor-only; `scores` keyed (`scope`, `scope_id`, `turn_id`) folded into 0012.

**G. Review CLI, then the LLM module and the label assistant** (section 7 and `docs/llm.md`) — HALF DONE. Review CLI landed: `leesided review [--top 20]`, actors by latest score with window summary and top features, b/m/u per row (Enter skips, q quits), operator labels at 1.0, append-only with latest-wins reads (0013). Operator labels append, not overwrite, landed with it. The LLM module is built (Baseten endpoint decision applied): config, JSON-mode probe, `prompts/label.md` registry, `llm_jobs`/`llm_calls` (0014), schema validation for all four points, worker on a 30 s tick, `llm show` and `llm send`; point 1 wired (rows above 0.5 and opened reviews enqueue, proposal beside each row, `c` confirms, own verdict rejects). Points 2 to 4 follow. The operator reviews three live sends from the e2e store, then flips the unit env from dry to live. Acceptance per `docs/llm.md`.

**H. Active mode** (section 6): the three install-set rules, off by default, only after a shadow report on real traffic.

**Later:** leesided as TLS front for the H2 fingerprint; the honeypot route group and the `divert` decision; investigation chat and honeypot responses from `docs/llm.md`.

## 7. Operator checklist (not yours; listed so you can reference it)

- Deploy leesided with migrations 0005 to 0007 together with the package from `6e3fe9f` or later.
- GeoIP: `LEESIDED_GEOIP_ACCOUNT_ID` and `LEESIDED_GEOIP_LICENSE_KEY` in `/etc/leeside/leesided.env`, `/etc/GeoIP.conf` for `/var/lib/GeoIP`, weekly `geoipupdate` timer; `LEESIDED_GEOIP_ASN` and `LEESIDED_GEOIP_COUNTRY` paths in the unit.
- `LEESIDE_TAG_SECRET` set explicitly on the sample app; `LEESIDE_HEADER_ORDER=reversed` on production after `header-order-check.sh` confirms it there.
- Tap unit with `CAP_NET_RAW` once A lands.

## 8. Report template

```
## <step name>, <state>

### Your N points
1. ...

### What's built
...

### Numbers
| | |
|---|---|
| package / sample / leesided tests | |
| e2e | |

### For other directories
- ...

### Open choices
- <choice>: <recommendation>
```
