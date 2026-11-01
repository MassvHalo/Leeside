# Windside training project

Python with uv. Scripts, not a package: `train.py`, `eval.py`, `inspect.py`.

## Environment

```bash
cd windside
uv venv
uv pip install -e .
```

Run from this directory with the venv active (`source .venv/bin/activate`),
or prefix with `uv run --no-sync`.

## Pipeline

```bash
uv run python train.py --dataset ../leeside-sample/runs/dataset.csv \
    --manifest ../leeside-sample/runs/dataset.csv.manifest.json \
    --out models/0.1.0 --cap 250 --seed 7
uv run python eval.py --model models/0.1.0
uv run python inspect.py --model models/0.1.0 \
    --run-id attack-nuclei-20261101T043840Z --scope cluster \
    --scope-id <key> --ts-us <ts>
```

## Rules

- The feature matrix comes from the manifest's `feature_names`, never from
  the key columns (`scope`, `scope_id`, `surface`, `kind`, `run_id`,
  `ts_us`, `ingest_seq`).
- Test rows come from `labels_test_eligible` sources only; disagreements
  and `rule_decision`/`llm_proposed`/`verified_business`-only windows never
  test (docs/windside.md section 5). The export's chosen label is the
  highest-confidence one per window.
- Latest run per kind trains and tests; earlier runs are holdout blocks.
- Accuracy is not reported anywhere. Thresholds target precision ≥ 0.98
  per surface; recall is reported, not targeted.
