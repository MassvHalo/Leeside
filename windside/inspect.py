#!/usr/bin/env python3
"""Score one exported window and explain it (docs/windside.md section 5).

Locates a single row of the dataset by its split keys, scores it with the
trained booster at the row's surface threshold, and prints the top SHAP
contributions. Exactly one row must match.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# This file shadows the stdlib module of the same name; drop this
# directory from the import path before third-party imports.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]

import lightgbm as lgb
import numpy as np
import polars as pl
import shap


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--scope-id", required=True)
    ap.add_argument("--ts-us", type=int, required=True)
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args()

    mdir = Path(args.model)
    manifest = json.loads((mdir / "manifest.json").read_text())
    names = manifest["feature_names"]
    booster = lgb.Booster(model_file=str(mdir / "model.txt"))

    df = pl.read_csv(args.dataset, schema_overrides={n: pl.Float64 for n in names})
    row = df.filter(
        (pl.col("run_id") == args.run_id)
        & (pl.col("scope") == args.scope)
        & (pl.col("scope_id") == args.scope_id)
        & (pl.col("ts_us") == args.ts_us)
    )
    if row.height != 1:
        sys.exit(f"inspect: locator matches {row.height} rows, want exactly 1")
    r = row.row(0, named=True)
    p = float(booster.predict(np.array([[r[n] for n in names]]))[0])
    t = manifest["thresholds"].get(r["surface"], {}).get("threshold", 0.5)
    print(f"{r['run_id']} {r['kind']} {r['scope']}:{r['scope_id']} surface={r['surface']}")
    print(f"true={r['label']} p_malicious={p:.4f} threshold={t} decision={'malicious' if p >= t else 'benign'}")
    sv = shap.TreeExplainer(booster).shap_values(np.array([[r[n] for n in names]]))
    if isinstance(sv, list):
        sv = sv[1]
    for j in np.argsort(-np.abs(sv[0]))[: args.top]:
        print(f"  {names[j]}: value={r[names[j]]} shap={sv[0][j]:+.4f}")


if __name__ == "__main__":
    main()
