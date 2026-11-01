#!/usr/bin/env python3
"""Evaluate a Windside model (docs/windside.md section 5).

Scores the test split and the holdout blocks with the trained booster at
the per-surface thresholds, and writes eval.json: metrics per surface and
per kind, confusion counts, feature importance, the holdout blocks, and
the 20 highest-confidence errors with their run_id, kind, scope_id and
top three features by |SHAP|. Accuracy is not reported anywhere.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# inspect.py shadows the stdlib module of the same name; drop this
# directory from the import path before third-party imports.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]

import lightgbm as lgb
import numpy as np
import polars as pl
import shap
from sklearn.metrics import average_precision_score


def pr_at_threshold(y: np.ndarray, p: np.ndarray, t: float) -> dict:
    pred = (p >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    return {
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "support": len(y),
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    mdir = Path(args.model)
    manifest = json.loads((mdir / "manifest.json").read_text())
    names = manifest["feature_names"]
    thresholds = manifest["thresholds"]
    booster = lgb.Booster(model_file=str(mdir / "model.txt"))

    test = pl.read_csv(
        mdir / "test.csv", schema_overrides={n: pl.Float64 for n in names}
    ).with_columns((pl.col("label") == "malicious").cast(pl.Int32).alias("y"))
    p = booster.predict(test.select(names).to_numpy())
    test = test.with_columns(pl.Series("p", p))

    surfaces: dict[str, dict] = {}
    for surface in sorted(test["surface"].unique()):
        sub = test.filter(pl.col("surface") == surface)
        y = sub["y"].to_numpy()
        ps = sub["p"].to_numpy()
        t = thresholds.get(surface, {}).get("threshold", 0.5)
        m = pr_at_threshold(y, ps, t)
        m["threshold"] = t
        m["pr_auc"] = (
            float(average_precision_score(y, ps)) if y.sum() not in (0, len(y)) else None
        )
        surfaces[surface] = m

    kinds: dict[str, dict] = {}
    for kind in sorted(test["kind"].unique()):
        sub = test.filter(pl.col("kind") == kind)
        y = sub["y"].to_numpy()
        ps = sub["p"].to_numpy()
        ts = np.array([thresholds.get(s, {}).get("threshold", 0.5) for s in sub["surface"]])
        pred = (ps >= ts).astype(int)
        tp = int(((pred == 1) & (y == 1)).sum())
        fp = int(((pred == 1) & (y == 0)).sum())
        tn = int(((pred == 0) & (y == 0)).sum())
        fn = int(((pred == 0) & (y == 1)).sum())
        kinds[kind] = {
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "pr_auc": (
                float(average_precision_score(y, ps))
                if y.sum() not in (0, len(y))
                else None
            ),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "support": len(y),
        }

    gain = dict(zip(booster.feature_name(), booster.feature_importance("gain")))
    importance = sorted(gain.items(), key=lambda kv: kv[1], reverse=True)[:15]

    def wrong_frames(df: pl.DataFrame, block: str) -> pl.DataFrame:
        thr = df["surface"].map_elements(
            lambda s: thresholds.get(s, {}).get("threshold", 0.5)
        )
        pred = (df["p"] >= thr).cast(pl.Int32)
        return df.with_columns(
            (
                pl.when(pl.col("y") == 1)
                .then(1 - pl.col("p"))
                .otherwise(pl.col("p"))
            ).alias("err_conf"),
            pl.lit(block).alias("block"),
        ).filter(pred != pl.col("y"))

    explainer = shap.TreeExplainer(booster)
    holdout_early = pl.read_csv(
        mdir / "holdout.csv", schema_overrides={n: pl.Float64 for n in names}
    ) if (mdir / "holdout.csv").exists() else None
    if holdout_early is not None and holdout_early.height:
        holdout_early = holdout_early.with_columns(
            (pl.col("label") == "malicious").cast(pl.Int32).alias("y")
        )
        ph = booster.predict(holdout_early.select(names).to_numpy())
        holdout_early = holdout_early.with_columns(pl.Series("p", ph))
    frames = [wrong_frames(test, "test")]
    if holdout_early is not None and holdout_early.height:
        frames.append(wrong_frames(holdout_early, "holdout"))
    wrong = pl.concat([f for f in frames if f.height]).sort("err_conf", descending=True).head(args.top) if any(
        f.height for f in frames
    ) else test.head(0)
    errors = []
    if wrong.height:
        sv = explainer.shap_values(wrong.select(names).to_numpy())
        if isinstance(sv, list):
            sv = sv[1]
        for i, row in enumerate(wrong.rows(named=True)):
            order = np.argsort(-np.abs(sv[i]))[:3]
            errors.append(
                {
                    "block": row["block"],
                    "run_id": row["run_id"],
                    "kind": row["kind"],
                    "scope": row["scope"],
                    "scope_id": row["scope_id"],
                    "surface": row["surface"],
                    "ts_us": row["ts_us"],
                    "true_label": row["label"],
                    "p_malicious": round(float(row["p"]), 6),
                    "top_features": [
                        {"name": names[j], "value": float(row[names[j]]), "shap": round(float(sv[i][j]), 4)}
                        for j in order
                    ],
                }
            )

    holdouts: dict[str, dict] = {}
    holdout = holdout_early
    if holdout is not None and holdout.height:
        for run_id in sorted(holdout["run_id"].unique()):
            sub = holdout.filter(pl.col("run_id") == run_id)
            y = sub["y"].to_numpy()
            ps = sub["p"].to_numpy()
            ts = np.array([thresholds.get(s, {}).get("threshold", 0.5) for s in sub["surface"]])
            pred = (ps >= ts).astype(int)
            tp = int(((pred == 1) & (y == 1)).sum())
            fp = int(((pred == 1) & (y == 0)).sum())
            tn = int(((pred == 0) & (y == 0)).sum())
            fn = int(((pred == 0) & (y == 1)).sum())
            holdouts[run_id] = {
                "kind": sub["kind"][0],
                "precision": tp / (tp + fp) if tp + fp else None,
                "recall": tp / (tp + fn) if tp + fn else None,
                "pr_auc": (
                    float(average_precision_score(y, ps))
                    if y.sum() not in (0, len(y))
                    else None
                ),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "support": len(y),
            }

    (mdir / "eval.json").write_text(
        json.dumps(
            {
                "model_version": manifest["model_version"],
                "surfaces": surfaces,
                "kinds": kinds,
                "importance_gain": [{"name": n, "gain": int(g)} for n, g in importance],
                "errors": errors,
                "holdouts": holdouts,
            },
            indent=2,
        )
    )

    print(f"eval: test {test.height} rows, holdout {holdout.height if holdout is not None else 0} rows")
    for surface, m in surfaces.items():
        print(f"  surface {surface}: P={m['precision']} R={m['recall']} PR-AUC={m['pr_auc']} n={m['support']}")
    for kind, m in kinds.items():
        print(f"  kind {kind}: P={m['precision']} R={m['recall']} n={m['support']}")
    for run_id, m in holdouts.items():
        n_mal = m["tp"] + m["fn"]
        if n_mal == 0:
            print(f"  holdout {run_id} ({m['kind']}): fp={m['fp']}/{m['support']} fpr={m['fp'] / m['support']:.4f} n={m['support']}")
        else:
            print(f"  holdout {run_id} ({m['kind']}): P={m['precision']} R={m['recall']} PR-AUC={m['pr_auc']} n={m['support']}")
    print(f"  top-{args.top} errors:")
    for e in errors:
        feats = ", ".join(f"{f['name']}={f['value']:.2f}" for f in e["top_features"])
        print(f"    [{e['block']}] {e['run_id']} {e['kind']} {e['scope_id']} true={e['true_label']} p={e['p_malicious']}: {feats}")


if __name__ == "__main__":
    main()
