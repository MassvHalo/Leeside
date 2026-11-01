#!/usr/bin/env python3
"""Train the Windside v2 scorer (docs/windside.md section 5).

Reads the export CSV plus its manifest, builds the feature matrix from the
manifest's feature names only, and writes a versioned model directory with
the native LightGBM model, the ONNX conversion, the split, and a manifest.

Split: the latest run per kind trains and tests; earlier runs of the same
kind are holdout blocks. Within a run each scope cuts its rows by
ingest_seq at the 80th percentile, so the test side is strictly later.
Whole-group splitting is infeasible on this data (single-key scopes like
the api cluster cannot split at all, and skewed keys cut perversely), so
a scope id may span the cut; spanning ids are counted in the manifest.
Adjacent train/test rows share window content (64-turn sliding windows):
the in-run split is leaky by construction and is a smoke check only.
Thresholds are chosen on the pooled holdouts per surface. The train
side is capped per kind after the split; the test side keeps its
natural rows.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# inspect.py shadows the stdlib module of the same name; drop this
# directory from the import path before third-party imports.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path = [p for p in sys.path if os.path.abspath(p or os.getcwd()) != _HERE]

import lightgbm as lgb
import numpy as np
import polars as pl
from sklearn.metrics import precision_recall_curve

STAMP = re.compile(r"(\d{8}T\d{6}Z)$")
KEY_COLUMNS = (
    "scope",
    "scope_id",
    "surface",
    "kind",
    "run_id",
    "ts_us",
    "ingest_seq",
    "label",
    "source",
    "confidence",
)


def run_stamp(run_id: str) -> datetime:
    m = STAMP.search(run_id)
    if not m:
        sys.exit(f"train: run_id {run_id!r} carries no timestamp suffix")
    return datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")


def split_rows(df: pl.DataFrame, test_fraction: float) -> tuple[pl.DataFrame, pl.DataFrame]:
    """Cut one (run, scope) frame by ingest_seq: the top test_fraction of
    rows by sequence test, the rest train. The test side is strictly
    later; scope ids spanning the cut are the caller's to count."""
    ordered = df.sort("ingest_seq")
    n_test = min(max(1, round(ordered.height * test_fraction)), ordered.height - 1) if ordered.height > 1 else 0
    if n_test == 0:
        return ordered, ordered.head(0)
    return ordered.head(ordered.height - n_test), ordered.tail(n_test)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--version", default="0.1.0")
    ap.add_argument("--cap", type=int, default=250)
    ap.add_argument("--test-fraction", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    manifest = json.loads(Path(args.manifest).read_text())
    names = manifest["feature_names"]
    df = pl.read_csv(
        args.dataset, schema_overrides={n: pl.Float64 for n in names}
    )
    missing = [c for c in list(names) + list(KEY_COLUMNS) if c not in df.columns]
    if missing:
        sys.exit(f"train: dataset lacks columns {missing}")

    unknown = df.filter(pl.col("label") == "unknown").height
    if unknown:
        print(f"train: dropping {unknown} unknown-label rows")
    df = df.filter(pl.col("label") != "unknown").with_columns(
        (pl.col("label") == "malicious").cast(pl.Int32).alias("y")
    )

    # Latest run per kind trains and tests; earlier runs hold out.
    kinds: dict[str, dict] = {}
    holdout_frames, pool_frames = [], []
    for kind in sorted(df["kind"].unique()):
        runs = sorted(df.filter(pl.col("kind") == kind)["run_id"].unique(), key=run_stamp)
        latest = runs[-1]
        sub = df.filter(pl.col("kind") == kind)
        kinds[kind] = {"train_run": latest, "holdout_runs": runs[:-1], "pool": sub.height}
        holdout_frames.append(sub.filter(pl.col("run_id") != latest))
        pool_frames.append(sub.filter(pl.col("run_id") == latest))
    pool = pl.concat(pool_frames)
    holdout = pl.concat([f for f in holdout_frames if f.height]) if any(
        f.height for f in holdout_frames
    ) else pool.head(0)
    print(f"train: pool {pool.height} rows, holdout {holdout.height} rows")

    # Seq cut per (run, scope); the test side is strictly later by
    # construction. Spanning scope ids are counted, not forbidden.
    train_frames, test_frames = [], []
    spanning: dict[str, int] = {}
    for (run_id, scope), sub in pool.group_by(["run_id", "scope"], maintain_order=True):
        tr, te = split_rows(sub, args.test_fraction)
        train_frames.append(tr)
        test_frames.append(te)
        spanning[f"{run_id}/{scope}"] = len(
            set(tr["scope_id"].unique()) & set(te["scope_id"].unique())
        )
    train_all = pl.concat(train_frames)
    test = pl.concat(test_frames)
    print(f"train: split {train_all.height} train rows, {test.height} test rows")
    print(f"train: spanning scope ids: {sum(spanning.values())} across {len(spanning)} run/scopes")

    # Cap the train side per kind; the test side keeps natural rows.
    capped = []
    for kind in sorted(train_all["kind"].unique()):
        sub = train_all.filter(pl.col("kind") == kind)
        kinds[kind]["train_before_cap"] = sub.height
        if sub.height > args.cap:
            sub = sub.sample(args.cap, seed=args.seed)
        kinds[kind]["train_after_cap"] = sub.height
        capped.append(sub)
    train = pl.concat(capped)
    print(f"train: capped train {train.height} rows")

    X_train = train.select(names).to_numpy()
    y_train = train["y"].to_numpy()
    params = {
        "objective": "binary",
        "num_leaves": 31,
        "learning_rate": 0.05,
        "n_estimators": 300,
        "min_child_samples": 20,
        "scale_pos_weight": float((y_train == 0).sum() / max(1, (y_train == 1).sum())),
        "deterministic": True,
        "seed": args.seed,
        "num_threads": 1,
        "verbose": -1,
    }
    model = lgb.LGBMClassifier(**params)
    model.fit(X_train, y_train)

    # Per-surface thresholds for precision >= 0.98 on the pooled
    # holdouts. The in-run test split is leaky by construction and never
    # sets thresholds.
    p_test = model.predict_proba(test.select(names).to_numpy())[:, 1]
    test = test.with_columns(pl.Series("p", p_test))
    if holdout.height:
        ph = model.predict_proba(holdout.select(names).to_numpy())[:, 1]
        holdout = holdout.with_columns(pl.Series("p", ph))
    else:
        print("train: no holdout rows; thresholds unset (0.5, met=False)")
    thresholds: dict[str, dict] = {}
    for surface in sorted(pool["surface"].unique()):
        sub = holdout.filter(pl.col("surface") == surface)
        y = sub["y"].to_numpy() if sub.height else np.array([])
        p = sub["p"].to_numpy() if sub.height else np.array([])
        if len(y) == 0:
            thresholds[surface] = {
                "threshold": 0.5,
                "precision": None,
                "recall": None,
                "met": False,
                "support": 0,
                "note": "no holdout rows",
            }
            print(f"train: surface {surface}: no holdout rows; t=0.5 met=False")
            continue
        if y.sum() == 0 or y.sum() == len(y):
            thresholds[surface] = {
                "threshold": 0.5,
                "precision": None,
                "recall": None,
                "met": False,
                "support": len(y),
                "note": "single-class holdout slice",
            }
            print(f"train: surface {surface}: single-class holdout slice; t=0.5 met=False")
            continue
        mal, ben = p[y == 1], p[y == 0]
        if mal.min() > ben.max():
            # Separable: the midpoint of the gap has maximum margin.
            # (The curve alone would pin t at 1.0 on saturated outputs.)
            t = float((mal.min() + ben.max()) / 2)
            thresholds[surface] = {
                "threshold": t,
                "precision": 1.0,
                "recall": 1.0,
                "met": True,
                "support": len(y),
            }
            th = thresholds[surface]
            print(f"train: surface {surface}: t={th['threshold']:.4f} P=1.0 R=1.0 met=True (gap)")
            continue
        prec, rec, thr = precision_recall_curve(y, p)
        ok = [(t, pr, re) for t, pr, re in zip(thr, prec[:-1], rec[:-1]) if pr >= 0.98]
        if ok:
            # Max recall, then max precision; the median threshold among
            # the winners keeps margin from both edges (a t of exactly
            # 1.0 would turn p=0.9999 holdout rows into false negatives).
            best = max((c[2], c[1]) for c in ok)
            tied = sorted(c[0] for c in ok if (c[2], c[1]) == best)
            t = tied[len(tied) // 2]
            pr = next(c[1] for c in ok if c[0] == t)
            re = next(c[2] for c in ok if c[0] == t)
            thresholds[surface] = {
                "threshold": float(t),
                "precision": float(pr),
                "recall": float(re),
                "met": True,
                "support": len(y),
            }
        else:
            i = int(np.argmax(prec[:-1]))
            thresholds[surface] = {
                "threshold": float(thr[i]),
                "precision": float(prec[i]),
                "recall": float(rec[i]),
                "met": False,
                "support": len(y),
                "note": "0.98 unreachable on holdout slice",
            }
        th = thresholds[surface]
        print(f"train: surface {surface}: t={th['threshold']:.4f} P={th['precision']} R={th['recall']} met={th['met']}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(out / "model.txt"))
    import onnxmltools
    from onnxmltools.convert.common.data_types import FloatTensorType
    from onnxmltools.utils import save_model as onnx_save

    onnx_model = onnxmltools.convert_lightgbm(
        model.booster_, initial_types=[("input", FloatTensorType([None, len(names)]))]
    )
    import onnx

    onnx.checker.check_model(onnx_model)
    onnx_save(onnx_model, str(out / "model.onnx"))

    test.drop("p").write_csv(out / "test.csv")
    (holdout.drop("p") if "p" in holdout.columns else holdout).write_csv(out / "holdout.csv")
    (out / "manifest.json").write_text(
        json.dumps(
            {
                "model_version": args.version,
                "features_version": manifest["features_version"],
                "feature_names": names,
                "cap_per_kind": args.cap,
                "kinds": kinds,
                "scale_pos_weight": params["scale_pos_weight"],
                "params": {k: v for k, v in params.items() if k != "verbose"},
                "split": {
                    "rule": "per (run, scope), cut rows by ingest_seq at the 80th percentile; test strictly later",
                    "test_fraction": args.test_fraction,
                    "train_rows": train.height,
                    "test_rows": test.height,
                    "holdout_rows": holdout.height,
                    "spanning_scope_ids": spanning,
                },
                "thresholds": thresholds,
                "seed": args.seed,
            },
            indent=2,
        )
    )
    print(f"train: wrote {out}")


if __name__ == "__main__":
    main()
