"""Train a LightGBM classifier on features extracted by `maltriage extract`.

Inputs: JSONL files produced by the Rust CLI, e.g.
    maltriage extract data/benign    --all-files --label benign    --out data/benign.jsonl
    maltriage extract data/malicious --all-files --label malicious --out data/malicious.jsonl

Optional --meta CSV (columns: sha256, first_seen) enables a *temporal* split,
which is what you want: random splits leak malware families across train/test.
Without it, the PE header timestamp is used as a (noisy, forgeable) fallback.
"""
import argparse
import json
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def load(paths: list[Path]) -> pd.DataFrame:
    rows = []
    for path in paths:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                rec = json.loads(line)
                if "error" in rec:
                    continue
                rows.append({"sha256": rec["sha256"], "label": rec["label"], **rec["features"]})
    return pd.DataFrame(rows).drop_duplicates("sha256")


def tpr_at_fpr(y_true, y_score, target_fpr: float) -> float:
    fpr, tpr, _ = roc_curve(y_true, y_score)
    return float(np.interp(target_fpr, fpr, tpr))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("jsonl", nargs="+", type=Path)
    ap.add_argument("--meta", type=Path, help="CSV with sha256,first_seen")
    ap.add_argument("--test-fraction", type=float, default=0.2)
    ap.add_argument("--out", type=Path, default=Path("models/model.txt"))
    args = ap.parse_args()

    df = load(args.jsonl)
    df["y"] = (df["label"] == "malicious").astype(int)

    if args.meta:
        meta = pd.read_csv(args.meta, parse_dates=["first_seen"])
        df = df.merge(meta, on="sha256", how="left")
        order_col = "first_seen"
    else:
        order_col = "hdr_timestamp"
    df = df.dropna(subset=[order_col]).sort_values(order_col).reset_index(drop=True)

    split = int(len(df) * (1 - args.test_fraction))
    train, test = df.iloc[:split], df.iloc[split:]

    features = [c for c in df.columns if c not in {"sha256", "label", "y", "first_seen"}]
    model = lgb.LGBMClassifier(n_estimators=400, learning_rate=0.05, num_leaves=63, subsample=0.8)
    model.fit(train[features], train["y"])

    scores = model.predict_proba(test[features])[:, 1]
    print(f"train={len(train)} test={len(test)} (ordered by {order_col})")
    print(f"ROC AUC       : {roc_auc_score(test['y'], scores):.4f}")
    print(f"PR AUC        : {average_precision_score(test['y'], scores):.4f}")
    print(f"TPR @ FPR 1%  : {tpr_at_fpr(test['y'], scores, 0.01):.4f}")
    print(f"TPR @ FPR 0.1%: {tpr_at_fpr(test['y'], scores, 0.001):.4f}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    model.booster_.save_model(str(args.out))
    (args.out.with_suffix(".features.json")).write_text(json.dumps(features), encoding="utf-8")
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
