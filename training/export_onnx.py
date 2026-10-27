"""Export the trained LightGBM model to ONNX and check Python/ONNX parity.

The feature order is taken from models/model.features.json, which must equal
the output of `maltriage names` (the Rust side defines the contract).
"""
import argparse
import json
import subprocess
from pathlib import Path

import lightgbm as lgb
import numpy as np
import onnxruntime as ort
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", type=Path, default=Path("models/model.txt"))
    ap.add_argument("--out", type=Path, default=Path("models/model.onnx"))
    ap.add_argument("--cli", default="maltriage", help="path to the Rust CLI for the contract check")
    args = ap.parse_args()

    features = json.loads(args.model.with_suffix(".features.json").read_text(encoding="utf-8"))
    rust_names = subprocess.run([args.cli, "names"], capture_output=True, text=True, check=True).stdout.split()
    if rust_names != features:
        raise SystemExit("feature contract mismatch: model columns != `maltriage names`")

    booster = lgb.Booster(model_file=str(args.model))
    onx = convert_lightgbm(booster, initial_types=[("input", FloatTensorType([None, len(features)]))], zipmap=False)
    args.out.write_bytes(onx.SerializeToString())

    # Parity check on random inputs.
    x = np.random.default_rng(0).random((64, len(features)), dtype=np.float32)
    sess = ort.InferenceSession(str(args.out))
    onnx_prob = sess.run(None, {"input": x})[1][:, 1]
    py_prob = booster.predict(x)
    max_diff = float(np.max(np.abs(onnx_prob - py_prob)))
    print(f"max |onnx - lightgbm| = {max_diff:.2e}")
    assert max_diff < 1e-4, "ONNX output diverges from LightGBM"
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
