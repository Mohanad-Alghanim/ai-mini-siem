"""Train or predict SSH behavior: python -m mini_siem.ml --help."""

import argparse
import json
from pathlib import Path

from .features import load_features
from .model import load_model, predict_records, prediction_counts, save_model, train_model


def protect_paths(inputs, outputs):
    """Reject collisions (including symlinks) before writing any output."""
    resolved = [path.resolve() for path in outputs]
    if len(set(resolved)) != len(resolved) or set(resolved) & {path.resolve() for path in inputs}:
        raise ValueError("Output would overwrite an input or another output")
    if any(path.exists() or path.is_symlink() for path in outputs):
        raise ValueError("Output already exists; choose a new model/export path")


def export_results(results, path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".csv":
        results.to_csv(path, index=False)
    elif path.suffix.lower() == ".json":
        results.to_json(path, orient="records", indent=2, double_precision=15)
    else:
        raise ValueError("Prediction output must end in .csv or .json")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    train = commands.add_parser("train", help="Fit a new local model")
    train.add_argument("--input", type=Path, required=True)
    train.add_argument("--model", type=Path, required=True)
    train.add_argument("--output", type=Path, help="Optional training-set predictions (.csv/.json)")
    train.add_argument("--contamination", type=float, default=0.1)
    train.add_argument("--random-state", type=int, default=42)
    predict = commands.add_parser("predict", help="Load a trusted local model and predict without fitting")
    predict.add_argument("--input", type=Path, required=True)
    predict.add_argument("--model", type=Path, required=True)
    predict.add_argument("--output", type=Path, required=True)
    predict.add_argument("--trust-model", action="store_true", help="Only for a model you created/trust; joblib can execute code")
    args = parser.parse_args(argv)
    try:
        inputs = [args.input] + ([args.model] if args.command == "predict" else [])
        outputs = ([args.model] if args.command == "train" else []) + ([args.output] if args.output else [])
        protect_paths(inputs, outputs)
        if args.output and args.output.suffix.lower() not in (".csv", ".json"):
            raise ValueError("Prediction output must end in .csv or .json")
        frame = load_features(args.input)
        if args.command == "train":
            model = train_model(frame, args.contamination, args.random_state)
        else:
            model = load_model(args.model, trusted=args.trust_model)
        results = predict_records(model, frame)
        if args.command == "train":
            save_model(model, args.model)
        if args.output:
            export_results(results, args.output)
    except (OSError, ValueError, TypeError, EOFError) as exc:
        # Do not echo source values or deserializer exception text.
        print(f"Model command failed ({type(exc).__name__}). Check feature validity, paths, model compatibility and explicit model trust.")
        return 2
    print(json.dumps({"command": args.command, **prediction_counts(results)}))
    if args.command == "train" and len(frame) != 30:
        print("Note: training row count differs from the expected 30-record baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
