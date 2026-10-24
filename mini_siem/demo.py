"""Build a fresh demonstration database from original legacy assets only; never fit."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile

from mini_siem.ingestion.ssh_backend import ingest_features
from mini_siem.ingestion.ssh_events import load_events
from mini_siem.ml.features import load_features, REQUIRED
from mini_siem.storage.ssh_events import persist_events, prepare_storage
from mini_siem.storage.sqlite import initialize_database


def checked_asset(path, approved_hash):
    if not re.fullmatch('[0-9a-f]{64}', approved_hash):
        raise ValueError('Require the exact approved SHA-256 identity')
    content = Path(path).read_bytes()
    if hashlib.sha256(content).hexdigest() != approved_hash:
        raise ValueError('Asset differs from approved legacy identity')
    return content


def prepare_demo(database, historical, baseline, model, baseline_hash, model_hash, *, trusted=False, original_baseline=False):
    """Human provenance confirmation is required: names/schema cannot prove lineage.

    Only a byte-identical, operator-confirmed original training baseline can be
    replayed. This is a training-set demonstration, not independent evaluation.
    Original inputs and any existing database are never opened for writing.
    """
    if not trusted or not original_baseline:
        raise ValueError('Trusted artifact and original legacy training input confirmation required')
    target = Path(database).resolve()
    inputs = {Path(p).resolve() for p in (historical, baseline, model)}
    if target in inputs or target.exists() or Path(database).is_symlink():
        raise ValueError('Choose a fresh demonstration database, separate from all inputs')
    baseline_bytes = checked_asset(baseline, baseline_hash)
    model_bytes = checked_asset(model, model_hash)
    # Existing historical loader snapshots and validates without generating model features.
    events, source_hash = load_events(historical)
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.mini-siem-demo-', dir=target.parent) as folder:
        root = Path(folder)
        feature_path, model_path, staged = root/'baseline.csv', root/'model.joblib', root/'demo.db'
        feature_path.write_bytes(baseline_bytes); model_path.write_bytes(model_bytes)
        frame = load_features(feature_path)
        if len(frame) != 30 or set(frame.columns) != set(REQUIRED):
            raise ValueError('Require original 30-row baseline with exactly the identifier and five features')
        initialize_database(staged); prepare_storage(staged)
        historical_result = persist_events(staged, events, source_hash, 'demo-historical-events')
        prediction_result = ingest_features(staged, feature_path, model_path, 'demo-original-baseline', trusted=True)
        # Publish only a complete database. Hard link refuses an existing target
        # even if another process creates it after our initial check.
        staged.chmod(0o600)
        os.link(staged, target)
    return {'historical_events':historical_result['records'], 'predictions':prediction_result['records'],
            'Normal':prediction_result['Normal'], 'Anomaly':prediction_result['Anomaly'],
            'alerts':prediction_result['inserted_alerts'],
            'inference_scope':'original legacy training-baseline replay only',
            'new_event_feature_inference_allowed':False, 'live_ai_detection':False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database',type=Path,required=True)
    parser.add_argument('--historical',type=Path,required=True)
    parser.add_argument('--baseline',type=Path,required=True)
    parser.add_argument('--model',type=Path,required=True)
    parser.add_argument('--original-baseline-sha256',required=True)
    parser.add_argument('--model-sha256',required=True)
    parser.add_argument('--trust-model',action='store_true')
    parser.add_argument('--confirm-original-training-baseline',action='store_true')
    args = parser.parse_args(argv)
    try:
        result = prepare_demo(args.database,args.historical,args.baseline,args.model,
                              args.original_baseline_sha256,args.model_sha256,
                              trusted=args.trust_model,original_baseline=args.confirm_original_training_baseline)
        print(json.dumps(result))
        return 0
    except (OSError,ValueError,TypeError,KeyError,EOFError,sqlite3.Error):
        print('Demo preparation refused. Check original training provenance, approved hashes, trusted compatible model, validated inputs and a fresh database path. Existing assets were not overwritten.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
