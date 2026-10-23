"""Deterministic educational Isolation Forest training, prediction and storage."""

from pathlib import Path
import pickle

import joblib
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline

from .features import FEATURES, prepare_features


DEFAULT_CONTAMINATION = 0.1
DEFAULT_RANDOM_STATE = 42
ARTIFACT_VERSION = 1


def train_model(frame, contamination=DEFAULT_CONTAMINATION, random_state=DEFAULT_RANDOM_STATE):
    """Fit only five features; no previous labels or identifiers reach the forest."""
    _, features = prepare_features(frame)
    if len(features) < 2:
        raise ValueError("Training requires at least two records")
    if isinstance(contamination, bool) or not isinstance(contamination, (int, float)) or not 0 < contamination <= 0.5:
        raise ValueError("contamination must be a number in (0, 0.5]")
    if isinstance(random_state, bool) or not isinstance(random_state, int) or not 0 <= random_state < 2**32:
        raise ValueError("random_state must be an integer in [0, 2**32)")
    # A persisted selector enforces the whitelist even if extra columns appear.
    # Trees do not require scaling; no imputation or inferred features are used.
    pipeline = Pipeline([
        ("features", ColumnTransformer([("behavior", "passthrough", list(FEATURES))], remainder="drop")),
        ("forest", IsolationForest(n_estimators=100, contamination=contamination,
                                   random_state=random_state, n_jobs=1)),
    ])
    pipeline.fit(features)
    return pipeline


def predict_records(pipeline, frame):
    """decision_function < 0 is Anomaly; >= 0 is Normal (not attack confidence)."""
    identifiers, features = prepare_features(frame)
    labels = pipeline.predict(features)
    scores = pipeline.decision_function(features)
    return pd.DataFrame({
        "SourceIP": identifiers.to_numpy(),
        "AnomalyLabel": labels,
        "AnomalyStatus": ["Anomaly" if label == -1 else "Normal" for label in labels],
        "AnomalyScore": scores,
    })


def prediction_counts(results):
    """Aggregate counts without printing identifying input records."""
    return {"records": len(results), "Normal": int(results.AnomalyLabel.eq(1).sum()),
            "Anomaly": int(results.AnomalyLabel.eq(-1).sum())}


def save_model(pipeline, path):
    """Persist a local pipeline and its schema/runtime compatibility metadata."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"artifact_version": ARTIFACT_VERSION, "features": list(FEATURES),
                 "sklearn_version": sklearn.__version__, "pipeline": pipeline}, path)


def load_model(path, *, trusted=False):
    """Load only artifacts you created/trust. Pickle can execute arbitrary code.

    Metadata checks happen AFTER deserialization and are not a security sandbox.
    Never set trusted=True for downloaded or otherwise untrusted artifacts.
    """
    if not trusted:
        raise ValueError("Refusing to deserialize an untrusted model; explicit trust is required")
    try:
        artifact = joblib.load(path)
    except (EOFError, pickle.UnpicklingError, KeyError, IndexError):
        raise ValueError("Malformed model artifact") from None
    if not isinstance(artifact, dict) or artifact.get("artifact_version") != ARTIFACT_VERSION or artifact.get("features") != list(FEATURES):
        raise ValueError("Unsupported model artifact or feature schema")
    if artifact.get("sklearn_version") != sklearn.__version__:
        raise ValueError("Model Scikit-learn version differs; recreate it in this environment")
    pipeline = artifact.get("pipeline")
    if not isinstance(pipeline, Pipeline) or list(pipeline.named_steps) != ["features", "forest"]:
        raise ValueError("Artifact does not contain the expected model pipeline")
    if not isinstance(pipeline.named_steps["forest"], IsolationForest):
        raise ValueError("Artifact does not contain an Isolation Forest")
    return pipeline
