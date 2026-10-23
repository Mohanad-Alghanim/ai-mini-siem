# TASK-008: Versioned SSH feature pipeline and model strategy

## Decision for beginners

Keep the existing model and its records unchanged. **Do not mix newly extracted
features into that model while compatibility is unverified.** A column named
FailedAuthCount can mean different things under different counting rules; this
changes the distribution seen by Isolation Forest, even when every column name
and SourceIP matches. Changing features to copy old numbers would conceal the
problem. Old prediction labels are not independent attack ground truth.

Recommend **Option B as the future experimental direction**, with provenance
recovery (Option A) continuing as an evidence-gathering activity. Option B is not
authorization to train now: first obtain appropriate data, specify comparable
scope/exposure, approve an evaluation plan and review a separate implementation.
The current 30 IP rows and unresolved provenance are not sufficient for deployment.

## Two options

| Dimension | A: Recover legacy producer | B: Separate reproducible pipeline/model |
| --- | --- | --- |
| Feasibility | Depends on finding private scripts/config and original inputs; repository evidence currently insufficient | Current extractor is inspectable/versioned; adequate new data and future integration remain prerequisites |
| Scientific validity | Reuse only after independently establishing exact semantics and training lineage | Consistent feature construction can support reproducible experiments; reproducibility alone is not detection validity |
| Available data | Existing 30-row baseline with unknown generating rules | Same historical file yields 30 IP rows; not 2,000 independent feature samples; 353 unassigned events are not invented rows |
| Main risks | Guessing provenance, forcing match, accidentally changing old behavior | Small/unrepresentative baseline, exposure/window mismatch, contaminated training, overfitting, entity/time leakage |
| Prerequisites | Producer revision, hashes/membership/window, definitions, training metadata, independent reproduction | Approved contract, representative distinct data units, version-enforcing artifact/bundle integration, locked environment and evaluation plan |
| Current outcome | Not demonstrated; no approval for reuse on extracted features | Recommended research direction only; no training/replacement/deployment in TASK-008 |

Recovering Option A may still prove useful. If its evidence independently
demonstrates compatibility, a future review may authorize reuse. If not, preserve
the old artifact as a legacy PoC and use a distinct new model/version/database
history if a future experimental model is authorized. Never silently overwrite it.

## Machine-readable contract

`config/ssh_feature_contract.json` specifies the unchanged current implementation:
parser ssh-historical-v2, semantics ssh-observed-peer-features-v1, exact required
headers and regexes, SourceIP attribution, ambiguous/missing-IP handling, event
ID/template preference, independent per-record flags/overlap, no deduplication,
feature ordering/types/formulas, numeric validation, preprocessing and provenance
requirements. SourceIP is an identifier, never a training feature. The public
contract contains implementation hashes but **no private input hashes**.

The current scope is **one whole supplied historical file**, grouped by observed
peer IP, with no known duration. It does not claim a fixed window. Count features
scale with observation opportunity: two arbitrary files of different durations
are not comparable merely because the extractor is the same. A future temporal
window or exposure normalization would need independently valid timestamps/data,
a separately reviewed feature version and consistent training/inference rules.
Never fabricate the missing historical year to make a window possible.

The validator compares the entire canonical JSON contract against the reviewed
reference and checks runtime version/order plus SHA-256 fingerprints of loader,
parser, aggregation, validation and preprocessing/model implementation files.
Unknown fields and changed rules/types/order are rejected, not ignored. Canonical
JSON sorts keys and ignores whitespace but preserves array order and scalar types.
Whole-file source fingerprints deliberately fail even on nonfunctional edits:
review the change rather than automatically refreshing hashes. This is a code/
specification consistency check using the reviewed checkout as trust root, not
a signature, defense against an attacker changing both files, or scientific proof.

The contract's local-run field requirements describe a **future complete private
manifest**: exact input bytes, generated feature bytes, record membership and
implementation/environment provenance. The TASK-008 readiness report is only a
partial inspection, not that manifest. It can measure local event/baseline hashes
and counts but does not export feature data or attest model training lineage.

## Future training/inference consistency design (not implemented authorization)

Both future paths must call the **same** load_events + aggregate_features +
prepare_features implementation, through one reviewed feature-bundle builder.
Do not write a second extraction function for inference. A bundle must pair the
numeric matrix with a contract digest and private provenance manifest. Reject
bare CSVs without verified provenance in that future versioned model interface.
Do not add such rejection to legacy APIs silently; preserve their existing behavior.

Before any future train/infer operation:

1. Validate an approved contract and exact parser/feature versions. Reject unknown
   versions, changed hashes, incompatible order/types, attribution/counting/scope/
   window or preprocessing. Same column names are not enough.
2. Validate inputs and provenance; retain exact source hashes and source-record
   membership per aggregate, skipped-record coverage, scope/exposure and output
   feature hash. Do not zero-fill missing IPs or use prior labels/risks as inputs.
3. Require an explicit scope/window/exposure compatibility policy. A file-level
   contract match alone cannot pass this policy for arbitrary data acquisitions.
4. For training, assign train/validation/test units **before aggregation** when
   necessary to avoid shared source events. Fit any approved learned preprocessing
   only on training data; persist selection/order/preprocessing with the estimator.
5. For inference, verify model metadata against the bundle before prediction;
   reuse persisted preprocessing without fit, refit, schema guessing or adaptation.
   Dependency/preprocessor incompatibility fails closed. Missing metadata never
   falls back to the old artifact format or to an override flag.
6. Keep separate artifact identity/history. Record scores with their exact API,
   direction and offset/threshold provenance. Loading remains trusted-artifact-only;
   JSON validation is not protection against joblib/pickle code execution.

The future model metadata should contain at least:

```json
{
  "artifact_format": "proposed-versioned-ssh-model-v2",
  "contract_id": "ssh-observed-peer-contract-v1",
  "contract_sha256": null,
  "parser_version": "ssh-historical-v2",
  "feature_semantics_version": "ssh-observed-peer-features-v1",
  "ordered_schema": null,
  "preprocessing_spec_and_sha256": null,
  "extractor_source_sha256": null,
  "source_event_sha256": null,
  "generated_features_sha256": null,
  "membership_manifest_sha256": null,
  "aggregation_scope_window_exposure": null,
  "training_code_commit": null,
  "dependency_versions_and_lock_hash": null,
  "train_validation_test_manifest_hashes": null,
  "estimator_parameters_and_random_seed": null,
  "score_api_and_threshold_policy": null,
  "model_artifact_sha256": null,
  "evaluation_report_sha256": null,
  "review_authorization_reference": null
}
```

Nulls indicate missing required future values, not a loadable artifact or fabricated
history. Metadata must be populated from actual runs and fail closed if required
values are absent. Maintain artifact hashes in a trusted manifest/sidecar (not a
self-referential hash inside the serialized artifact). The training timestamp,
record counts and source provenance belong in that private manifest too.
TASK-003 v1 artifacts lack this provenance and must not be relabeled compatible.

**Implemented now:** contract validation, drift checks, optional read-only input
inspection, blocked readiness reports and tests. **Design only:** version-enforcing
feature bundles, model metadata format/integration, environment locking, reviewed
scope policy and future experiment execution. No enforcement is retrofitted into
legacy training/inference; TASK-006/007 guards remain unchanged.

## Data and evaluation prerequisites

Thirty IP-level rows are the effective sample size of this feature table, not
2,000 independent model examples. Repeated IPs, hosts and source events further
reduce independence. A small random row split gives unstable estimates; it does
not solve temporal/entity overlap. No universal minimum sample size is justified
by the available evidence. Acquire sufficiently diverse, representative data for
the intended operational scope, and quantify uncertainty before any claims.

Collect multiple independently identified acquisition periods/files/hosts or
sites, real timestamp/exposure provenance, parser coverage/quality records and
operational context. Keep raw data private. Include representative normal
variability and investigate potential contamination. Do not generate new attack
simulations in this task. Labeled attack evaluation would additionally require
independently verified outcomes, label definitions, review provenance and enough
positive/negative cases over appropriate units/time horizons.

Use forward-in-time held-out acquisitions **only where actual time is known**;
otherwise use genuinely disjoint acquisition groups and explicitly avoid temporal
claims. Prevent a raw event from contributing to more than one split aggregate.
Group by IP/host/site where the generalization question requires unseen entities;
for future periods on known entities, state that objective and enforce temporal
separation. Purge/embargo overlapping windows when justified by future window
semantics. Do not invent historical timestamps for splitting. Reserve test data
before tuning contamination/thresholds, use validation data for those choices,
and keep a final independent test set untouched. Bootstrap/repeat splits at the
independent acquisition/entity level, not as if individual log lines were IID.

Compare against predeclared simple baselines on the same held-out units: e.g.
rank by a documented failure count/rate or a transparent threshold rule. Such
comparators are evaluation references, not automatic replacements for AI alert
classification. Compare coverage, score/rank stability across seeds/data subsets,
distribution shifts, top-k overlap and blinded analyst review of unusual records.
Report sensitivity to contamination and alert counts/proportions; report rates
per duration only when observation durations are independently known. Alert yield
and analyst agreement are not verified precision. Stability alone is not accuracy.

Without independent labels: analyze anomaly scores, operational burden, coverage
and stability; explicitly label all findings unsupervised. With verified labels
and an appropriate held-out design: report precision/recall/F1, precision-recall
curves, false positives per defined unit and uncertainty, alongside class balance
and label limitations. Never evaluate "accuracy" against earlier predictions or
reuse tuned test labels. In-sample agreement and 30-row fits are PoC checks only.

## Authorization gate

Before an experimental new model can be authorized: approve the provenance audit,
contract and scope policy; obtain adequate independent data; predeclare splits,
baselines, metrics and review criteria; implement and test fail-closed versioned
feature/model interfaces; pin the environment; review privacy and trusted artifact
handling; and obtain Project Manager approval for a separate training task.
TASK-008 leaves training, inference and deployment blocked regardless of a valid
contract or a successfully read dataset.
