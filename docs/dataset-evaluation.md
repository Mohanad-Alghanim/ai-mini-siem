# TASK-009: Independent split planning and evaluation methodology

## Planning policy

A split plan is a reproducible metadata artifact, not a trained model, evaluation
execution, statistical-independence certificate or performance estimate. Each
supplied dataset is assigned whole to train, validation or independent test.
Assignments are explicit rather than randomly splitting dependent log rows.
All manifests must be assigned once, and all three partitions must be nonempty.

The planner rejects duplicate dataset/version IDs, reused file hashes, collection
or acquisition overlap, shared dependence groups, root lineage or source-event
identities across partitions, incompatible identity namespaces, and duplicate
underlying event/file exports within a partition. Dataset versions do not make
shared original events independent. Multiple disjoint exports from one collection
can be kept together in the same partition; the collection cannot cross a boundary.
Plan ordering/digests are deterministic for the same manifests and assignments.

The policy is deliberately conservative. It rejects splitting different subsets
of one root capture across partitions even if their declared event IDs differ.
Temporal planning also requires disjoint dependence groups; it is not a tool for
relaxing provenance for repeated known entities. A future known-entity temporal
experiment would need its own reviewed policy and adequate purge/embargo logic.

Temporal plans additionally require independently verified timestamp fields,
evidence-backed full timezone-aware ISO observation boundaries and durations,
and ordered nonoverlapping intervals: max(train end) <= min(validation start)
and max(validation end) <= min(test start). Intervals are half-open. No timestamps
or year are inferred from partial SSH fields or processing timestamps. Metadata
claims must be independently checked; optional CSV checks expose contradictions
but the planner cannot authenticate evidence hashes or inventory declarations.

## CLI for genuinely independent future collections

First obtain and register actual, reviewed inventories for at least three suitable
independent collection groups. This is not currently established for the single
historical SSH capture. The following paths refer to **future real manifests**,
not files or collections created by TASK-009.

Create a private `data/inventory/assignment.json` using actual registered dataset
identities. This is the shape only; replace placeholders, not evidence:

```json
{
  "train": [{"dataset_id": "YOUR_REGISTERED_TRAIN_ID", "dataset_version": "YOUR_VERSION"}],
  "validation": [{"dataset_id": "YOUR_REGISTERED_VALIDATION_ID", "dataset_version": "YOUR_VERSION"}],
  "test": [{"dataset_id": "YOUR_REGISTERED_TEST_ID", "dataset_version": "YOUR_VERSION"}]
}
```

Run from the repository root, with the virtual environment active:

```bash
mkdir -p reports
siem_split_review="$(mktemp -d reports/evaluation-plan-XXXXXX)"
python -m mini_siem.datasets plan \
  --manifest data/inventory/train.json \
  --manifest data/inventory/validation.json \
  --manifest data/inventory/test.json \
  --assignment data/inventory/assignment.json \
  --method group \
  --output "$siem_split_review/split-plan.json"
```

For trustworthy chronological data use --method temporal; the tool rejects
missing/partial/untrusted times or overlapping/out-of-order intervals. There is
no random/event-level split method or override. Rejection is expected for
incomplete historical provenance. A plan records dataset/version, input manifest
hashes, file hashes, acquisition/group identity, membership evidence, counts and
its own digest; it copies no raw records and grants no training/inference approval.
Record identity/membership manifests must be complete and independently reviewed.

## Shared experimental safeguards

Define the operational question, independent unit and generalization target before
collection or splitting. Different source types need actual appropriate schemas,
context, observation opportunity and consistent feature definitions. Port scans,
SQL injection, unauthorized changes, DoS and password spraying must not be inferred
merely from category names or SSH presence. No new collection, attacks, features,
models or simulations are implemented in TASK-009.

Keep train, tuning/validation and independent test provenance separate. Assign raw
collection units before aggregation; no source event can contribute across splits.
Review nested/overlapping windows, reused captures, related hosts/accounts/sessions,
correlated scenario runs and duplicate exports. Fit learned preprocessing only on
training data. Choose thresholds/hyperparameters using training/validation only;
keep test labels and outcomes untouched until final evaluation. Use group-aware
uncertainty estimates and repeat across genuinely independent collections. Do not
bootstrap raw lines as IID when the unit is a capture/host/aggregate.

The existing 2,000 events collapse to 30 IP rows under the SSH contract; they are
not 2,000 independent model examples. Thirty correlated aggregates from one
historical capture support software demonstrations and descriptive investigation,
not strong claims about unseen hosts/time/sites or rare attacks. No universal
minimum sample size can be justified here. Acquire representative independent
units, normal variability, adequate duration/exposure, provenance, and sufficient
labeled positives/negatives if labeled evaluation is intended; then report
uncertainty and collection limitations. Existing feature mismatch/legacy model
compatibility remains unresolved. The new inventory does not change that decision.

## A. Unsupervised anomaly detection without trusted attack labels

Use independent unlabeled holdouts to inspect score distributions, rank/top-k
stability across seeds and collection subsets, distribution/coverage shifts,
alert counts/proportions and blinded analyst review workload. Report rates per
duration only when exposure is independently known. Sensitivity to contamination
and dataset composition is informative but is not a tuning license on the final
test set. Analyst agreement, anomaly frequency and score stability are not attack
precision or accuracy. Do not calculate precision, recall, F1 or accuracy against
previous model labels or unverified event heuristics.

Predeclare simple reference baselines on the same independent units, such as a
transparent count/rate ranking or a documented fixed rule when its semantics and
exposure are justified. Compare review burden, overlap and stability, not invented
attack correctness. Those baselines are experimental comparisons, not replacements
for the existing AI alert classification pipeline.

## B. Attack detection with independently verified labels

Require independently established outcome definitions, positive and negative
coverage, review/evidence provenance, attribution and label uncertainty. Previous
AI predictions remain ai_predictions/unverified; the validator rejects marking
them independently_verified. A controlled experiment identifier or trigger alone
is not proof an attack reached the intended target or had the intended effect.
Independent outcome evidence/review is needed. Such experiments require future
authorization; none are executed here.

Choose metrics at the predeclared unit (event/session/host/window) consistent with
label granularity. On the untouched independent test set, suitable measures can
include precision/recall/F1, precision-recall curves, confusion counts, and false
positives per independently known exposure/unit, with class balance and uncertainty.
Use accuracy only with its assumptions/class imbalance made explicit; never use it
as the sole measure. Time-to-detection needs verified event/onset times and an
actually implemented detector, neither manufactured from these historical fields.
Do not extend verified labels to unlabeled rows or treat missing labels as normal.

## Privacy, readiness and authorization

Store inventories, event-membership evidence, assignments, split plans and reports
under ignored data/ or reports/ directories. They can contain sensitive acquisition,
environment and event identity information even when hashed. Do not force-add them.
The public schema/docs and synthetic test source are the only examples committed.
No private manifests or dataset samples are committed.

Quality/readiness is conditional on supplied honest evidence, not independent
certification. Metadata can be registered while unknown/pending; split planning
requires reviewed complete provenance. No report authorizes training, legacy-model
inference, collection, simulations, database writes or deployment. Obtain Project
Manager review of the collection/privacy protocol, feature-contract consistency,
independent data/split plan and evaluation criteria before a future experiment.
