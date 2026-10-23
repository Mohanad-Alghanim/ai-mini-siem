# TASK-008: SSH feature provenance audit

Audit base: main `43e71517ed88994d5d2eeca2bac2c646caecaca3`.
Scope: tracked repository files, available Git history/trees and existing tests/
documentation. Private Kali CSVs and actual saved model artifacts were unavailable.
This is not an audit of uncommitted notebooks, private machines or external sources.

## Evidence and limits

| Question | Verified repository evidence | Missing or not inferable |
| --- | --- | --- |
| Original baseline producer | TASK-003 consumes an existing CSV through ml/features.py; no tracked producer was found before that consumer | Original generation code/config, original source membership, window, deduplication and rules |
| Initial project | Initial commit 783a14c contains README.md and .gitignore only | No baseline algorithm can be reconstructed from that description |
| Training consumer | ml/model.py introduced in TASK-003 (778d805 merged history) selects five numeric columns, no scaler/imputer, fixed configurable seed/contamination, persisted pipeline | Actual private training invocation, exact CSV bytes, data membership or artifact provenance |
| Later event-derived producer | TASK-006 adds aggregate_features in 2e417d7; parser corrected to v2 in 513282e | This later implementation is not evidence that it generated the earlier baseline |
| Current feature definitions | ingestion/ssh_events.py, preprocessing/ssh_features.py and ml/features.py define observable parser, count, ordering/type rules | Matching names/types cannot establish legacy semantic equivalence |
| Existing model artifact format | save_model writes artifact_version, features, sklearn_version and pipeline | No parser/feature contract identity, training input hashes, source membership or baseline-generation lineage in this format |
| Actual private artifact | None inspected or loaded in TASK-008 | Cannot attest which data trained it, its parameters at training, or its exact runtime/library provenance |
| Diagnostics | TASK-007 measures differences and traceable generated membership; hypotheses are explicitly not baseline algorithms | Numerical coincidences cannot reveal a unique historical producer |

Repository inspection included complete tracked-file listings; targeted searches
for baseline/train/parser definitions; reachable history for relevant source paths;
tracked/reachable-history filenames matching CSV, notebooks and baseline names;
and initial/TASK-003 Git trees. No tracked original dataset, generation notebook,
legacy producer or training provenance manifest was found in those sources.
This absence is a bounded repository finding, not proof that such evidence never
existed elsewhere. Ignoring datasets in Git is appropriate and does not itself
invalidate a model; missing reproducibility/provenance evidence prevents approval.

## Project Manager's externally verified results

The supplied Kali review reports 228 tests, 2,000 events, parser v2, 1,647 supported
peers, 353 unassigned events, 30 matching IPs and 22 IPs with differences. Feature
mismatch counts are EventCount 5, UniqueEventTypes 5, FailedAuthCount 21,
InvalidUserCount 0, FailedAuthRate 21. These are **provided review observations**,
not remeasured in this cloud task and not hardcoded targets for the validator.

Confirmed inference from those observations: equal IP sets and one matching
feature do not imply equal feature vectors. The concentration of failure/rate
gaps is a reason to investigate authentication rules and denominators, not proof
of the old algorithm. Event membership/type definitions also need investigation.
Unassigned events cannot safely be attributed simply to fill gaps. No original
attack labels, timestamp years or aggregation window can be inferred from these
counts or previous model predictions.

## Evidence required to close the provenance gap

Recover the original producer revision/configuration, raw input hashes and exact
record membership, peer attribution rules, failure/invalid-user overlap handling,
event-type definition, deduplication policy, rate denominator/rounding, and scope/
window/exposure. Recover actual training invocation, feature order/preprocessing,
input feature hash, artifact hash, dependency versions and split/evaluation records.
Review these against the model's true training provenance. Do not retrofit missing
metadata with guessed values or treat a newly created sidecar as historical proof.

**Decision:** legacy compatibility is not demonstrated; inference on newly
extracted features stays blocked. No baseline-generation algorithm is invented.
