# TASK-007: SSH feature compatibility investigation

The diagnostic tool explains **what differs and which raw record references
contribute to the generated values**, without guessing the original baseline
producer's rules. It uses parser ssh-historical-v2 and feature semantics
ssh-observed-peer-features-v1 unchanged. There is no database access, model
artifact input, training, inference, or compatibility override.

## Current compatibility decision

**NOT DEMONSTRATED for newly extracted event features: existing-model inference
on those features remains blocked.** Matching IP
sets do not establish matching event membership, counting rules or feature
semantics. Numerical agreement alone also cannot establish model provenance or
semantic compatibility. This tool does not enable the existing model, change its
thresholds, retrain it, or alter records/alerts/dashboard behavior.

The Project Manager's existing Kali review reports 2,000 events, 1,647 supported
peers, 353 unassigned events, 30 matching generated/baseline IPs, and 22 IPs with
at least one feature difference; numerical_match and inference_allowed are both
false. Those are **externally supplied verified observations**, not measurements
performed by this cloud task. Real private files remain unavailable here, so
new real-data root-cause findings remain pending. The tool never force-matches
these numbers.

## Kali Linux execution

From the repository root, using Python 3.10+:

```bash
source .venv/bin/activate
python -m pytest -q

mkdir -p reports
ssh_compatibility_dir="$(mktemp -d reports/ssh-compatibility-XXXXXX)"
python -m mini_siem.feature_compatibility \
  --events "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --baseline "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --output-dir "$ssh_compatibility_dir"
```

Outputs are `analysis.md` for human review and `diagnostics.json` for complete
machine-readable evidence. Paths are configurable. Existing output files,
symlinks to inputs, and input/output collisions are rejected. The source CSVs are
opened only for reading and snapshotted for hash-consistent processing. Reports
record both source SHA-256 hashes and diagnostic/parser/feature versions.
No new dependency or system package is needed.

Exit 0 means the investigation completed, **not that compatibility passed**.
Exit 2 means input/schema/path/output errors. The CLI prints aggregate counts
and the blocked compatibility decision, without IPs, filesystem paths, or raw
messages. Keep the reports in ignored local reports/ directories: they contain
IP-level references and should not be committed or pasted publicly.

## How to read the findings

### Confirmed observations

The coverage summary measures total, assigned and unassigned events using the
unchanged parser. Parsing groups list source-record positions, original LineId
and EventId. Invalid/unsupported/ambiguous/no-evidence groups remain distinct.
Unassigned peer-context evidence records context names and token categories
(valid IPv4/IPv6, strict IPv4 separator form, or invalid/unsupported token), not
raw messages or rejected tokens. This helps locate the original rows privately
without assigning an unverified peer.

For each SourceIP, the report contains all five generated and baseline values,
`delta_generated_minus_baseline`, match status, and exact contributing event
references. Missing-side values are null, not zero-filled. Duplicate baseline
IP keys are marked ambiguous and excluded from value comparisons. Canonical IP
comparison and the existing rate tolerance of 1e-12 are retained. Per-feature
summaries show compared/differing IP counts and maximum absolute differences.

Generated evidence includes:

- Assigned event references explaining EventCount.
- Failure and invalid-user references, their overlap and union count, accepted
  references, failure/accepted ambiguity, and rows with no supported auth flag.
- Excluded broad `failed`-word references: e.g. reverse-DNS failures are not
  automatically authentication failures.
- Derived event-type groups and hashed template groups; distinct nonblank
  EventIds/templates; and records using template fallback. No template text is
  exported. Derived types still prefer EventId and otherwise use the prefixed
  EventTemplate, exactly as in TASK-006.
- Repeated Content excess count, without removing repeated events or exporting
  their Content. Repeated text is not proof of a duplicate event.
- Baseline/generated rate arithmetic checks. A zero denominator is reported as
  undefined under unknown producer conventions, not filled with an invented rate.

When both reported rates agree with their respective FailedAuthCount/EventCount
ratios and denominators are nonzero, the report decomposes the rate difference:

```text
numerator effect   = (generated_failed - baseline_failed) / baseline_events
denominator effect = generated_failed / generated_events
                     - generated_failed / baseline_events
rate delta         = numerator effect + denominator effect + roundoff residual
```

This is an **evidence-backed arithmetic explanation**, not proof of why baseline
counts differ. If baseline rate arithmetic disagrees at tolerance 1e-12, that
observable mismatch is recorded, but the producer's rounding/denominator intent
remains unknown. The diagnostic never silently repairs values.

Authentication counters are per-record and independent. A failed authentication
mentioning an invalid user increments both counts once; those counters must not
be added as though disjoint. Accepted and failure indicators can also overlap
in ambiguous text. Indicator counts are not verified outcomes or attack labels.

### Hypotheses only

The tool probes a small set of alternative counts **for diagnosis only**:
nonblank template counts vs current derived type counts, EventId-only counts,
failure/invalid-user unions, a broader failed-word count, and assigned events plus
unassigned address-candidate records. A coincidence with a differing baseline
value is labeled `hypothesis_only`. The probe values are not new feature vectors
and are never fed to a model or used to change generated features.

An address token found in an unassigned record is only textual evidence. For
example, an ambiguous message mentioning two addresses is linked as candidate
evidence to both IPs but attributed to neither. Candidate counts are not additive
global event totals. They must not be used to fill the 353 unassigned events or
to force a baseline match. Hostnames/invalid IPs are not invented into candidates.

### Unresolved causes

Every nonmatching feature retains `cause: unresolved`: the original baseline
producer implementation, deduplication, input membership, time-window and model
training provenance are not independently established by two CSVs. A baseline
numerical gap can be measured and a generated value explained without knowing
its historical cause. Diagnostic arithmetic is separated from causal claims.
The tool does not claim any hypothesis is the confirmed baseline algorithm.

## Safe next steps for Project Manager review

1. Recover the original baseline-generation code/configuration, exact input
   hashes/record membership, peer parser, event-type definition, authentication
   indicator rules, overlap/deduplication conventions, rate denominator/rounding,
   and aggregation window. Confirm which exact features/artifact trained TASK-003.
2. Review IP coverage groups and per-feature evidence. Reproduce the baseline
   independently under its documented rules. Demonstrate semantic compatibility
   and training/inference consistency before considering reuse of the existing
   model. Do not tune features or contamination to reproduce previous predictions.
3. If compatibility cannot be independently established, propose a **separate
   versioned feature/model pipeline** trained and inferred with consistent
   definitions. This requires adequate representative data and independent
   evaluation, and explicit authorization in a later task. Do not silently
   replace the existing artifact or train such a model in TASK-007.

Thirty aggregate records and in-sample outputs do not establish generalization
or attack detection quality. Previous model labels are not verified ground truth;
no accuracy, precision, recall or F1 is calculated. No timestamp year, missing IP,
username, aggregation window or event attribution is inferred. The current
in-memory diagnostic is intended for the small historical dataset. Full
per-IP reports remain private; no real-data reports are committed.

## Implementation

- `mini_siem/preprocessing/compatibility.py`: evidence, comparison, diagnostic
  arithmetic, explicitly labeled hypotheses and blocked compatibility decision.
- `mini_siem/feature_compatibility.py`: CLI and Markdown/JSON reports.
- `tests/test_feature_compatibility.py`: synthetic regression fixtures generated
  only in temporary paths. No model loading/inference or database access occurs.

Existing parser, feature definitions, model, backend, alerts, SQLite schema and
dashboard code remain unchanged.

## Validation evidence

On Python 3.12 in the cloud, the full suite completed with **228 passed**:
214 existing tests and 14 diagnostic regressions. Dependency and Git whitespace
checks passed. Tests exercise exact numerical agreement without compatibility
approval, coverage/context evidence, per-feature signed gaps, overlapping flags,
event-type alternatives, rate arithmetic/decomposition, duplicate and unmatched
baseline IPs, missing supported peers, privacy, input preservation, output
collisions, and no model/database operations.

A separate CLI check on temporary synthetic fixtures generated both report
formats, preserved the input bytes and left inference blocked even with
numerical_match true. Temporary outputs were removed. No new real-data findings,
private IP-level reports, models or database records were created or committed.
