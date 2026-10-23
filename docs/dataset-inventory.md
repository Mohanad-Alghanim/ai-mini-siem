# TASK-009: Dataset inventory and read-only preparation

This framework registers metadata and plans independent evaluation partitions.
It does not collect logs, simulate attacks, train/infer with a model, open SQLite,
modify alerts, or change the dashboard. The public schema is
`config/dataset_inventory.schema.json`. Actual inventories, assignments, reports
and split plans are private local outputs, not committed examples.

## Available vs planned sources

| Source category | Current project availability | Future intended use, requiring suitable data/context |
| --- | --- | --- |
| ssh_authentication | Existing private historical structured SSH CSV and legacy IP feature table | Authentication anomaly experiments; password spraying requires verified attribution/context across accounts/sources |
| network_flow | Metadata registration only; no dataset/parser claimed | Connection/flow behavior and port-scanning evaluation |
| http_access_application | Metadata registration only; no dataset/parser claimed | SQL-injection indicators with request/application context and independently verified outcomes |
| file_integrity | Metadata registration only; no dataset/parser claimed | Unauthorized file-change evaluation with authorization/change context |
| http_server_metrics_requests | Metadata registration only; no dataset/parser claimed | Controlled DoS evaluation with request/availability/latency/load context |

Category names describe potential data sources, not attack labels. The SSH file
does not contain all five attack types. TASK-009 implements no attack/simulation
or source-specific parser beyond optional generic CSV inspection. JSONL/other
formats can be registered as metadata but are not parsed by this CLI.

The Project Manager reports 252 prior tests, 2,000 historical events, 1,647 with
supported SourceIP, 30 IP feature rows, 22 mismatching IPs and unverified legacy
compatibility. These are supplied review observations, not new measurements here.
No private data were available to revalidate them in the cloud.

## Inventory fields

Every field must be present; **null/unknown is honest metadata, not approval**.
The draft command creates scaffolding, not dataset samples or acquisition facts.

| Section | Meaning |
| --- | --- |
| dataset_id / dataset_version | User-assigned stable inventory identity/version; never reused for changed data |
| source_type / acquisition_method / collection_environment | Actual source category, acquisition description and original capture environment; a Kali storage VM is not automatically the historical capture environment |
| record_unit | raw_event, aggregate, or unknown; IP feature rows are aggregates, not independent raw events |
| file | Format, SHA-256 of exact bytes and record count; hash/count may be null until measured |
| schema | Logical schema ID, parser version, required header names, optional record-ID/label fields, explicit column rules |
| timestamps | Actual available fields, confidence and evidence reference; partial Date/Day/Time does not establish a year/timezone |
| observation | Independently reviewed observation start/end, duration and evidence; use null when unknown; record spread is not necessarily capture duration |
| aggregation | Scope/window/exposure declarations; no window/exposure is invented from file names or row counts |
| labels | Availability, source, reliability and evidence; ai_predictions cannot be independently_verified attack truth |
| privacy | public/internal/sensitive/restricted/unknown classification |
| provenance | Acquisition identity, whole collection group, dependence groups, original root-source hashes and evidence |
| event_membership | Complete canonical source-event hash set, common identity namespace and evidence; missing membership blocks planning |
| quality_notes / quality_review | Notes, pending/independently_reviewed status, evidence and unresolved findings |

All SHA-256 values are lowercase 64-character hexadecimal hashes. Evidence hashes
must refer to actual independently reviewed local evidence, not invented strings.
They are references, not cryptographic authentication of the claims. The tool
cannot determine whether an acquisition ID or external review is truthful.

The schema is standard JSON Schema; the dependency-free validator implements the
subset used here: types, required/additional properties, enums, patterns, array
items/uniqueness and numeric bounds. Additional cross-field checks cover label
contradictions, timing, complete raw-event membership and quality evidence. This
is not a general-purpose validator for arbitrary schemas.

Column rules are an explicit list of objects containing field, type
(string/integer/number/ip), nullable, min and max. Use null bounds where inapplicable.
They must be declared from actual schema evidence; the tool does not guess domain
fields or values. Existing shared numeric/IP validation is reused unchanged.
Required columns specify header presence. Blank cells are counted for all fields;
only nonnullable rules/record identifiers make blanks a quality finding.

## Exact Kali Linux workflow

From the repository root with Python 3.10+:

```bash
git fetch origin
git switch task-009-dataset-evaluation
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q

python -m mini_siem.datasets draft \
  --dataset-id openssh-historical --version 1 \
  --source-type ssh_authentication --format csv \
  --output data/inventory/ssh-draft-v1.json
```

Edit that private draft with only verified metadata. For the known structured
SSH CSV, confirm the actual headers before declaring its schema. LineId can be
inspected as an original record reference, but do not assume it is globally
unique. The current applicable parser is ssh-historical-v2; that parser name is
not evidence of the historical producer. Date/Day/Time are partial/ambiguous,
not independently verified full timestamps. Leave the original acquisition,
duration, membership and legacy feature window unknown if unavailable. Do not
fill provenance with pretend independent groups or declare predictions verified.

Register and measure the real CSV without changing it:

```bash
python -m mini_siem.datasets register \
  --manifest data/inventory/ssh-draft-v1.json \
  --file "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --output data/inventory/ssh-registered-v1.json

python -m mini_siem.datasets inspect \
  --manifest data/inventory/ssh-registered-v1.json

python -m mini_siem.datasets validate \
  --manifest data/inventory/ssh-registered-v1.json \
  --file "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv"

mkdir -p reports
siem_dataset_review="$(mktemp -d reports/dataset-readiness-XXXXXX)"
python -m mini_siem.datasets readiness \
  --manifest data/inventory/ssh-registered-v1.json \
  --file "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --output "$siem_dataset_review/readiness.json"
```

Registration fills only measured hash/count fields when absent and rejects
contradicting declared values. Inspection findings become unresolved quality
findings and reset review to pending; it never invents independent quality
approval. Registration can therefore succeed for an incomplete/unready dataset.
Without --file it registers metadata declarations only, with no claim that bytes
were inspected. Existing files are never overwritten; use fresh inventory/report
versions when repeating. All input/output paths are configurable.

CSV checks reuse the strict loader on a private snapshot: malformed records,
duplicate/empty headers and bad UTF-8 are rejected; original bytes stay unchanged.
Reports count missing headers/blanks, duplicate nonblank IDs, exact duplicate rows,
declared type/range errors, label-field coverage and timestamp limitations. No
raw record values, labels, IPs, usernames or filesystem paths are echoed in safe
errors. Full `inspect` output intentionally shows private metadata; do not publish it.
Partial timestamps are reported as partial, not repaired. They become a quality
contradiction if the inventory falsely declares independently verified full times.
Values outside a verified half-open observation interval are flagged. Metadata
availability/reliability and label counts do not independently establish truth.

Exit codes: 0 = operation/metadata validation completed without file findings,
**not approval**; 1 = invalid metadata or supplied-file quality findings; 2 =
malformed inputs, output conflicts, unsupported inspection, or rejected split.
Readiness may return 0 with planning_ready false: inspect blockers. All reports
and plans keep training_allowed and inference_allowed false. No dependencies
were added, and there is no model/SQLite compatibility override.

## Provenance and event identity rules for planning

A plan requires known acquisition method/environment, schema/parser IDs, nonempty
file hash/count, reviewed quality, scope/exposure, aggregation window for
aggregate rows, complete membership, and evidence-backed collection/lineage/
dependence identities. Obvious unknown placeholders are not accepted as provenance.
Incomplete manifests remain useful inventory entries but cannot be planned.

Use the same global event-identity namespace/recipe across all manifests. A
suitable declared recipe hashes canonical namespace + immutable original capture
identity + original event reference. Keep the capture identity/reference the
same across copies, parsers, exports and aggregates. A position is usable only
within the same immutable original capture, not a newly numbered export. Never
hash only SourceIP, only message text, or a fresh per-export row ordinal to hide
shared events. Obtain upstream membership mappings and review them independently.

For aggregate rows, list the union of every contributing original event identity;
its size need not equal the number of aggregates. A complete raw-event inventory
must have one unique identity per record. Root lineage connects derived files to
their original captures. Dependence groups identify shared host/entity/session/
scenario/campaign context where applicable, including correlated observations
across different source categories. Identity hashes protect neither low-entropy
identifiers nor dishonest metadata; keep manifests/evidence private and reviewed.

The planner cannot reconstruct these facts from the existing historical SSH file.
Do not split its 30 IP rows or rename exports as independent acquisition groups.
See [split planning and evaluation](dataset-evaluation.md).

## Validation evidence

On Python 3.12 in the cloud, **296 tests passed**: all 252 existing tests and
44 dataset/evaluation regressions. Dependency and Git whitespace checks passed.
Coverage includes source-category metadata, unknown drafts, malformed/duplicate
fields and identifiers, declared CSV types/ranges, hash/count preservation,
timestamp confidence, prior-prediction label rejection, quality-review gates,
registration/inspection/readiness, reproducibility, cross-partition lineage/
event/group/dependence overlap, temporal ordering, random-split rejection and
output protection. Existing AI/backend/dashboard tests remain passing.

A separate CLI check used only temporary synthetic manifests: an explicitly
assigned verified-time plan was generated, a shared collection group was rejected,
and training/inference stayed false. Temporary manifests/plans were removed.
Real-data inventory/provenance validation remains pending. No private manifests,
logs, plans, reports, models or databases are committed.
