# TASK-011: Native SSH telemetry quality and evidence review

This workflow reads TASK-010 native OpenSSH captures and writes a separate local
JSON/Markdown review. It does not run SSH, create users, touch credentials, write
SQLite, issue alerts, train models or make predictions. The native adapter,
legacy contracts and lab security controls are unchanged.

## Safely synchronize pytest.ini on Kali

Repository-level `pytest.ini` now contains exactly:

```ini
[pytest]
testpaths = tests
```

Default `python -m pytest -q` therefore discovers tests only in `tests/`, avoiding
root-private captures beneath `data/`. Explicitly requesting another test path
still overrides discovery; do not run pytest against private captures.

Your existing untracked `pytest.ini` may block checkout. First run `git status
--short` and preserve unrelated changes through your normal Git workflow. Do not
use `git clean`, force checkout or blanket stashing that includes private data.
If `pytest.ini` is untracked and has exactly the content above, use this narrow
backup step before switching branches:

```bash
python3 - <<'PY'
from pathlib import Path
import subprocess
p = Path('pytest.ini')
backup = Path('pytest.ini.task011-local-backup')
if subprocess.run(['git', 'ls-files', '--error-unmatch', 'pytest.ini'],
                  capture_output=True).returncode == 0:
    print('Already tracked: leave it in place and review git status.')
elif p.exists():
    if p.is_symlink() or p.read_bytes() != b'[pytest]\ntestpaths = tests\n':
        raise SystemExit('Different local configuration: preserve and review it manually; nothing changed.')
    if backup.exists():
        raise SystemExit('Backup already exists: review it first; nothing changed.')
    p.rename(backup)
    print('Preserved the exact local configuration in pytest.ini.task011-local-backup')
else:
    print('No local pytest.ini to move.')
PY
git fetch origin main task-011-ssh-evidence-review
git switch task-011-ssh-evidence-review
git pull --ff-only origin task-011-ssh-evidence-review
```

If this branch has not been checked out locally, Git normally sets up tracking
when switching; alternatively use `git switch --track
origin/task-011-ssh-evidence-review`. Once checked out, compare the preserved file
with the tracked one (`cmp pytest.ini pytest.ini.task011-local-backup`). Keep the
backup private/untracked or remove only that exact backup after verifying equality.
Do not commit it. No dataset or capture directory is moved or removed.

## Run a review

From the repository root, activate the existing environment and use fresh paths:

```bash
source .venv/bin/activate
python -m pytest -q
python -m mini_siem.evidence_review \
  --collection-dir data/native-lab/capture-001 \
  --output-dir reports/native-lab/review-001
```

The account running this command needs existing authorized read access to the
capture and write access to the report parent. The CLI requires no privilege
escalation and never changes permissions on input evidence. If access is denied,
ask the evidence owner to arrange authorized review; do not recursively chmod,
copy private keys or relax the lab's protections. An already authorized analysis
session can use the same commands. No working SSH service is needed.

Inputs are `raw-sshd.log`, `events.csv`, `collection.json`, `inventory.json`,
`quality.json` and all indexed files in `experiments/`. A collection that
explicitly has no experiment references can still be reviewed, but correlation
is unavailable. Missing indexed manifests, extra unindexed experiment files,
invalid provenance or inconsistent metadata cause refusal. Fresh outputs are:

- `review.json`: versioned machine-readable quality, categories, per-event
  references, unsupported explanations, experiment candidate references and blockers.
- `review.md`: readable counts, reasons, experiment/attempt summaries and limitations.

Console output contains only the review version, total records and disabled
training/inference flags. There is deliberately no raw-log output switch. Use
event references to inspect original evidence only in an authorized private
review session. Both outputs stay under ignored `reports/`; do not commit them.
An existing or nested-in-evidence output directory is rejected. Input validation
finishes before any output directory is created.

## What integrity verification establishes

Exact input bytes are read into a private temporary snapshot. The existing
TASK-010 `inspect_collection` verifies raw/CSV and experiment hashes and reuses
`kali-sshd-native-v1` to reproduce normalized events. The additional review checks
process identity consistency, collection interval, experiment IDs/account/process,
completed manifest structure, disabled labeling/training/inference flags and
regenerated inventory/quality agreement. Symlinked evidence files or experiment
directories are refused. Temporary snapshots are deleted when review ends;
original evidence is never edited.

Inventory and quality are expected to be the original TASK-010 generated drafts.
If an analyst has independently edited those files, preserve their changes as
separate evidence; this workflow refuses to silently accept an inconsistent draft.
Hashes and cross-file consistency are not signatures. Coordinated alteration of
all files and hashes cannot be ruled out without an external trusted evidence
anchor. No independent provenance certification is claimed. Concurrent input
changes that affect consistency cause refusal; arrange a stable capture first.

## Versioned evidence categories

Review scheme `ssh-evidence-review-v1` is separate from the unchanged native
normalization adapter. It uses anchored, conservative native message rules:

| Category | Evidence required |
| --- | --- |
| authentication_success_evidence | Explicit `Accepted publickey for … from … port … ssh2` form with valid numeric IP/port and recognized optional key fingerprint form |
| authentication_failure_evidence | Corresponding explicit `Failed publickey` form |
| session_open_evidence | Explicit `Starting session: command for … from … port … id …` form |
| session_close_evidence | Explicit `Close session: user … from … port … id …` form |
| connection_or_transport_event | Recognized listening, connection, disconnect or termination form; no authentication outcome inferred |
| unsupported_or_ambiguous | Everything else, including incomplete, malformed, unfamiliar or untrusted-looking authentication syntax |

The review handles only explicitly supported server forms; it does not invent
support for every OpenSSH version, auth method, PAM diagnostic or invalid-user
variant. A broad native-adapter prefix match may still be ambiguous under these
stricter review rules. Such records are counted separately. A client exit of 0
or 255 never becomes server authentication evidence. Explicit failure is evidence
of an authentication failure, not proof of malicious behavior. Explicit success
is not evidence of an attack either.

Unsupported records are grouped into fixed privacy-safe categories: PAM-related,
authentication/diagnostic, connection/session and unrecognized native message.
Each has an event reference, a fixed explanation of the missing adapter rule and
a format/insufficient-evidence gap. No actual message, account, IP or fingerprint
is copied into reports. These are implementation-based explanations, not guesses
about private message semantics. Unsupported does not mean malicious. New parser
support requires a separate evidence-backed change; TASK-011 never changes
normalization or labels.

## Interpret experiment correlation conservatively

Each reviewed manifest contributes its UUID, scenario, expected result, status,
recorded attempt count and client exit codes. Candidate server references require
explicit authentication evidence matching the manifest account, loopback source
and expected evidence type. Those account/IP values are used internally, not
printed. Candidate lists can overlap across experiments with the same intent.

No trustworthy original event times or per-attempt connection IDs exist in this
capture format. Therefore **all event-to-experiment assignments remain unresolved**,
even if only one candidate happens to exist. Manifest action times and collection
start/end are not substituted for event times. All records remain unassigned;
the report separately lists records with no candidate experiment. Session and
transport evidence remain visible as categories without being force-assigned to
a scenario. Agreement between expected/client/server counts is not correlation
proof and does not create ground truth. Reliable future correlation would require
independently justified timing and/or explicit server/client connection identifiers
and review of ambiguity; TASK-011 does not collect or invent them.

## Quality and research limits

Reports cover total/supported/unsupported records, source coverage and status,
repeated exact message occurrences, duplicate event references, provenance and
TASK-009 readiness blockers. Repeated identical messages at different line
positions retain distinct native event references; do not delete them as presumed
duplicates. Cross-capture overlap still requires the existing inventory/planning
checks; this review does not declare captures independent.

Available snapshot records do not establish complete collection, exposure duration
or observation completeness. Labels remain unverified and original event timestamps
unavailable. `training_allowed`, `inference_allowed` and `event_labels_assigned`
remain false. No attack accuracy, precision, recall or generalization is calculated.
Opaque hashes/references and experiment IDs are still private correlation metadata;
store the reports securely even though raw messages and IPs are omitted.

The supplied Kali observations (39 records, 31 supported, 8 unsupported, 23 with
SourceIP, four scenarios and six attempts) are user-reported context, not hardcoded
results or cloud-verified findings. Actual contents are private and unavailable
here. The code/tests use synthetic fixtures; detailed real unsupported categories
and correlation findings remain pending a local run.

## Validation results

Cloud checks: **393 tests passed** (366 existing and 27 new synthetic review
tests). Dependency consistency, Python compilation and whitespace checks passed.
No new dependencies or privileged operations were introduced. Real private
Kali capture analysis remains pending.

## Exact local validation

```bash
python -m pytest -q
python -m pytest -q tests/test_evidence_review.py
python -m pytest --collect-only -q
python -m pip check
python -m mini_siem.evidence_review \
  --collection-dir data/native-lab/capture-001 \
  --output-dir reports/native-lab/review-002
```

Check the generated `review.json` and `review.md` privately, including integrity,
counts, candidate overlap and unresolved findings. A failed command returns 2 with
a generic message and no raw content, sensitive paths or traceback. It creates no
report directory on evidence-validation failure. No privileged lab lifecycle
operations should be run for this task. Stop after TASK-011; do not merge or begin
TASK-012 without review.
