# Team Kali operations

Use this guide with the preserved local delivery checkout on
`task-012-dashboard-simplification`. Its TASK-012/documentation consolidation
is uncommitted and unpublished; main still represents the earlier dashboard.
The [README](../README.md) explains scope and
[final demonstration guide](final-demonstration.md) contains the full acceptance
checklist. No teammate should widen the lab listener or treat an anomaly as a
verified attack.

## Start, stop and restart on the existing Kali machine

```bash
cd ~/ai-mini-siem
source .venv/bin/activate
export MINI_SIEM_DATABASE="$PWD/data/mini-siem.db"
python -m streamlit run mini_siem/dashboard/app.py \
  --server.address 127.0.0.1 \
  --server.port 8501 \
  --browser.gatherUsageStats false
```

Open http://127.0.0.1:8501 in the **same Kali machine's browser**. The database
must already exist and be readable. The command does not create demonstration
records or run AI. Press Ctrl+C in that terminal to stop. Stored data remains.

For tomorrow's presentation, run the same block again. Each new terminal needs
its own activation and environment variables. Use `deactivate` only after
stopping Streamlit if you want to leave the venv. Do not reboot as a substitute
for lab cleanup: `/run` disappears but disposable system accounts can persist.

An already prepared, user-readable sanitized native review is optional:

```bash
export MINI_SIEM_LAB_REVIEW="$PWD/reports/dashboard-evidence/review.json"
```

Set it before launch outside the UI. No path-input widget is displayed. This
report is not included in Git; if absent, leave the variable unset. The database
screens work without native evidence. Never start the dashboard as root to access protected captures.

## Set up another teammate's Kali VM

```bash
cd ~
git clone --branch main https://github.com/Mohanad-Alghanim/ai-mini-siem.git
cd ai-mini-siem
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

These clone commands install published main only, not the unpublished final
working changes. Obtain an approved working-copy handoff or later approved
published revision for the consolidated four-page UI.

For an empty application, explicitly initialize a **new** database:

```bash
python -m mini_siem.backend init --database data/mini-siem.db
```

Then use the launch block above. Empty tables after a fresh clone are expected.
Do not make up events or retrain a model to populate a presentation. To use the
recorded project demonstration, request the approved private assets below.
A fresh environment may not match the existing model's exact scikit-learn
version; restore the recorded trusted runtime before inference. Dashboard-only
viewing of stored predictions does not require loading that artifact.

Git/Python prerequisite installation is an administrator operation. Optional
OpenSSH packages can have service-starting post-install scripts: review the
[native guide](kali-native-ssh-lab.md) first. Do not change system Python, use
root pip or stop/reconfigure an existing system SSH service.

## Private assets and approved handoff

| Local asset | Needed for | Handling |
| --- | --- | --- |
| SQLite database/consistent backup | Existing event/prediction/alert presentation | Sensitive history; use approved private transfer and protect sidecars/backups |
| Historical structured CSV | Event ingestion or fresh demonstration preparation | Project-owned private original; keep unchanged |
| Original 30-row baseline | Confirmed original-baseline model replay only | Preserve training pairing, approved hash and semantics |
| Trusted model and runtime records | New inference without fitting | Joblib can execute code; recover exact approved artifact/environment |
| Root-private native capture/manifests | Authorized evidence integrity review | Keep ownership/permissions; do not give the dashboard direct access |
| Sanitized V2 review.json | Native evidence display | Share only the reviewed derived report with the dashboard user |
| Disposable lab keys/state | Operation/cleanup of that one restricted lab | No teammate/public handoff, no Git, no screenshots |

These files are excluded from Git for privacy and safety. Check `.gitignore`;
never force-add security data. A clone provides code/configuration, not the
populated database, trained artifact or log capture. Make a consistent SQLite
backup using SQLite backup tooling rather than copying only a live main file.
The data owner must approve each recipient and the material shared.

The [final preparation workflow](final-demonstration.md#prepare-the-data-choose-one-path)
reuses an existing database or builds a fresh one using confirmed original
assets. Paths in technical guides are examples unless explicitly identified as
the existing Kali setup. Replace them with approved actual paths, not invented
files. A hash computed from unknown bytes is not proof of legacy compatibility.

## Use recorded events and understand predictions

Use the existing database before running new ingestion:

```bash
python -m mini_siem.backend stats --database data/mini-siem.db
```

- Overview summarizes stored records, not attacks or unique users.
- Security Events shows event type, Source IP, available peer-parsing status
  and original/ingestion timestamps. Internal IDs and batch/source-record fields
  are hidden, not regenerated. Original timestamps can be Unknown.
- Predictions shows IP-level Normal/Anomaly outputs and presentation Risk Level.
  The underlying stored scores remain unchanged; numerical scores are hidden.
- Alerts displays Unusual SSH Authentication Behavior, Source IP, Risk Level,
  UTC creation timestamp and description. These are not verified incidents.
- Native SSH lab evidence shows a separate sanitized offline review. It is not
  a new model prediction, database ingestion or automatically linked experiment.

Only Overview, Security Events, Alerts and Predictions are navigation pages.
Use literal IP/name/type searches, available status/classification, Risk Level
and inclusive UTC date ranges together. Event date filtering explicitly chooses
original or ingestion time; Unknown times are excluded only with an active date
filter. All actual timestamps display as YYYY-MM-DD HH:MM:SS in labeled UTC
columns. There are no database-path, batch or model widgets.

Risk bins are display-only: High below -0.1, Medium from -0.1 to below 0, Low
at 0 or above. They are uncalibrated priorities, not attack probabilities or
validated severity. Raw/native events have no assigned model risk.

Use filters and Refresh to reread stored data. An aggregate prediction is not
proof that a particular log event caused it. The 30-row original baseline and
previous 27 Normal / 3 Anomaly / 3 alert observation are not an accuracy claim.
Do not pass newly aggregated historical or native features into the legacy model.

## Review protected native evidence

The owner/authorized analyst can run the **reviewed trusted environment** with
existing authorized read access; the review itself needs no new permissions:

```bash
.venv/bin/python -m mini_siem.evidence_review \
  --collection-dir data/native-lab/capture-001 --diagnostics-only
.venv/bin/python -m mini_siem.evidence_review \
  --collection-dir data/native-lab/capture-001 \
  --output-dir reports/native-lab/team-review-001
```

The report output must be fresh. Do not loosen source permissions or copy raw
logs/keys. If the analyst is in a separate privileged context, follow the
[report-only handoff](final-demonstration.md#prepare-native-evidence-without-exposing-the-capture)
for the derived review.json. The dashboard validates its consistency but does
not reverify the original capture. Counts must come from the supplied report.
Client exits and intended scenario names do not establish event-level labels;
correlation remains unresolved without reliable linking evidence.

## Permitted laboratory activity and team coordination

The optional lab is **127.0.0.1:2222 on the Kali host only**. It is not remotely
accessible, not a teammate target server and not a general-purpose vulnerable
machine. Share a supervised local demonstration or a sanitized report, not an
external route/tunnel into the listener.

One authorized operator coordinates a run. Agree on the fresh runtime/capture
names and approved fixed scenarios, confirm no other activity owns port 2222,
and record the actual experiment IDs and results privately. Run one reviewed
scenario at a time. An evidence reviewer checks integrity and reports ambiguity;
matching expected/client/server counts alone does not create ground truth.
Communicate stop conditions before starting and review findings together before
sharing any report or screenshot.

Permitted after the guide's explicit administrator authorization:

- Success with a disposable authorized key.
- One disposable unauthorized-key failure.
- Three such failures with fixed rate limits.
- A short forced `/bin/true` session followed by logout.

Not permitted: arbitrary targets/accounts, password lists, high-volume attempts,
port forwarding, unrestricted shells, external exposure, weakening ownership
checks or editing existing system SSH configuration. Never change the bind to
`0.0.0.0`. Never stop an unknown process because the port is occupied.

Follow the [native lab guide](kali-native-ssh-lab.md) and the
[demonstration's fixed scenario commands](final-demonstration.md#demonstrate-the-existing-controlled-ssh-scenarios).
Do not restart over an old runtime/capture; use fresh reviewed paths. A persistent
stop marker prevents further actions. Ctrl+C interrupts a scenario; an active
attempt remains bounded. `stop` targets only the verified owned listener.

## Stop, clean up and confirm system SSH is unchanged

The following example uses only the new graduation runtime named in the
presentation guide. Substitute a different runtime only if it is the one you
created and reviewed; never assume a similarly named account/process is yours.

```bash
lab_python="$PWD/.venv/bin/python"
sudo "$lab_python" -m mini_siem.kali_ssh_lab stop --runtime /run/mini-siem-native-graduation
# Collect/preserve the new evidence before cleanup, using a fresh output directory.
sudo "$lab_python" -m mini_siem.kali_ssh_lab collect --runtime /run/mini-siem-native-graduation \
  --output-dir "$PWD/data/native-lab/team-capture-001"
sudo "$lab_python" -m mini_siem.kali_ssh_lab cleanup --runtime /run/mini-siem-native-graduation
sudo ss -H -ltnp 'sport = :2222'
```

These are explicit administrator actions on trusted code, never automatic steps
for ordinary dashboard viewing. Compare system-service state/config hashes with
the **before-run baseline**, using the exact read-only commands in
[the native guide](kali-native-ssh-lab.md#3-record-the-existing-kali-ssh-service-baseline).
The lab listener should be absent; system SSH configuration, service identity and
original capture should be unchanged. Do not restart a system service to hide a
difference. Cleanup refuses an active listener/account process; it is not a broad
kill or user deletion. Review interrupted/reboot recovery in that guide rather
than deleting runtime ownership evidence first.

## Unsupported categories need separate authorized research environments

The repository supplies no password-spraying, scanning, SQL injection,
unauthorized-file-change or DoS detector/target. Supporting those would require,
respectively, suitable multi-account authentication context, network flow data,
HTTP/application evidence, file-integrity baselines, or controlled service/request
metrics, plus authorization and independent evaluation. Such environments do not
currently exist in this repository. Do not improvise them against the protected
SSH lab or unrelated hosts. Repeated SSH key failures do not fill those gaps.

## Troubleshooting and pre-demo checks

Use `.venv/bin/python` explicitly if activation is uncertain. Check imports and
`pip check` before installing anything; a model version mismatch requires the
original compatible runtime, not retraining. An unavailable database/report or an
empty clone is a data/access problem, not evidence that detection failed.
Inspect `ss -ltnp 'sport = :8501'` for an occupied dashboard port; stop only your
known session. Preserve local pytest.ini backups and unrelated changes using the
[evidence guide's safe synchronization procedure](ssh-evidence-review.md#safely-synchronize-pytestini-on-kali).
Do not switch/pull over the uncommitted final delivery working tree. Preserve
all tracked and untracked files. After an authorized future publication, use
the approved revision; cloning current main alone is not the final UI.

Before presenting:

- [ ] Existing environment/test evidence and approved asset paths are recorded; the combined state is explicitly untested.
- [ ] Dashboard binds to 127.0.0.1:8501 and the correct database is selected.
- [ ] Overview, events, predictions, alerts, filters and Refresh are demonstrated.
- [ ] Native report is sanitized/readable; private captures and credentials stay protected.
- [ ] Anomaly, offline processing, unresolved correlation and five unsupported attacks are explained.
- [ ] If a live lab is used, the authorized operator records before/after checks and cleanup.

For the complete acceptance record, use the
[single final checklist](final-demonstration.md#single-final-kali-acceptance-checklist).

## Existing verification evidence

The previous full suite passed 427 tests before TASK-012. TASK-012 passed 51
focused tests plus an event-ID recheck. Those runs used synthetic data; no new
tests, imports or dependency checks were run for this consolidation. Combined
regressions, final commands/links and actual Kali/browser acceptance remain
unverified. Do not imply these earlier counts validate the combined state.

## Screenshots and sharing

Capture the actual local UI only after confirming data selection. Remove or redact
IP/account values, private paths, key fingerprints and sensitive batch/model IDs.
Do not include raw logs, terminal credentials or private artifacts. Keep an original
privately if required by policy; publish only the reviewed redacted image. Add
real screenshots to GitHub after team approval, never substitute generated images
or fabricated counts.
