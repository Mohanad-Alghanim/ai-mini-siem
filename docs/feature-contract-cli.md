# Read-only contract inspection on Kali Linux

From the repository root:

```bash
git fetch origin
git switch task-008-feature-pipeline-strategy
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q

python -m mini_siem.feature_contract
```

A valid contract returns exit 0 for **specification/runtime consistency only**.
The report still says training_allowed, inference_allowed and deployment_allowed
are false. Contract drift returns exit 1 and skips optional input inspection.
Malformed JSON, duplicate keys, invalid input files, or output errors return 2.
There is no approval/override option, model loading, fitting, prediction, database
connection or alert operation. Dependencies and existing behavior are unchanged.

Optionally inspect private input hashes/counts and save a local readiness report:

```bash
mkdir -p reports
ssh_readiness_dir="$(mktemp -d reports/ssh-contract-readiness-XXXXXX)"
python -m mini_siem.feature_contract \
  --contract config/ssh_feature_contract.json \
  --events "$HOME/siem-private/ssh/OpenSSH_2k.log_structured.csv" \
  --baseline "$HOME/siem-private/ssh/ssh_baseline_features.csv" \
  --output-dir "$ssh_readiness_dir"
```

Outputs are readiness.json and readiness.md. Input paths are configurable; either
input is optional. Missing/unavailable supplied files cause an error, not fabricated
hashes or counts. Existing output files/input collisions are rejected. Reports
contain hashes and aggregate counts only, not IPs, raw messages, template text,
usernames or private filesystem paths. Keep them local in ignored reports/.
The tool reads the whole input and uses private temporary snapshots when required
by existing loaders; it does not write original inputs or persist feature exports.

The public contract records code hashes, not private dataset hashes. Optional
input inspection proves only which local bytes were inspected and whether
existing loaders accept them. It does not establish legacy provenance, semantic
compatibility, adequate evaluation data, experimental authorization, or model
readiness. Real-data validation remains pending in the cloud. The Project Manager's
Kali results are attributed in the audit, not re-created as code constants.

Read [the provenance audit](feature-provenance-audit.md) and
[the strategy/consistency design](feature-pipeline-strategy.md) before proposing
any model training. This task does not authorize it.

Validation in the cloud (Python 3.12): **252 tests passed** (228 existing and 24
new contract tests). Coverage includes canonical representation, changed versions/
ordering/types/counting/window/preprocessing, implementation drift with unchanged
version strings, missing/escaping source paths, duplicate/nonfinite JSON,
blocked readiness, private-input hash inspection, unchanged input bytes, output
protection and no model/database operations. Dependency and Git whitespace checks
passed. A separate CLI run generated both readiness reports with contract_valid
true and all model actions false; temporary reports were removed. Real-data
inspection remains pending; no private readiness report is committed.
