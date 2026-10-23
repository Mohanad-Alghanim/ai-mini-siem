# Controlled SSH laboratory (TASK-010)

This opt-in lab collects new SSH telemetry for future experiments. It never
trains a model, invokes inference, writes SQLite, or changes the dashboard.
Legacy feature compatibility remains unverified. Anomaly predictions are not
attack ground truth. Do not feed these outputs into the legacy model.

## Architecture and prerequisites

Use a disposable Kali VM, Python and the existing project requirements, a local
Docker Engine with Compose v2, and `ssh-keygen`. Install prerequisites manually
using your institution's approved instructions; this project installs nothing
on the host automatically. Docker access grants powerful host privileges.
Use your ordinary Docker-authorized account, not `sudo python`.

Allow roughly 2 GiB VM RAM and 1–2 GiB spare disk for image building (estimates,
not measured requirements). Each running container is capped at 128 MiB, half a
CPU and 64 processes. The server and separate client share one internal IPv4
bridge. There are no published ports, host network namespaces or Docker socket
mounts. The server listens on container port 2222 only. Its root filesystem is
read-only, with ephemeral host keys in tmpfs; only three SSH privilege-separation
capabilities remain. The client has no capabilities. Both drop privileges via
no-new-privileges and have bounded rotating logs.

**Host prerequisite:** after building images, disconnect the VM's external
adapter or select an isolated host-only network. Verify there is no public,
bridged or forwarded path to Docker's bridge, including host firewall/NAT rules.
Do not change a shared host firewall blindly. VM networking changes require
operator/hypervisor privileges and may interrupt connectivity. Docker can change
host networking when creating/removing its bridge; these are explicit operator
steps below. The CLI checks Docker configuration, membership and local endpoint,
but cannot prove hypervisor or host firewall isolation. Its explicit attestation
is required in addition to those checks. Stop if you cannot verify these facts.
Only trusted local users may access the host and Docker daemon.

The existing host SSH service and configuration are never used or modified.
The disposable `labuser` account accepts a generated key only. Password/root
login, forwarding, tunnels, interactive TTYs and arbitrary commands are disabled.
The server forces `/bin/true`, producing a short noninteractive session/logout.

## Build, isolate, start and verify

Run from the repository root with the existing virtual environment activated:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m mini_siem.ssh_lab config-check
python -m mini_siem.ssh_lab check-host

# Explicit image installation; requires registry/package access during build.
# Installs OpenSSH inside disposable images, never the host SSH service.
docker build -t mini-siem-local/ssh-server:task010 lab/ssh/server
docker build --build-arg LAB_UID="$(id -u)" --build-arg LAB_GID="$(id -g)" \
  -t mini-siem-local/ssh-client:task010 lab/ssh/client
```

Now isolate the VM as described above. The Debian tag/package repositories are
not pinned: this reproduces the configuration, not a bit-identical image.
Collection provenance records actual image IDs and configuration hashes. Future
reviewed releases can pin verified image/package digests; no hashes are invented.
Build steps retain package signature verification and suppress service autostart.

```bash
python -m mini_siem.ssh_lab prepare --runtime data/ssh-lab/runtime --ack-isolated-host
docker compose --env-file data/ssh-lab/runtime/lab.env -f lab/ssh/compose.json \
  up -d --no-build --pull never
python -m mini_siem.ssh_lab verify --runtime data/ssh-lab/runtime
python -m mini_siem.ssh_lab trust-host --runtime data/ssh-lab/runtime
```

`prepare` requires a fresh path and creates owner-only disposable private keys,
a unique environment ID and an environment file. No containers start until the
explicit Compose command. `verify` rejects remote Docker endpoints, foreign or
additional network peers, extra networks, nonprivate subnets, port publication,
unsafe mounts/capabilities and incorrect ownership. Unset Docker/Compose override
environment variables if rejected; do not bypass checks. `trust-host` obtains the
public host key through the verified local container and pins it to that exact
container. SSH host-key verification remains enabled. If SSH initialization is
still starting, wait briefly and retry verification/trust. Replacing the server
requires a fresh environment rather than overwriting its binding.

## Fixed scenarios and stop controls

| CLI name | Fixed action | Limit |
| --- | --- | --- |
| `success` | Authorized disposable key; forced short session | 1 attempt |
| `single-failure` | Unauthorized disposable key | 1 attempt |
| `short-failure-sequence` | Same unauthorized key | 3 attempts, 2 seconds apart |
| `session-logout` | Authorized key; normal short session and close | 1 attempt |

There are no arbitrary host, account, credential-list or attempt-count inputs.
A key rejection is not a password brute-force experiment or a password-spraying
dataset. Both successful scenarios intentionally use the same minimal session.

```bash
python -m mini_siem.ssh_lab scenario --runtime data/ssh-lab/runtime --name success
python -m mini_siem.ssh_lab scenario --runtime data/ssh-lab/runtime --name single-failure
python -m mini_siem.ssh_lab scenario --runtime data/ssh-lab/runtime --name short-failure-sequence
python -m mini_siem.ssh_lab scenario --runtime data/ssh-lab/runtime --name session-logout
```

Each action has an 8-second container timeout and a 10-second outer timeout.
Press Ctrl+C or, from another terminal, set the persistent stop marker:

```bash
python -m mini_siem.ssh_lab stop --runtime data/ssh-lab/runtime
```

It prevents further attempts; an active attempt remains time-bounded. For
immediate shutdown use the Compose `down` command below. A stopped environment
is not automatically resumed; create a fresh runtime for another experiment.

Every scenario writes `experiment-<UUID>.json` before action execution. Version 1
records run/scenario/environment IDs, actual server/client/daemon identities,
account name (no credentials), UTC start/end, bounded action times, credential
role, expected authentication result, client return code, status and server-log
evidence reference. An interrupted/incomplete manifest must be reviewed; a
missing end time cannot be collected as a completed reference. Client code 255
can also mean connection/host-key failure: it does not verify authentication
rejection. Intent and client exits never become individual event labels.

## Collection, inventory and read-only inspection

Use a fresh output directory on every capture. In Kali Bash:

```bash
ssh_lab_runs=()
for ssh_lab_manifest in data/ssh-lab/runtime/experiment-*.json; do
  if [ -f "$ssh_lab_manifest" ]; then
    ssh_lab_runs+=(--run-manifest "$ssh_lab_manifest")
  fi
done
python -m mini_siem.ssh_lab collect --runtime data/ssh-lab/runtime \
  --output-dir data/ssh-lab/capture-001 "${ssh_lab_runs[@]}"
python -m mini_siem.ssh_lab inspect --collection-dir data/ssh-lab/capture-001
python -m mini_siem.datasets inspect --manifest data/ssh-lab/capture-001/inventory.json
python -m mini_siem.datasets validate --manifest data/ssh-lab/capture-001/inventory.json \
  --file data/ssh-lab/capture-001/events.csv
mkdir -p reports/ssh-lab
python -m mini_siem.datasets readiness --manifest data/ssh-lab/capture-001/inventory.json \
  --file data/ssh-lab/capture-001/events.csv --output reports/ssh-lab/readiness-001.json
```

Collection writes only the new directory: original `raw-docker.log`, normalized
`events.csv`, `collection.json`, draft `inventory.json`, aggregate `quality.json`,
and exact referenced experiment copies in `experiments/`. Inspect verifies raw
and normalized hashes, reruns the versioned adapter and performs TASK-009
readiness checks. Validation/readiness may deliberately report blockers; this is
not authorization to train. All these outputs are private and ignored by Git.

Adapter `docker-sshd-native-v1` accepts UTF-8 native sshd messages prefixed with
Docker's full RFC3339 engine timestamps (including timezone and subsecond
precision). It rejects historical structured CSV and absent/malformed prefixes;
it never falls back to `ssh-historical-v2`. Historical CSV has template/event-ID
columns and partial date fields; these native logs do not provide that schema.
Unknown native messages are preserved and marked unsupported. Raw bytes, original
lines and messages are retained; explicitly supported peer contexts use strict
IP validation. Missing, ambiguous and malformed peers remain missing and flagged.
No source identity is inferred from the server's listening address.

`engine_recorded_at` is Docker's timestamp, not a fabricated original sshd event
time. `event_occurred_at` and `event_label` remain empty. Clock correctness/timezone
semantics require independent review; timestamp syntax alone cannot establish
trustworthy temporal splits. Collection start/end and container start are recorded
separately. Export includes available server lifetime records, not just scenario
intervals. Rotation (2 × 5 MiB maximum per service) can discard earlier messages;
completeness and observation/exposure duration are not certified.

Event references hash daemon/container identity, exact engine timestamp and
message. Repeated exports therefore retain overlapping identities; indistinguishable
collisions are flagged rather than assigned invented uniqueness. Collection UUIDs
do not make repeated captures independent. The inventory records actual hashes,
record count, native adapter schema, source category, private classification,
container acquisition identity, environment/daemon dependence groups, raw lineage
and membership references. Quality review remains pending, exposure unknown,
clock confidence unknown and experiment labels unverified. Run references apply
to the collection as a whole: no defensible one-to-one correlation is claimed.
Do not manually relabel predictions as ground truth or split the same environment
into supposedly independent train/test groups. See [evaluation design](dataset-evaluation.md).

## Shutdown, cleanup and troubleshooting

```bash
# Explicitly stops/removes only this prepared Compose project and its network.
docker compose --env-file data/ssh-lab/runtime/lab.env -f lab/ssh/compose.json down --volumes
```

Archive private captures and experiment evidence securely before cleanup. Remove
only the explicitly reviewed runtime directory to destroy disposable credentials;
remove capture directories only after confirming retention policy. Avoid broad
recursive deletion commands. Optional manual image removal uses the two exact
`mini-siem-local/ssh-server:task010` and `mini-siem-local/ssh-client:task010` tags
once all labs are stopped. Host SSH needs no restoration because it was untouched.

If Docker/Compose is missing, install it manually first; no fallback opens host
SSH. Permission failures may indicate incorrect Docker access or a client image
built for a different UID/GID. Rootless/user-namespace mapping may not support
these bind permissions: fail safely instead of making private keys world-readable.
A nonzero scenario exit requires reviewing actual server evidence, not declaring
an attack/failure label. Unsupported native messages remain available for review;
invalid prefixes reject collection before outputs are created. Never suppress
isolation checks to work around another network peer or a public port.

## Validation and limitations

Validation result: **339 tests passed** (296 existing plus 43 lab tests).
Dependency consistency, Python compilation, shell syntax and whitespace checks
also passed. No new Python dependencies were added.

Synthetic tests require no SSH daemon or Docker services:

```bash
python -m pytest -q
```

Cloud checks cover synthetic normalization, timestamps, provenance, overlap,
configuration/runtime isolation rejection, bounded commands, stop/timeouts,
collection, read-only inspection and unchanged legacy paths. Docker Compose
configuration rendering and local Unix Docker endpoint checks passed. Images were
not built and no containers/scenarios were started in this task environment.
Actual Kali image build/start, hypervisor/firewall isolation, successful and failed
server evidence, permissions, capture counts and clock review remain pending.
Record observed values only; no real telemetry results are claimed. A tiny
single-client lab is dependent data and cannot demonstrate detection accuracy or
generalization. Additional independent collection and evaluation approval remain
necessary. Stop after TASK-010 for Project Manager review.
