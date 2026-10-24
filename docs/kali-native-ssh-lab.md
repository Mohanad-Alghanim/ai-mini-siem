# TASK-010: Kali-native SSH security laboratory

This lab uses native OpenSSH, Python subprocesses and local files. No container
runtime or additional VM is used. It is separate from historical ingestion,
SQLite, alerts, the dashboard, legacy feature contracts and the Isolation Forest.
It does not authorize training or inference. Real SSH execution and security
validation must take place on Kali, not in the cloud development environment.

## 1. Understand the isolation and privileges

The dedicated sshd binds **127.0.0.1:2222**, IPv4 only. It uses its own temporary
configuration, host key, PID and native log file in a fresh root-owned
`/run/mini-siem-native-NAME` directory. It never reads or edits system-wide
`sshd_config`, calls systemctl/service, or stops/restarts the existing SSH service.
An occupied port aborts startup; there is no alternate target or bind override.
Effective configuration is checked before startup, then `ss` must show exactly
one loopback listener belonging to the recorded process. Any wildcard/IPv6 or
foreign listener on port 2222 fails verification.

Root is required for account creation, normal OpenSSH privilege separation,
process ownership checks, reading shadow policy and account cleanup. Review and
trust this repository and its virtual environment before explicitly executing
its Python as root. Do not use a privileged interpreter on untrusted code.
Never run pip as root for this lab. Nonprivileged `check`, `inspect` and pytest
need no account creation or working daemon.

A unique system account `msl<10 hex digits>` is created with primary group
`nogroup`, no supplementary groups, an invalid password hash and no writable
home. Its `/bin/sh` shell is necessary for OpenSSH's forced `/bin/true` command;
it does not provide an interactive lab shell. The root-owned public authorized
key is readable through an otherwise unlistable runtime (0711); private keys,
configuration, state and logs are root-only. Password, keyboard-interactive,
root login, PAM, TTY, user rc/environment files, forwarding and tunnels are
disabled. Only this account is allowed. A separate unauthorized disposable key
produces rejection tests. No real passwords are used.

Loopback prevents external network binding; it does not isolate hostile local
users, compromised root or OpenSSH vulnerabilities. Use a trusted Kali host,
keep OpenSSH patched, and do not configure external proxies/SSH tunnels that
expose port 2222. No firewall or network-interface changes are needed. If you
cannot establish these assumptions or account restrictions, do not start.
Allow roughly tens of MiB for this tiny lab plus normal Python/OpenSSH usage;
reserve at least 100 MiB free in `/run` (estimates, not measured benchmarks).
The daemon's file-size limit is 5 MiB and core dumps are disabled. This is not
a high-volume collector or production security boundary.

## 2. Check prerequisites without changing services

From the repository root on Kali:

```bash
python3 -m venv .venv             # only if an environment does not already exist
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m mini_siem.kali_ssh_lab check
command -v ssh ssh-keygen ss
/usr/sbin/sshd -V
getent group nogroup
sudo test -d /run/sshd
```

Required native packages are `openssh-server`, `openssh-client`, `iproute2`,
Python/venv and the normal account-management utilities (`useradd`, `userdel`,
`getent`). Linux/Python must support pidfds. No new Python dependencies are added.
The read-only check reports available tools; it does not certify live isolation.

If packages are missing, have the Kali administrator install them under local
policy **without starting, restarting or reconfiguring the existing SSH
service**. Package post-install scripts can start/restart services, so this guide
intentionally does not automate package installation. A planning-only check is:

```bash
apt-get --simulate install openssh-server openssh-client iproute2
```

Review actual installation separately. After installation, take the service
baseline below before any laboratory commands. If `/run/sshd` is absent, an
administrator can explicitly create the standard root-owned 0755 privilege-
separation directory (`sudo install -d -o root -g root -m 0755 /run/sshd`). This
is not a service start or configuration change; never chmod an existing
misconfigured directory blindly. The CLI refuses startup if its ownership or
permissions are unsafe. It does not create or delete that shared directory.

## 3. Record the existing Kali SSH service baseline

These read-only commands record system service identity and configuration hashes.
They do not stop or reconfigure services. Reports stay private under ignored
`reports/`. Use new filenames for a new validation session.

```bash
mkdir -p reports/native-lab
sudo find /etc/ssh -type f \( -name sshd_config -o -name '*.conf' \) \
  -exec sha256sum {} + | sort > reports/native-lab/system-config-before.txt
systemctl show ssh.service ssh.socket \
  -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp \
  > reports/native-lab/system-service-before.txt
sudo ss -H -ltnp > reports/native-lab/listeners-before.txt
```

`ssh.socket` may be absent; record that rather than enabling it. If systemd is
not used, record the existing sshd process identity and supervision status using
your administrator's read-only tools instead. If anything already uses 2222,
leave it alone. This version has a fixed port and must refuse to start.

## 4. Prepare, start and verify

Keep the same Bash terminal and repository working directory:

```bash
lab_python="$PWD/.venv/bin/python"
lab_runtime=/run/mini-siem-native-demo
sudo "$lab_python" -m mini_siem.kali_ssh_lab prepare --runtime "$lab_runtime"
sudo "$lab_python" -m mini_siem.kali_ssh_lab start --runtime "$lab_runtime"
sudo "$lab_python" -m mini_siem.kali_ssh_lab verify --runtime "$lab_runtime"
sudo ss -H -ltnp 'sport = :2222'
```

Expect only `127.0.0.1:2222` owned by the recorded lab PID, never `0.0.0.0`, `*`
or IPv6. Startup verifies `sshd -t`, effective `sshd -T` settings and ownership.
A race for the port cannot count as successful startup. Startup verification
failure terminates only its own unreaped child. Other services are not signaled.
A reused/changed PID, executable, boot identity or account causes refusal.
Subsequent shutdown uses a pidfd and validates start ticks to avoid signaling an
unrelated process. Do not use broad `pkill sshd` or `killall sshd` commands.

`prepare` creates only the dedicated account and runtime; it installs no software
and starts no server. The account is not automatically removed on an error.
If preparation fails after creation, `preparation.json` records the intended
account and, where available, its UID. Review it before manual recovery.
Never reuse another account or loosen permissions to make validation pass.

**Clean up before reboot.** `/run` is volatile but system accounts persist.
Optionally retain a root-private audit copy of `state.json` outside `/run` using
an explicitly chosen fresh directory, e.g. `/root/native-lab-demo-audit/`.
It contains account/provenance identifiers and hashes, not private key values.
This helps identify orphaned accounts after a reboot; it is not authorization
to delete an account without checking its UID, home, shell and running processes.

## 5. Execute fixed scenarios

```bash
sudo "$lab_python" -m mini_siem.kali_ssh_lab scenario --runtime "$lab_runtime" --name success
sudo "$lab_python" -m mini_siem.kali_ssh_lab scenario --runtime "$lab_runtime" --name single-failure
sudo "$lab_python" -m mini_siem.kali_ssh_lab scenario --runtime "$lab_runtime" --name three-failures
sudo "$lab_python" -m mini_siem.kali_ssh_lab scenario --runtime "$lab_runtime" --name session-logout
```

| Scenario | Fixed action | Maximum attempts |
| --- | --- | --- |
| success | Authorized key and short forced session | 1 |
| single-failure | Unauthorized key rejection | 1 |
| three-failures | Same unauthorized key, 2-second gaps | 3 |
| session-logout | Authorized key, forced `/bin/true`, normal session close | 1 |

Both successful cases deliberately use the same short, noninteractive session;
there is no unrestricted shell. Failures test public-key rejection, not password
spraying or password-list attacks. Attempts cannot target arbitrary IPs/accounts.
SSH client config is disabled with `-F /dev/null`, proxies/agents are disabled,
and the independently generated host key is pinned with strict checking.
Only one scenario can run at a time; each attempt has a 10-second timeout.

Press Ctrl+C to interrupt or, in a second repository terminal, request a stop:

```bash
sudo "$PWD/.venv/bin/python" -m mini_siem.kali_ssh_lab request-stop \
  --runtime /run/mini-siem-native-demo
```

This persistent marker stops subsequent attempts, including during rate-limit
waits. The current attempt remains time-bounded. `stop` below terminates the
owned listener. No command clears a stop marker or restarts an old environment;
use a fresh runtime for a new experiment.

## 6. Manifests, native logs and collection

Each `experiment-UUID.json` (format version 1) records experiment/scenario ID,
environment, actual process identity (PID/start ticks/boot/executable/UID), test
account, UTC start/end, expected result, bounded actions and client exit codes,
status and a native-log evidence reference. Interrupted/error runs retain their
status and partial action evidence. An unfinished manifest is rejected at
collection. Intent and client code 255 are not verified log-event labels:
255 may mean connection or host-key failure. Correlate actual server evidence
before any future event labeling. No credentials or client raw output are copied
into experiment manifests.

Stop first for a stable final snapshot (collection also supports a running log,
but rejects an incomplete trailing line). Then collect to a fresh private path:

```bash
sudo "$lab_python" -m mini_siem.kali_ssh_lab stop --runtime "$lab_runtime"
sudo "$lab_python" -m mini_siem.kali_ssh_lab collect --runtime "$lab_runtime" \
  --output-dir "$PWD/data/native-lab/capture-001"
sudo "$lab_python" -m mini_siem.kali_ssh_lab inspect \
  --collection-dir "$PWD/data/native-lab/capture-001"
sudo "$lab_python" -m mini_siem.datasets inspect \
  --manifest "$PWD/data/native-lab/capture-001/inventory.json"
sudo "$lab_python" -m mini_siem.datasets validate \
  --manifest "$PWD/data/native-lab/capture-001/inventory.json" \
  --file "$PWD/data/native-lab/capture-001/events.csv"
sudo "$lab_python" -m mini_siem.datasets readiness \
  --manifest "$PWD/data/native-lab/capture-001/inventory.json" \
  --file "$PWD/data/native-lab/capture-001/events.csv" \
  --output "$PWD/reports/native-lab/readiness-001.json"
```

The fresh capture holds unchanged `raw-sshd.log`, normalized `events.csv`,
`collection.json`, draft `inventory.json`, `quality.json` and exact referenced
experiment manifests under `experiments/`. Root-private access is intentional;
do not make logs or private runtime credentials public. Native logs can expose
account names, key fingerprints and local addresses. All captures, reports,
keys and generated manifests stay outside Git.

Adapter **kali-sshd-native-v1** accepts native OpenSSH `-E` messages, preserves
original whitespace/CR and the raw bytes, flags unsupported native messages and
extracts IPs only in explicit supported `from` contexts with strict validation.
Missing, ambiguous and invalid peers are flagged, never guessed. All-native
unknown input, CSV, invalid UTF-8, truncated or oversized logs are rejected.
Some OpenSSH versions may add new message formats: retain the raw file and
review a versioned adapter change rather than silently using the old parser.

Unlike `OpenSSH_2k.log_structured.csv`, these messages have no historical
EventId/template columns. This adapter never invokes `ssh-historical-v2`,
invents event types or generates legacy model features. The log messages do not
supply an independently verified full date/time. `event_occurred_at` remains
empty; any timestamp text remains in the original message. UTC collection
start/end are process-observed times, not reconstructed authentication times.
Clock trust, event timing and completeness remain pending review.

Event references hash process identity, line position and exact content within
the append-only log. Prefixes of repeated captures keep identical references,
including identical messages at different positions. No rotation/reordering is
supported; a 5 MiB limit stops further daemon writes rather than asserting
complete telemetry. Inspect recomputes normalization and verifies file and
experiment hashes. Hashes detect changes; they do not independently authenticate
honest collection or ground truth.

The TASK-009 draft records source category, hashes/counts, native schema version,
collection UUID, process acquisition identity, lab and host-boot dependence
groups, raw lineage and membership references. Labels stay unavailable; quality
review, observation duration/exposure and trustworthy event times stay unknown.
Different experiments, collection UUIDs or loopback ports do not establish
independent datasets. Readiness blockers are expected, not permission to train.
No prior anomaly labels are used as ground truth. This tiny single-host lab
cannot establish attack accuracy or generalization. See
[dataset evaluation](dataset-evaluation.md).

## 7. Verify unchanged service and clean up

Repeat the read-only baseline checks:

```bash
sudo find /etc/ssh -type f \( -name sshd_config -o -name '*.conf' \) \
  -exec sha256sum {} + | sort > reports/native-lab/system-config-after.txt
systemctl show ssh.service ssh.socket \
  -p Id -p LoadState -p ActiveState -p SubState -p MainPID -p ExecMainStartTimestamp \
  > reports/native-lab/system-service-after.txt
diff -u reports/native-lab/system-config-before.txt reports/native-lab/system-config-after.txt
diff -u reports/native-lab/system-service-before.txt reports/native-lab/system-service-after.txt
sudo ss -H -ltnp 'sport = :2222'
```

Configuration hashes and system-service identity should match; the dedicated
listener should be absent after stopping. Investigate unexpected changes rather
than restarting a system service to make the comparison pass. Service changes
by other administrators or automatic updates need separate explanation.

After securely preserving the capture, remove only lab-owned resources:

```bash
sudo "$lab_python" -m mini_siem.kali_ssh_lab cleanup --runtime "$lab_runtime"
```

Cleanup verifies account identity/restrictions, refuses a live listener or any
remaining account processes, invokes `userdel` on only the recorded account
(without `-f` or `-r`), and removes the dedicated runtime/private keys. It leaves
captures and the existing service untouched. Do not manually delete runtime
first: that destroys the ownership evidence needed for safe account cleanup.

For a failed preparation or reboot-orphaned account, an administrator must review
`preparation.json` or the retained audit copy, compare `getent passwd ACCOUNT`,
`id ACCOUNT`, shadow restrictions and `ps -u ACCOUNT`, confirm it is exactly the
created disposable account and has no processes, then explicitly run
`sudo userdel ACCOUNT` (no force/home removal). Remove only the matching reviewed
runtime/audit directory after retention review. Never infer ownership from a
similar name alone. Interrupted account deletion may require this manual recovery.

## 8. Troubleshooting and pending Kali validation

- Missing packages or `/run/sshd`: use the prerequisites section; no service fallback.
- Occupied 2222: do not kill its owner; lab startup must fail.
- Ownership/hash/account mismatch: stop and investigate; do not chmod private
  files broadly, edit manifests, reuse an existing user or bypass checks.
- Startup errors: review root-private `startup-error.log` and `native.log` locally;
  the CLI deliberately prints no sensitive log contents, filesystem paths or traces.
- Nonzero client result: inspect actual server evidence; it is not a verified label.
- PID mismatch: no signal is sent. Manually review process ownership; do not use
  broad process-name kills. A stopped lab cannot be restarted over its history.
- Unknown format/partial line: stop, collect a stable fresh snapshot and review
  raw evidence. No historical-parser fallback or inference override exists.

Cloud results: **342 tests passed** (296 existing plus 46 native-lab tests).
Python compilation, dependency consistency and whitespace checks passed. No new
Python dependencies were added. No live accounts, servers or services were changed.

Automated checks use synthetic data and mocked subprocesses; they need no root,
server installation or live authentication:

```bash
python -m pytest -q
python -m pip check
```

Cloud validation does not establish Kali security. On Kali, record actual
loopback ownership, fixed scenario client/server evidence, timing and permissions,
raw/normalized record counts and readiness findings, unchanged system-service
hashes/PID, absence of the lab listener after stop and account removal after
cleanup. No real log counts, successful authentications or security validation
are claimed here. Stop after TASK-010 for Project Manager review; do not merge or
begin training, inference or TASK-011.
