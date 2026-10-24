"""Opt-in native SSH lab. Lifecycle actions require root on Kali; inspect is read-only."""

import argparse
import json
from pathlib import Path
import subprocess

from mini_siem.evaluation.inventory import readiness
from mini_siem.feature_contract import read_contract as read_json
from mini_siem.native_lab import control, safety
from mini_siem.native_lab.telemetry import VERSION, csv_bytes, normalize, summary


def inspect_collection(directory):
    root = Path(directory)
    collection = read_json(root/'collection.json')
    if collection['adapter'] != VERSION:
        raise ValueError('Incompatible native telemetry version')
    raw = (root/'raw-sshd.log').read_bytes()
    normalized = (root/'events.csv').read_bytes()
    if safety.digest(raw) != collection['raw_sha256'] or safety.digest(normalized) != collection['normalized_sha256']:
        raise ValueError('Collection hash mismatch')
    records = normalize(raw, collection['provenance'])
    if csv_bytes(records) != normalized:
        raise ValueError('Native normalization does not match preserved evidence')
    for name, expected in collection['experiments'].items():
        import re
        if not re.fullmatch(r'experiment-[0-9a-f-]{36}\.json', name) or safety.digest((root/'experiments'/name).read_bytes()) != expected:
            raise ValueError('Experiment evidence missing or changed')
    return {'quality':summary(records), 'inventory':readiness(read_json(root/'inventory.json'), root/'events.csv')}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('check')
    for name in ('prepare','start','verify','scenario','stop','collect','cleanup','request-stop'):
        sub = commands.add_parser(name)
        sub.add_argument('--runtime', type=Path, required=True)
        if name == 'scenario':
            sub.add_argument('--name', choices=tuple(control.SCENARIOS), required=True)
        if name == 'collect':
            sub.add_argument('--output-dir', type=Path, required=True)
    sub = commands.add_parser('inspect')
    sub.add_argument('--collection-dir', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'check':
            result = control.prerequisites()
        elif args.command == 'inspect':
            result = inspect_collection(args.collection_dir)
        elif args.command == 'verify':
            safety.root_kali(); safety.verify(args.runtime)
            result = {'verified_listener':'127.0.0.1:2222', 'ownership_verified':True}
        elif args.command == 'request-stop':
            safety.root_kali(); root, _ = safety.load(args.runtime)
            (root/'STOP').touch(mode=0o600)
            result = {'stop_requested':True, 'active_attempt_timeout_seconds':10}
        elif args.command == 'scenario':
            result = control.scenario(args.runtime, args.name)
        elif args.command == 'collect':
            result = control.collect(args.runtime, args.output_dir)
        else:
            result = getattr(control, args.command)(args.runtime)
        print(json.dumps(result, indent=2))
        if args.command == 'check' and not result['tools_available']:
            return 1
        return 1 if result.get('status') in ('operator_stopped','operator_interrupted','aborted_pending_review','unexpected_client_result') else 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('Native SSH lab operation refused. Check Kali privileges, fixed loopback listener, owned resources, fresh paths and evidence integrity. No isolation bypass is provided.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
