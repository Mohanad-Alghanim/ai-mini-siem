"""Opt-in isolated lab controls and read-only native telemetry analysis."""

import argparse
import json
from pathlib import Path
import subprocess

from mini_siem.evaluation.inventory import read_json, readiness
from mini_siem.lab.control import SCENARIOS, collect, load_state, local_host, prepare, scenario, trust_host, verify
from mini_siem.lab.isolation import COMPOSE, validate_config
from mini_siem.lab.telemetry import ADAPTER_VERSION, csv_bytes, normalize, quality_summary


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest='command',required=True)
    commands.add_parser('config-check')
    commands.add_parser('check-host')
    for command in ('prepare','verify','trust-host','scenario','stop','collect'):
        sub=commands.add_parser(command)
        sub.add_argument('--runtime',type=Path,required=True)
        if command=='prepare':sub.add_argument('--ack-isolated-host',action='store_true',help='Only after verifying a host-only/disconnected VM with no external bridge routes')
        if command=='scenario':sub.add_argument('--name',choices=tuple(SCENARIOS),required=True)
        if command=='collect':
            sub.add_argument('--output-dir',type=Path,required=True)
            sub.add_argument('--run-manifest',type=Path,action='append',default=[])
    inspect=commands.add_parser('inspect',help='Read-only collected-format/quality/inventory inspection')
    inspect.add_argument('--collection-dir',type=Path,required=True)
    args=parser.parse_args(argv)
    try:
        if args.command=='config-check':
            validate_config(read_json(COMPOSE));result={'static_configuration':'passed','runtime_isolation_not_yet_checked':True}
        elif args.command=='check-host':
            local_host();result={'local_unix_docker_endpoint':True,'host_firewall_vm_isolation':'operator verification still required'}
        elif args.command=='prepare':result=prepare(args.runtime,args.ack_isolated_host)
        elif args.command=='verify':
            verify(args.runtime);result={'container_isolation_checks':'passed','host_network_isolation':'operator attested, not independently proven'}
        elif args.command=='trust-host':result=trust_host(args.runtime)
        elif args.command=='scenario':result=scenario(args.runtime,args.name)
        elif args.command=='stop':
            root,_=load_state(args.runtime)
            (root/'STOP').touch();result={'stop_marker_set':True,'next_action_will_stop':True,'shutdown':'explicit docker compose down remains required'}
        elif args.command=='collect':result=collect(args.runtime,args.output_dir,args.run_manifest)
        else:
            root=args.collection_dir
            collection=read_json(root/'collection.json')
            if collection.get('adapter_version')!=ADAPTER_VERSION:raise ValueError('Unsupported collection adapter version')
            raw=(root/'raw-docker.log').read_bytes()
            from mini_siem.lab.telemetry import sha256
            if sha256(raw)!=collection['raw_sha256'] or sha256((root/'events.csv').read_bytes())!=collection['normalized_sha256']:
                raise ValueError('Collection hashes do not match')
            records=normalize(raw,collection['provenance'])
            if csv_bytes(records)!=(root/'events.csv').read_bytes():raise ValueError('Normalized evidence does not match the versioned adapter')
            result={'telemetry':quality_summary(records),'inventory_readiness':readiness(read_json(root/'inventory.json'),root/'events.csv')}
        print(json.dumps(result,indent=2))
        return 1 if result.get('status') in ('operator_stopped','operator_interrupted','aborted_pending_review','unexpected_client_result') else 0
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError) as exc:
        print(f'SSH lab command failed ({type(exc).__name__}); check isolated local Docker state, prepared runtime, supported format and fresh paths. No isolation bypass is available.')
        return 2


if __name__=='__main__':raise SystemExit(main())
