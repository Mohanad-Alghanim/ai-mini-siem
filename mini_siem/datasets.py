"""Private dataset inventory/diagnostics/planning CLI; never runs a model."""

import argparse
from copy import deepcopy
import json
from pathlib import Path

from mini_siem.evaluation.inventory import blank_inventory, inspect_csv, metadata_errors, read_json, readiness, validate_schema
from mini_siem.evaluation.splits import plan_splits
from mini_siem.ssh_logs import check_output_paths


def save_json(path, value, inputs):
    check_output_paths([path], inputs)
    text = json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation also prevents accidental overwrite between check/write.
    with path.open('x', encoding='utf-8') as handle:
        handle.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    draft = commands.add_parser('draft', help='Create unknown metadata scaffolding, not data samples')
    draft.add_argument('--dataset-id', required=True)
    draft.add_argument('--version', required=True)
    draft.add_argument('--source-type', required=True)
    draft.add_argument('--format', choices=('csv','jsonl','other'), default='csv')
    draft.add_argument('--output', type=Path, required=True)
    for command in ('register','inspect','validate','readiness'):
        subparser = commands.add_parser(command)
        subparser.add_argument('--manifest', type=Path, required=True)
        if command != 'inspect':
            subparser.add_argument('--file', type=Path, help='Optional existing CSV; other formats are metadata-only')
        if command == 'register':
            subparser.add_argument('--output', type=Path, required=True)
        if command == 'readiness':
            subparser.add_argument('--output', type=Path, required=True)
    split = commands.add_parser('plan')
    split.add_argument('--manifest', type=Path, action='append', required=True)
    split.add_argument('--assignment', type=Path, required=True)
    split.add_argument('--method', choices=('group','temporal'), default='group')
    split.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'draft':
            save_json(args.output, blank_inventory(args.dataset_id,args.version,args.source_type,args.format), [])
            print(json.dumps({'draft_created': True, 'provenance': 'unknown', 'training_allowed': False, 'inference_allowed': False}))
            return 0
        if args.command == 'plan':
            manifests = [read_json(path) for path in args.manifest]
            plan = plan_splits(manifests, read_json(args.assignment), args.method)
            save_json(args.output, plan, [*args.manifest,args.assignment])
            print(json.dumps({'plan_created': True, 'method': args.method, 'training_allowed': False, 'inference_allowed': False}))
            return 0
        manifest = read_json(args.manifest)
        if args.command == 'inspect':
            errors = metadata_errors(manifest)
            if errors:
                print(json.dumps({'metadata_valid': False,'errors': errors}))
                return 1
            print(json.dumps(manifest, indent=2))  # Explicit private metadata inspection.
            return 0
        inputs = [args.manifest] + ([args.file] if args.file else [])
        if args.command == 'register':
            if validate_schema(manifest):
                raise ValueError('Invalid inventory structure')
            manifest = deepcopy(manifest)
            if args.file:
                inspection = inspect_csv(args.file, manifest)
                if 'file hash mismatch' in inspection['findings'] or 'record count mismatch' in inspection['findings']:
                    raise ValueError('Supplied file contradicts declared provenance')
                manifest['file']['sha256'] = inspection['sha256']
                manifest['file']['record_count'] = inspection['record_count']
                if inspection['findings']:
                    review = manifest['quality_review']
                    review['unresolved_findings'] = sorted(set(review['unresolved_findings']) | set(inspection['findings']))
                    review['status'], review['evidence_sha256'] = 'pending', None
            if metadata_errors(manifest):
                raise ValueError('Invalid inventory metadata')
            save_json(args.output, manifest, inputs)
            print(json.dumps({'registered': True, 'training_allowed': False, 'inference_allowed': False}))
            return 0
        report = readiness(manifest, args.file)
        if args.command == 'readiness':
            save_json(args.output, report, inputs)
        print(json.dumps(report, indent=2))
        return 0 if report['metadata_valid'] and not (report.get('inspection') or {}).get('findings') else 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f'Dataset command failed ({type(exc).__name__}); check inventory schema, provenance, independent groups and fresh output paths.')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
