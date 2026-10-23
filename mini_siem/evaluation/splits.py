"""Deterministic explicit split planning over independent collection units."""

from collections import defaultdict
import hashlib
import json

from mini_siem.evaluation.inventory import readiness, utc_timestamp


PARTITIONS = ('train', 'validation', 'test')


def manifest_digest(manifest):
    return hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def plan_splits(manifests, assignment, method='group'):
    """No event sampling or shuffling; all rows of a dataset stay together.

    Identity/provenance declarations must be independently reviewed. A plan is
    not model authorization or a proof of statistical independence.
    """
    manifests = list(manifests)
    if method not in ('group','temporal'):
        raise ValueError('Random/event-level splitting is unsupported')
    if not isinstance(assignment, dict) or set(assignment) != set(PARTITIONS):
        raise ValueError('Assignment must declare train, validation and test')
    inventory = {}
    for manifest in manifests:
        result = readiness(manifest)
        if not result['metadata_valid'] or not result['planning_ready']:
            raise ValueError('Every dataset needs complete provenance, membership and exposure metadata')
        key = (manifest['dataset_id'], manifest['dataset_version'])
        if key in inventory:
            raise ValueError('Duplicate dataset ID/version')
        inventory[key] = manifest
    selected = {}
    seen = set()
    for partition in PARTITIONS:
        entries = assignment[partition]
        if not isinstance(entries, list) or not entries:
            raise ValueError('Each partition needs at least one distinct collection dataset')
        selected[partition] = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'dataset_id','dataset_version'} or not all(isinstance(value,str) for value in entry.values()):
                raise ValueError('Malformed assignment identity')
            key = (entry['dataset_id'], entry['dataset_version'])
            if key not in inventory or key in seen:
                raise ValueError('Dataset missing or assigned more than once')
            seen.add(key)
            selected[partition].append(inventory[key])
    if seen != set(inventory):
        raise ValueError('All supplied datasets must be explicitly assigned')
    namespaces = {manifest['event_membership']['identity_namespace'] for manifest in manifests}
    if len(namespaces) != 1:
        raise ValueError('Event identity namespaces differ; overlap cannot be safely tested')
    # Root lineage overlap is conservatively rejected even if provided event
    # subsets differ. Splitting one acquisition is outside this planner's scope.
    ownership = defaultdict(set)
    for partition, datasets in selected.items():
        for manifest in datasets:
            provenance = manifest['provenance']
            identities = [('acquisition', provenance['acquisition_id']),
                          ('collection', provenance['collection_group']),
                          ('file', manifest['file']['sha256'])]
            for kind, values in (('dependence', provenance['dependence_groups']),
                                 ('root', provenance['lineage_root_sha256']),
                                 ('event', manifest['event_membership']['event_identity_sha256'])):
                identities += [(kind, value) for value in values]
            for identity in identities:
                ownership[identity].add(partition)
    if any(len(owners) > 1 for owners in ownership.values()):
        raise ValueError('Cross-partition acquisition/group/dependence/file/lineage/event overlap')
    # Multiple exports/aggregations of the same events within a partition can
    # still overweight observations; reject duplicates there too.
    for datasets in selected.values():
        events, files = set(), set()
        for manifest in datasets:
            members = set(manifest['event_membership']['event_identity_sha256'])
            file_hash = manifest['file']['sha256']
            if events & members or file_hash in files:
                raise ValueError('Duplicate underlying events/files within partition')
            events |= members
            files.add(file_hash)
    if method == 'temporal':
        boundaries = {}
        for partition, datasets in selected.items():
            starts, ends = [], []
            for manifest in datasets:
                observation, timestamps = manifest['observation'], manifest['timestamps']
                if observation['confidence'] != 'independently_verified' or timestamps['confidence'] != 'independently_verified':
                    raise ValueError('Temporal planning requires independently verified full timestamps, duration and evidence')
                starts.append(utc_timestamp(observation['start']))
                ends.append(utc_timestamp(observation['end']))
            boundaries[partition] = (min(starts), max(ends))
        if boundaries['train'][1] > boundaries['validation'][0] or boundaries['validation'][1] > boundaries['test'][0]:
            raise ValueError('Temporal partitions overlap or are out of order')
    partitions = {}
    for partition in PARTITIONS:
        datasets = sorted(selected[partition], key=lambda item: (item['dataset_id'],item['dataset_version']))
        partitions[partition] = [{'dataset_id': manifest['dataset_id'], 'dataset_version': manifest['dataset_version'],
                                   'manifest_sha256': manifest_digest(manifest), 'file_sha256': manifest['file']['sha256'],
                                   'acquisition_id': manifest['provenance']['acquisition_id'],
                                   'collection_group': manifest['provenance']['collection_group'],
                                   'record_count': manifest['file']['record_count'],
                                   'membership_evidence_sha256': manifest['event_membership']['evidence_sha256']}
                                  for manifest in datasets]
    plan = {'plan_version': 1, 'method': method, 'partitions': partitions,
            'event_identity_namespace': next(iter(namespaces)),
            'policy': 'whole independent collection units; no event-level random split; disjoint dependence groups and lineage',
            'training_allowed': False, 'inference_allowed': False,
            'limitations': ['Relies on honest, independently reviewed complete identity/evidence declarations; hashes are not provenance authentication',
                            'No automatic label verification, statistical independence claim or performance estimate',
                            'No raw data copied; plan does not execute training or evaluation']}
    plan['plan_sha256'] = manifest_digest(plan)
    return plan
