"""Synthetic manifests/CSV records only; no collection, attacks or model use."""

from copy import deepcopy
import hashlib
import json
from unittest.mock import patch

import pandas as pd
import pytest

from mini_siem.datasets import main
from mini_siem.evaluation.inventory import metadata_errors, readiness, validate_schema
from mini_siem.evaluation.splits import plan_splits


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def manifest(index=1):
    return {
        'inventory_schema_version': 1, 'dataset_id': f'synthetic-{index}', 'dataset_version': '1',
        'source_type':'ssh_authentication', 'acquisition_method':'synthetic test fixture', 'collection_environment':f'fixture-env-{index}',
        'record_unit':'raw_event', 'file':{'format':'csv','sha256':digest(f'file-{index}'),'record_count':2},
        'schema':{'id':'synthetic-csv-v1','parser_version':'synthetic-parser-v1','record_id_field':'id','required_columns':['id','time'],'label_field':None,'column_rules':[]},
        'timestamps':{'fields':['time'],'confidence':'independently_verified','evidence_sha256':digest(f'times-{index}')},
        'observation':{'start':f'2026-01-0{index}T00:00:00Z','end':f'2026-01-0{index}T01:00:00Z','duration_seconds':3600,'confidence':'independently_verified','evidence_sha256':digest(f'duration-{index}')},
        'aggregation':{'scope':'whole independent synthetic acquisition','window':None,'exposure':'one hour'},
        'labels':{'available':False,'source':'none','reliability':'not_available','evidence_sha256':None},
        'privacy':'sensitive',
        'provenance':{'acquisition_id':f'acq-{index}','collection_group':f'group-{index}','dependence_groups':[f'entity-{index}'],'lineage_root_sha256':[digest(f'root-{index}')],'evidence_sha256':digest(f'provenance-{index}')},
        'event_membership':{'complete':True,'identity_namespace':'synthetic-global-event-v1','event_identity_sha256':[digest(f'event-{index}-a'),digest(f'event-{index}-b')],'evidence_sha256':digest(f'membership-{index}')},
        'quality_notes':[], 'quality_review':{'status':'independently_reviewed','evidence_sha256':digest(f'review-{index}'),'unresolved_findings':[]}}


def assignment():
    return {partition:[{'dataset_id':f'synthetic-{i}','dataset_version':'1'}] for i,partition in enumerate(('train','validation','test'),1)}


def write(path, value):
    path.write_text(json.dumps(value))
    return path


@pytest.mark.parametrize('category',['ssh_authentication','network_flow','http_access_application','file_integrity','http_server_metrics_requests'])
def test_future_categories_metadata_only(category):
    value = manifest()
    value['source_type'] = category
    assert metadata_errors(value) == []
    assert readiness(value)['planning_ready']
    assert not readiness(value)['training_allowed']


@pytest.mark.parametrize('mutation',[
    lambda m:m.pop('dataset_version'),
    lambda m:m.update(extra='unknown'),
    lambda m:m['file'].update(sha256='bad'),
    lambda m:m['file'].update(record_count=True),
    lambda m:m['file'].update(record_count=-1),
    lambda m:m.update(source_type='all attacks'),
    lambda m:m['provenance'].update(dependence_groups=['duplicate','duplicate']),
    lambda m:m['event_membership']['event_identity_sha256'].append(m['event_membership']['event_identity_sha256'][0]),
    lambda m:m['observation'].update(duration_seconds=float('inf')),
])
def test_schema_invalid_values(mutation):
    value = manifest()
    mutation(value)
    assert validate_schema(value)


def test_timestamp_and_label_contradictions():
    value = manifest()
    value['labels'] = {'available':True,'source':'ai_predictions','reliability':'independently_verified','evidence_sha256':digest('labels')}
    assert metadata_errors(value)
    value = manifest()
    value['observation']['start'] = 'Jan 1 12:00:00'
    assert metadata_errors(value)
    value = manifest()
    value['observation']['duration_seconds'] = 1
    assert metadata_errors(value)


def test_incomplete_inventory_can_be_recorded_but_not_planned():
    value = manifest()
    value['provenance']['acquisition_id'] = None
    value['event_membership'] = {'complete':False,'identity_namespace':None,'event_identity_sha256':[],'evidence_sha256':None}
    value['observation'] = {'start':None,'end':None,'duration_seconds':None,'confidence':'unknown','evidence_sha256':None}
    value['timestamps'] = {'fields':[],'confidence':'partial_or_ambiguous','evidence_sha256':None}
    value['aggregation']['exposure'] = None
    result = readiness(value)
    assert result['metadata_valid'] and not result['planning_ready']
    with pytest.raises(ValueError):
        plan_splits([value,manifest(2),manifest(3)], assignment())


def test_csv_diagnostics_preserve_bytes(tmp_path):
    value = manifest()
    value['schema']['label_field'] = 'label'
    value['labels'] = {'available':True,'source':'ai_predictions','reliability':'unverified','evidence_sha256':None}
    source = tmp_path/'private.csv'
    pd.DataFrame({'id':['same','same'],'time':['Jun 1 12:00:00','2026-01-01T02:00:00Z'],'label':['prior_prediction','']}).to_csv(source,index=False)
    before = source.read_bytes()
    value['file']['sha256'] = digest('wrong')
    report = readiness(value,source)
    assert report['inspection']['duplicate_record_ids'] == 1
    assert report['inspection']['timestamp_checks']['time']['invalid_or_partial_values'] == 1
    assert report['inspection']['timestamp_checks']['time']['outside_declared_half_open_interval'] == 1
    assert report['inspection']['nonblank_label_records'] == 1
    assert not report['ground_truth_declared_verified'] and not report['planning_ready']
    assert source.read_bytes() == before
    assert 'prior_prediction' not in json.dumps(report)


def test_missing_columns_and_identifier_diagnostics(tmp_path):
    path = tmp_path/'input.csv'
    path.write_text('other\nvalue\n')
    report = readiness(manifest(),path)
    assert report['inspection']['missing_columns'] == ['id','time']
    assert report['inspection']['duplicate_record_ids'] is None


def test_group_plan_reproducible_and_whole_units():
    values = [manifest(i) for i in range(1,4)]
    plan = plan_splits(values,assignment())
    assert plan == plan_splits(list(reversed(values)),assignment())
    assert not plan['training_allowed'] and not plan['inference_allowed']
    assert plan['partitions']['test'][0]['record_count'] == 2
    assert len(plan['plan_sha256']) == 64


@pytest.mark.parametrize('overlap', ['acquisition','group','dependence','file','root','event','namespace'])
def test_cross_partition_leakage_rejected(overlap):
    values = [manifest(i) for i in range(1,4)]
    a,b=values[:2]
    if overlap == 'acquisition': b['provenance']['acquisition_id']=a['provenance']['acquisition_id']
    if overlap == 'group': b['provenance']['collection_group']=a['provenance']['collection_group']
    if overlap == 'dependence': b['provenance']['dependence_groups']=a['provenance']['dependence_groups']
    if overlap == 'file': b['file']['sha256']=a['file']['sha256']
    if overlap == 'root': b['provenance']['lineage_root_sha256']=a['provenance']['lineage_root_sha256']
    if overlap == 'event': b['event_membership']['event_identity_sha256']=a['event_membership']['event_identity_sha256']
    if overlap == 'namespace': b['event_membership']['identity_namespace']='unrelated identity recipe'
    with pytest.raises(ValueError):plan_splits(values,assignment())


def test_temporal_verified_order_and_ambiguous_times():
    values=[manifest(i) for i in range(1,4)]
    assert plan_splits(values,assignment(),'temporal')['method']=='temporal'
    values[1]['timestamps']['confidence']='partial_or_ambiguous'
    with pytest.raises(ValueError,match='Temporal'):plan_splits(values,assignment(),'temporal')
    values=[manifest(i) for i in range(1,4)]
    values[1]['observation']=deepcopy(values[0]['observation'])
    with pytest.raises(ValueError,match='overlap'):plan_splits(values,assignment(),'temporal')


@pytest.mark.parametrize('method',['random','event_random','shuffle'])
def test_random_dependent_event_splits_rejected(method):
    with pytest.raises(ValueError):plan_splits([manifest(i) for i in range(1,4)],assignment(),method)


def test_duplicate_missing_or_unassigned_dataset_rejected():
    values=[manifest(i) for i in range(1,4)]
    bad=assignment(); bad['validation']=deepcopy(bad['train'])
    with pytest.raises(ValueError):plan_splits(values,bad)
    bad=assignment(); bad['test']=[]
    with pytest.raises(ValueError):plan_splits(values,bad)
    with pytest.raises(ValueError):plan_splits(values+[manifest(4)],assignment())
    with pytest.raises(ValueError):plan_splits(values+[manifest(1)],assignment())


def test_quality_review_required():
    values=[manifest(i) for i in range(1,4)]
    values[0]['quality_review']['status']='pending'
    assert not readiness(values[0])['planning_ready']
    with pytest.raises(ValueError):plan_splits(values,assignment())


def test_register_measure_validate_readiness_and_private_inspect(tmp_path,capsys):
    value=manifest()
    value['file'].update(sha256=None,record_count=None)
    value['event_membership'].update(complete=False,identity_namespace=None,event_identity_sha256=[],evidence_sha256=None)
    source=tmp_path/'private.csv'
    pd.DataFrame({'id':['one','two'],'time':['2026-01-01T00:00:00Z','2026-01-01T00:01:00Z']}).to_csv(source,index=False)
    original=source.read_bytes()
    draft=write(tmp_path/'draft.json',value); registered=tmp_path/'inventory.json'
    with patch('sqlite3.connect',side_effect=AssertionError('No database')),patch('mini_siem.ml.model.train_model',side_effect=AssertionError('No training')),patch('mini_siem.ml.model.predict_records',side_effect=AssertionError('No inference')):
        assert main(['register','--manifest',str(draft),'--file',str(source),'--output',str(registered)])==0
        assert main(['inspect','--manifest',str(registered)])==0
        assert main(['validate','--manifest',str(registered),'--file',str(source)])==0
        assert main(['readiness','--manifest',str(registered),'--file',str(source),'--output',str(tmp_path/'readiness.json')])==0
    saved=json.loads(registered.read_text())
    assert saved['file']['sha256']==hashlib.sha256(original).hexdigest()
    assert saved['file']['record_count']==2
    assert not json.loads((tmp_path/'readiness.json').read_text())['planning_ready']
    assert source.read_bytes()==original


def test_cli_plan_and_conflict_protection(tmp_path):
    paths=[write(tmp_path/f'm{i}.json',manifest(i)) for i in range(1,4)]
    assign=write(tmp_path/'assignment.json',assignment())
    output=tmp_path/'plan.json'
    args=['plan','--assignment',str(assign),'--output',str(output)]
    for path in paths:args += ['--manifest',str(path)]
    assert main(args)==0
    before=output.read_bytes()
    assert main(args)==2
    assert output.read_bytes()==before
    args[args.index(str(output))]=str(paths[0])
    assert main(args)==2


def test_bad_json_and_malformed_csv_safe_failure(tmp_path,capsys):
    path=tmp_path/'private-name.json';path.write_text('{"private": NaN}')
    assert main(['inspect','--manifest',str(path)])==2
    assert 'private-name' not in capsys.readouterr().out
    path=write(tmp_path/'valid.json',manifest())
    source=tmp_path/'bad.csv';source.write_text('id,time\none,extra,malformed\n')
    assert main(['validate','--manifest',str(path),'--file',str(source)])==2


def test_non_csv_registration_does_not_pretend_to_parse(tmp_path):
    value=manifest();value['file']['format']='jsonl'
    path=write(tmp_path/'metadata.json',value)
    assert main(['register','--manifest',str(path),'--output',str(tmp_path/'registered.json')])==0
    assert main(['validate','--manifest',str(path),'--file',str(path)])==2


def test_metadata_draft_never_fabricates_collection_facts(tmp_path):
    path=tmp_path/'draft.json'
    assert main(['draft','--dataset-id','user-assigned-id','--version','1','--source-type','ssh_authentication','--output',str(path)])==0
    value=json.loads(path.read_text())
    assert metadata_errors(value)==[]
    assert value['file']['sha256'] is None and value['file']['record_count'] is None
    assert value['observation']['duration_seconds'] is None
    assert value['provenance']['acquisition_id'] is None
    assert not readiness(value)['planning_ready']


def test_registration_records_file_quality_issues_as_pending(tmp_path):
    value=manifest()
    value['file']['sha256']=None
    source=tmp_path/'duplicate.csv'
    source.write_text('id,time\nsame,Jun 1\nsame,Jun 1\n')
    draft=write(tmp_path/'draft.json',value)
    output=tmp_path/'registered.json'
    assert main(['register','--manifest',str(draft),'--file',str(source),'--output',str(output)])==0
    result=json.loads(output.read_text())
    assert result['quality_review']['status']=='pending'
    assert 'duplicated record identifiers' in result['quality_review']['unresolved_findings']
    assert not readiness(result)['planning_ready']


def test_obvious_unknown_provenance_cannot_enable_planning():
    value=manifest()
    value['provenance']['acquisition_id']='unknown'
    assert not readiness(value)['planning_ready']


def test_huge_numeric_values_are_rejected_cleanly():
    value=manifest()
    value['file']['record_count']=10**1000
    assert validate_schema(value)


def test_register_rejects_claimed_hash_conflict(tmp_path):
    path=write(tmp_path/'claimed.json',manifest())
    source=tmp_path/'data.csv';source.write_text('id,time\none,2026-01-01T00:00:00Z\n')
    output=tmp_path/'registered.json'
    assert main(['register','--manifest',str(path),'--file',str(source),'--output',str(output)])==2
    assert not output.exists()


def test_within_partition_duplicate_event_exports_are_rejected():
    values=[manifest(i) for i in range(1,5)]
    values[3]['event_membership']['event_identity_sha256']=deepcopy(values[0]['event_membership']['event_identity_sha256'])
    assign=assignment();assign['train'].append({'dataset_id':'synthetic-4','dataset_version':'1'})
    with pytest.raises(ValueError,match='within partition'):plan_splits(values,assign)


def test_declared_column_types_and_ranges_do_not_guess_schema(tmp_path):
    value=manifest();value['file']['sha256']=None
    value['schema']['column_rules']=[{'field':'port','type':'integer','nullable':False,'min':0,'max':65535},{'field':'peer','type':'ip','nullable':True,'min':None,'max':None}]
    source=tmp_path/'flow.csv'
    pd.DataFrame({'id':['a','b'],'time':['2026-01-01T00:00:00Z']*2,'port':['wrong',70000],'peer':['not-an-ip','']}).to_csv(source,index=False)
    result=readiness(value,source)
    checks=result['inspection']['declared_column_checks']
    assert checks['port']['invalid_type']==checks['port']['out_of_range']==1
    assert checks['peer']['invalid_type']==1
    assert not result['planning_ready']


def test_honest_partial_timestamps_do_not_become_full_dates(tmp_path):
    value=manifest();value['file']['sha256']=None
    value['timestamps']['confidence']='partial_or_ambiguous';value['timestamps']['evidence_sha256']=None
    source=tmp_path/'partial.csv';source.write_text('id,time\na,Jun 1 12:00:00\nb,Jun 1 12:00:01\n')
    result=readiness(value,source)
    assert result['inspection']['timestamp_checks']['time']['full_aware_values']==0
    assert not any('timestamp values' in finding for finding in result['inspection']['findings'])
    assert result['timestamp_confidence']=='partial_or_ambiguous'
    value['file']['sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    with pytest.raises(ValueError,match='Temporal'):plan_splits([value,manifest(2),manifest(3)],assignment(),'temporal')
