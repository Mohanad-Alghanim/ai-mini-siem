"""Minimum integration acceptance using synthetic data and an ephemeral test model."""

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from mini_siem.dashboard.events import historical_events, lab_review
from mini_siem.dashboard.queries import DashboardDataError, read_snapshot
from mini_siem.demo import prepare_demo
from mini_siem.evidence_review import CLASSES, VERSION
from mini_siem.ml.model import save_model, train_model


@pytest.fixture
def assets(tmp_path):
    # Testing only: no artifact or example dataset is shipped or used in the UI.
    frame=pd.DataFrame([{'SourceIP':f'192.0.2.{i+1}', 'EventCount':i+1,
                         'UniqueEventTypes':1+i%4,'FailedAuthCount':i,'InvalidUserCount':i%3,
                         'FailedAuthRate':i/(i+1)} for i in range(30)])
    baseline=tmp_path/'baseline.csv'; frame.to_csv(baseline,index=False)
    model=tmp_path/'trusted.joblib'; save_model(train_model(frame),model)
    historical=tmp_path/'historical.csv'
    pd.DataFrame([{'LineId':str(i+1),'Date':'Jun','Day':'1','Time':'12:00:00','Component':'sshd','Pid':'123',
                   'Content':'Failed password for lab from 192.0.2.1 port 22 ssh2','EventId':'E1','EventTemplate':'synthetic'} for i in range(3)]).to_csv(historical,index=False)
    args=(tmp_path/'demo.db',historical,baseline,model,
          hashlib.sha256(baseline.read_bytes()).hexdigest(),hashlib.sha256(model.read_bytes()).hexdigest())
    return args


def test_demo_full_path_without_training_and_dashboard_pages(assets,monkeypatch):
    before={p:p.read_bytes() for p in assets[1:4]}
    with patch('sklearn.ensemble.IsolationForest.fit',side_effect=AssertionError('demo must not train')):
        result=prepare_demo(*assets,trusted=True,original_baseline=True)
    assert result['predictions']==30 and result['Normal']+result['Anomaly']==30
    assert result['alerts']==result['Anomaly'] and result['Anomaly']>0
    assert result['historical_events']==3 and not result['new_event_feature_inference_allowed']
    assert all(p.read_bytes()==content for p,content in before.items())
    data=read_snapshot(assets[0]); assert data['kpis']['Total Predictions']==30
    assert len(historical_events(assets[0]))==3
    assert historical_events(assets[0],batch="' OR 1=1 --").empty
    assert historical_events(assets[0],source_ip='%').empty
    db_before=assets[0].read_bytes()
    monkeypatch.setenv('MINI_SIEM_DATABASE',str(assets[0]))
    app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'mini_siem/dashboard/app.py'),default_timeout=20).run()
    for page in ('Overview','Security Events','Predictions','Alerts','Data Sources / System Information'):
        app.sidebar.radio[0].set_value(page).run()
        assert not app.exception
    assert assets[0].read_bytes()==db_before
    with pytest.raises(ValueError): prepare_demo(*assets,trusted=True,original_baseline=True)
    assert assets[0].read_bytes()==db_before


@pytest.mark.parametrize('failure',['hash','trust','original','inference-error'])
def test_demo_refuses_unknown_inputs_and_never_publishes_partial_database(assets,failure):
    args=list(assets); trusted=True; original=True
    if failure=='hash': args[4]='0'*64
    if failure=='trust': trusted=False
    if failure=='original': original=False
    with patch('mini_siem.demo.ingest_features',side_effect=ValueError('model unavailable')):
        with pytest.raises(ValueError): prepare_demo(*args,trusted=trusted,original_baseline=original)
    assert not assets[0].exists()


def test_sanitized_lab_review_dashboard_separate_from_ai(tmp_path,assets,monkeypatch):
    prepare_demo(*assets,trusted=True,original_baseline=True)
    report={'review_version':VERSION,'training_allowed':False,'inference_allowed':False,'event_labels_assigned':False,
            'quality':{'total_records':2,'supported_records':1,'unsupported_records':1,'records_with_source':1},
            'event_evidence':[{'event_ref':'a'*64,'category':CLASSES[0]},{'event_ref':'b'*64,'category':CLASSES[-1]}],
            'evidence_counts':{c:int(c in (CLASSES[0],CLASSES[-1])) for c in CLASSES},
            'correlation_summary':{'verified_assignments':0},'experiment_correlations':[{'correlation_confidence':'unresolved'}]}
    path=tmp_path/'review.json'; path.write_text(json.dumps(report)); original=path.read_bytes()
    assert lab_review(path)['counts']['Records']==2
    monkeypatch.setenv('MINI_SIEM_DATABASE',str(assets[0])); monkeypatch.setenv('MINI_SIEM_LAB_REVIEW',str(path))
    with patch('mini_siem.ml.model.predict_records',side_effect=AssertionError('UI must not infer')):
        app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'mini_siem/dashboard/app.py'),default_timeout=20).run()
        app.sidebar.radio[0].set_value('Security Events').run()
        assert not app.exception
        assert any(metric.label=='Records' and metric.value=='2' for metric in app.metric)
    assert path.read_bytes()==original
    report['training_allowed']=True; path.write_text(json.dumps(report))
    with pytest.raises(DashboardDataError): lab_review(path)
