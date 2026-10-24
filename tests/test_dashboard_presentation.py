"""Focused display/filter checks with synthetic records; no private Kali evidence."""

from datetime import date
import sqlite3
from unittest.mock import patch

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

from mini_siem.dashboard.events import historical_events
from mini_siem.dashboard.presentation import (
    ALERT_NAME, alert_table, event_table, filter_table, format_timestamp,
    prediction_table, risk_level,
)
from mini_siem.dashboard.queries import read_snapshot
from mini_siem.storage.sqlite import SCORE_CONVENTION, initialize_database


@pytest.mark.parametrize('value,expected',[
    ('2026-10-24T19:50:23+03:00','2026-10-24 16:50:23'),
    ('2026-10-24T00:10:00+03:00','2026-10-23 21:10:00'),
    ('2026-10-24T16:50:23.123456Z','2026-10-24 16:50:23'),
    ('2026-10-24T16:50:23','Unknown'),
    ('Jun 1 12:00:00','Unknown'),(None,'Unknown'),
])
def test_timestamp_display_uses_actual_utc_only(value,expected):
    assert format_timestamp(value)==expected


@pytest.mark.parametrize('score,expected',[(-.10001,'High'),(-.1,'Medium'),(-.00001,'Medium'),(0,'Low'),(.5,'Low')])
def test_transparent_risk_boundaries(score,expected):
    assert risk_level(score)==expected


def test_display_filters_combine_and_retain_original_scores():
    source=pd.DataFrame({'SourceIP':['192.0.2.1','192.0.2.2','192.0.2.1'],
                         'AnomalyStatus':['Anomaly','Anomaly','Normal'], 'AnomalyScore':[-.2,-.05,.1],
                         'Processing Timestamp (UTC)':['2026-10-24T01:00:00+03:00','2026-10-24T10:00:00Z',None]})
    original=source.copy(deep=True); displayed=prediction_table(source)
    chosen=filter_table(displayed,source_ip='192.0.2.',risk='High',status='Anomaly',dates=(date(2026,10,23),))
    assert chosen['Source IP'].tolist()==['192.0.2.1']
    assert filter_table(displayed,source_ip='192.0.2.2',risk='High').empty
    assert len(filter_table(displayed,dates=(date(2026,10,23),date(2026,10,24))))==2
    assert filter_table(displayed,source_ip='.*').empty  # literal, never regex
    assert not {'Prediction ID','Model ID','Batch ID','AnomalyScore'} & set(displayed)
    pd.testing.assert_frame_equal(source,original)


def test_alert_name_description_creation_time_and_literal_search():
    source=pd.DataFrame({'SourceIP':['192.0.2.1'],'Anomaly Score':[-.05],
                         'Alert Created (UTC)':['2026-10-24T00:00:00+03:00'],
                         'Processing Timestamp (UTC)':['2026-10-22T00:00:00Z']})
    displayed=alert_table(source)
    assert displayed.iloc[0]['Alert Name']==ALERT_NAME
    assert displayed.iloc[0]['Timestamp (UTC)']=='2026-10-23 21:00:00'
    assert displayed.iloc[0]['Risk Level']=='Medium'
    assert 'Not a confirmed attack' in displayed.iloc[0]['Description']
    assert len(filter_table(displayed,text='authentication',text_column='Alert Name',risk='Medium'))==1
    assert filter_table(displayed,text='.*',text_column='Alert Name').empty
    assert filter_table(displayed,dates=(date(2026,10,22),)).empty


def test_event_primary_keys_preserved_not_renumbered_or_displayed(tmp_path):
    path=tmp_path/'events.db'; initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO ingestion_batches VALUES ('events','hash',2,'2026-10-24T00:00:00Z')")
        for source_record,(identifier,kind) in enumerate(((7,'id:E24'),(93,'id:E7')),1):
            connection.execute('INSERT INTO security_events VALUES (?,?,?,?,?,?,?)',
                               (identifier,'events',source_record,'192.0.2.1',kind,None,'2026-10-24T00:00:00Z'))
    before=path.read_bytes(); queried=historical_events(path); view=event_table(queried)
    assert queried['Event ID'].tolist()==[7,93]
    assert queried['Source Record'].tolist()==[1,2]
    assert 'Event ID' not in view and 'Batch ID' not in view
    assert view['Event Type'].tolist()==['id:E24','id:E7']
    assert view['Event Timestamp (UTC)'].tolist()==['Unknown','Unknown']
    assert view['Event Status'].tolist()==['Unknown','Unknown']
    assert len(filter_table(view,text='E24',text_column='Event Type',dates=(date(2026,10,24),),timestamp='Ingested (UTC)'))==1
    assert filter_table(view,dates=(date(2026,10,24),),timestamp='Event Timestamp (UTC)').empty
    assert path.read_bytes()==before


def test_dashboard_ui_combined_filters_and_no_technical_columns(tmp_path,monkeypatch):
    path=tmp_path/'records.db'; initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO ingestion_batches VALUES ('private-batch','hash',2,'2026-10-24T00:00:00Z')")
        for n,score in enumerate((-.2,-.05),1):
            connection.execute('INSERT INTO predictions VALUES (?,?,?,?,?,?,?,?,?,?)',
                (n,'private-batch','private-model',n,f'192.0.2.{n}',-1,'Anomaly',score,SCORE_CONVENTION,'2026-10-24T00:00:00Z'))
            connection.execute('INSERT INTO alerts VALUES (?,?,?,?)',(n,n,'SSH behavioral anomaly','2026-10-24T00:00:00Z'))
    before=path.read_bytes(); monkeypatch.setenv('MINI_SIEM_DATABASE',str(path))
    # UI never opens any private capture. An optional sanitized report is not configured.
    monkeypatch.delenv('MINI_SIEM_LAB_REVIEW',raising=False)
    with patch('mini_siem.ml.model.predict_records',side_effect=AssertionError('no inference')):
        from pathlib import Path
        app=AppTest.from_file(str(Path(__file__).resolve().parents[1]/'mini_siem/dashboard/app.py'),default_timeout=15).run()
        assert not app.exception
        app.sidebar.radio[0].set_value('Alerts').run()
        app.text_input(key='alerts-ip').set_value('192.0.2.1')
        app.text_input(key='alerts-text').set_value('authentication')
        app.selectbox(key='alerts-risk').set_value('High')
        app.date_input(key='alerts-dates').set_value((date(2026,10,24),date(2026,10,24))).run()
        assert not app.exception and len(app.dataframe[0].value)==1
        assert list(app.dataframe[0].value)==['Alert Name','Source IP','Risk Level','Timestamp (UTC)','Description']
        assert app.dataframe[0].value.iloc[0]['Timestamp (UTC)']=='2026-10-24 00:00:00'
        assert not app.sidebar.text_input
        assert all('private-' not in repr(widget.value) for widget in app.selectbox)
    assert path.read_bytes()==before
