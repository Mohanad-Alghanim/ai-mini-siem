"""Simple local, read-only SOC dashboard. Configure paths outside the UI."""

import os
from datetime import datetime, timezone

import streamlit as st

from mini_siem.dashboard.charts import prediction_distribution, processing_counts, risk_distribution
from mini_siem.dashboard.events import historical_events, lab_review
from mini_siem.dashboard.presentation import (
    RISK_LEVELS, RISK_NOTE, alert_table, event_table, filter_table, format_timestamp, prediction_table,
)
from mini_siem.dashboard.queries import DashboardDataError, read_snapshot

st.set_page_config(page_title='Mini SIEM | SSH Operations', page_icon='🛡️', layout='wide', initial_sidebar_state='expanded')
st.title('SSH Security Operations')
st.caption('Local proof of concept · Historical/offline AI inference')
st.warning('Local use only. Anomaly means unusual behavior, not a confirmed attack. Do not expose this dashboard publicly.')

with st.sidebar:
    st.header('Mini SIEM')
    page = st.radio('Navigation', ['Overview', 'Security Events', 'Alerts', 'Predictions'])
    st.button('Refresh', help='Reread stored data. No automatic monitoring or inference.')
    st.caption('All displayed times use UTC. Missing times are Unknown.')

# No paths, batch/model selectors or model artifacts are exposed in the UI.
database = os.environ.get('MINI_SIEM_DATABASE', 'data/mini-siem.db')
try:
    snapshot = read_snapshot(database)
except DashboardDataError:
    st.error('Database unavailable or incompatible. Ask the operator to check the configured database and access permissions.')
    st.stop()

st.caption(f"Read at {format_timestamp(datetime.now(timezone.utc))} UTC · Read-only")
with st.expander('How to interpret these results'):
    st.write('The model is a 30-record educational proof of concept. Stored predictions are not verified attack labels or real-time detection.')
    st.write(RISK_NOTE)
    st.write('Legacy model inputs must retain their original compatible feature semantics. Newly extracted events and native SSH evidence are not passed to that model.')
    st.write('Timestamp columns identify processing, alert creation, ingestion or original event time. Unknown original dates are never reconstructed.')


def controls(records, key, *, text_column=None, status_column=None, has_risk=False,
             timestamp='Timestamp (UTC)'):
    """Simple built-in controls, combined without SQL or storage mutations."""
    columns = st.columns(2)
    with columns[0]:
        ip = st.text_input('Search Source IP', key=f'{key}-ip')
    text = ''
    if text_column:
        with columns[1]:
            text = st.text_input(f'Search {text_column}', key=f'{key}-text')
    columns = st.columns(2)
    risk = status = None
    if has_risk:
        with columns[0]:
            risk = st.selectbox('Risk Level', [None, *RISK_LEVELS], format_func=lambda value: value or 'All levels', key=f'{key}-risk', help=RISK_NOTE)
    if status_column:
        options = sorted(records[status_column].dropna().unique())
        with columns[1]:
            status = st.selectbox(status_column, [None, *options], format_func=lambda value: value or 'All statuses', key=f'{key}-status')
    dates = st.date_input('Date range (UTC)', value=(), key=f'{key}-dates', help=f'Uses {timestamp}. Unknown timestamps are excluded only when filtering by date. A single selected date means that whole day.')
    st.caption(f'Date filter uses {timestamp}. Times unavailable in the source remain Unknown.')
    try:
        return filter_table(records, source_ip=ip, text=text, text_column=text_column, risk=risk,
                            status=status, status_column=status_column or 'Classification',
                            dates=dates, timestamp=timestamp)
    except ValueError:
        st.error('Select a start date no later than the end date.')
        return records.iloc[:0]


def show_records(records, empty):
    if records.empty:
        st.info(empty)
    else:
        st.caption(f'{len(records)} records')
        st.dataframe(records, hide_index=True, use_container_width=True)


if page == 'Overview':
    st.subheader('Stored security overview')
    kpis = snapshot['kpis']
    labels = ['Total Predictions', 'Normal Predictions', 'Anomaly Predictions', 'Total Alerts', 'Raw Events Available']
    for offset in (0, 3):
        group = labels[offset:offset+3]
        for column, label in zip(st.columns(len(group)), group):
            column.metric(label, kpis[label])
    st.caption('Counts describe stored records, not unique IPs, attacks or incidents.')
    if not kpis['Raw Events Available']:
        st.caption('No raw events are stored. This does not mean no SSH activity occurred.')
    if not kpis['Total Predictions']:
        st.info('No predictions stored yet. Ask the operator to prepare compatible historical data, then Refresh.')
    else:
        left, right = st.columns(2)
        with left:
            st.plotly_chart(prediction_distribution(kpis), use_container_width=True)
        with right:
            st.plotly_chart(risk_distribution(prediction_table(snapshot['predictions'])), use_container_width=True)
        st.caption(RISK_NOTE)
        if not snapshot['dates'].empty:
            st.plotly_chart(processing_counts(snapshot['dates']), use_container_width=True)
            st.caption('These are UTC day buckets, not original event timestamps or evidence of a live trend.')
        if snapshot['skipped_timestamps']:
            st.warning(f"{snapshot['skipped_timestamps']} unknown processing timestamps were excluded from the day chart.")
elif page == 'Security Events':
    st.subheader('Security events')
    stored, native = st.tabs(['Stored historical events', 'Native SSH evidence'])
    with stored:
        st.caption('Event Type identifies the stored event group. Event Status describes peer parsing, not an attack classification. Internal database IDs are hidden.')
        try:
            records = event_table(historical_events(database))
            date_field = st.selectbox('Filter dates by', ['Ingested (UTC)', 'Event Timestamp (UTC)'], key='events-time-field')
            selected = controls(records, 'events', text_column='Event Type', status_column='Event Status', timestamp=date_field)
            show_records(selected, 'No stored security events match these filters.')
        except DashboardDataError:
            st.error('Stored event metadata unavailable or incompatible. Ask the operator to check database integrity.')
        st.caption('Raw events have no model risk score. No Risk Level is inferred from unrelated IP predictions.')
    with native:
        review_path = os.environ.get('MINI_SIEM_LAB_REVIEW', '')
        st.caption('Separate sanitized offline review only. This screen does not read private captures, run AI or verify attack labels.')
        if not review_path:
            st.info('No sanitized native review configured. The operator may select an authorized report outside the dashboard.')
        else:
            try:
                reviewed = lab_review(review_path)
                for column, (label, count) in zip(st.columns(4), reviewed['counts'].items()):
                    column.metric(label, count)
                # Neither internal hashes nor unavailable source/time/risk values
                # are inferred from this sanitized evidence summary.
                events = reviewed['events'][['category']].rename(columns={'category':'Evidence Type'}).copy()
                events['Evidence Type'] = events['Evidence Type'].str.replace('_', ' ', regex=False)
                status = st.selectbox('Evidence Type', [None, *sorted(events['Evidence Type'].unique())], format_func=lambda value: value or 'All evidence', key='native-status')
                if status:
                    events = events[events['Evidence Type'].eq(status)]
                events['Event Timestamp (UTC)'] = 'Unknown'
                show_records(events, 'No native evidence matches this filter.')
                st.caption('Source IPs and original timestamps are not supplied by this sanitized table. No Risk Level is assigned; experiment correlation remains unresolved.')
            except DashboardDataError:
                st.error('Sanitized native review unavailable or incompatible. Ask the operator to check its configuration; keep private capture permissions unchanged.')
elif page == 'Alerts':
    st.subheader('Alerts for review')
    st.caption('Timestamps are alert creation times in UTC. Names describe unusual behavior, not a confirmed attack type.')
    selected = controls(alert_table(snapshot['alerts']), 'alerts', text_column='Alert Name', has_risk=True)
    show_records(selected, 'No stored alerts match these filters.')
else:
    st.subheader('Anomaly classifications')
    st.caption('Timestamps are prediction processing times in UTC. Scores remain unchanged in storage.')
    selected = controls(prediction_table(snapshot['predictions']), 'predictions', status_column='Classification', has_risk=True)
    show_records(selected, 'No stored predictions match these filters.')
