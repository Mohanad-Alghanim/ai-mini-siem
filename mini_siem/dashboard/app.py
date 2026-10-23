"""Local-only Streamlit application; launch from the repository root."""

import os
from datetime import datetime, timezone

import streamlit as st

from mini_siem.dashboard.charts import (
    alerts_by_source, prediction_distribution, processing_counts, score_distribution,
)
from mini_siem.dashboard.queries import DashboardDataError, read_snapshot


st.set_page_config(page_title="Mini SIEM | SSH Operations", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.title("SSH Security Operations")
st.caption("AI-Powered Mini SIEM · Local proof of concept")
st.warning("Local use only. Do not expose Streamlit publicly without authentication and additional security controls.")

with st.sidebar:
    st.header("Mini SIEM")
    page = st.radio("Navigation", ["Overview", "Alerts", "Predictions", "Data Sources / System Information"])
    database = st.text_input("SQLite database", value=os.environ.get("MINI_SIEM_DATABASE", "data/mini-siem.db"), type="password", help="Existing TASK-004 database. Read-only access; no database is created.")
    st.button("Refresh", help="Rerun the page and read a fresh database snapshot.")
    st.caption("Refresh rereads stored data. This dashboard does not ingest logs or run model inference.")

try:
    snapshot = read_snapshot(database)
except DashboardDataError as error:
    st.error(str(error))
    st.info("Select an existing initialized TASK-004 database. Initialize or ingest with the backend CLI outside the dashboard.")
    st.stop()

st.caption(f"Snapshot read at {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} · Read-only")
st.info("Anomaly means unusual behavior, not a confirmed attack. The current model is a 30-record proof of concept; independent labeled ground truth is required for accuracy metrics.")


def table_filters(key, include_status=False):
    options = snapshot["options"]
    columns = st.columns(3 if include_status else 2)
    with columns[0]:
        batch = st.selectbox("Batch", [None, *options.batch_id.unique()], format_func=lambda value: "All batches" if value is None else value, key=f"{key}-batch")
    with columns[1]:
        model = st.selectbox("Model", [None, *options.model_id.unique()], format_func=lambda value: "All models" if value is None else value, key=f"{key}-model")
    status = None
    if include_status:
        with columns[2]:
            status = st.selectbox("Status", [None, "Normal", "Anomaly"], format_func=lambda value: value or "All statuses", key=f"{key}-status")
    search = st.text_input("Search SourceIP", key=f"{key}-ip", help="Literal substring match; addresses are displayed only in operational tables.")
    try:
        return read_snapshot(database, batch=batch, model=model, status=status, source_ip=search)
    except DashboardDataError as error:
        st.error(str(error))
        st.stop()


if page == "Overview":
    st.subheader("Database overview")
    st.caption("All stored batches and model versions; counts represent records, not unique IPs or confirmed attacks.")
    kpis = snapshot["kpis"]
    for offset in (0, 3):
        for column, (label, count) in zip(st.columns(3), list(kpis.items())[offset:offset + 3]):
            column.metric(label, count)
    if kpis["Raw Events Available"] == 0:
        st.caption("No raw events are stored. This does not mean no SSH activity occurred; feature batches contain aggregated observations.")
    if not kpis["Total Predictions"]:
        st.info("No predictions stored yet. Ingest a feature batch with the backend CLI, then select Refresh.")
    else:
        left, right = st.columns(2)
        with left:
            st.plotly_chart(prediction_distribution(kpis), use_container_width=True)
        with right:
            if snapshot["alert_groups"].empty:
                st.info("No alerts stored.")
            else:
                st.plotly_chart(alerts_by_source(snapshot["alert_groups"]), use_container_width=True)
        models = snapshot["scores"]["Model ID"].unique().tolist()
        selected_model = st.selectbox("Score distribution model", models)
        st.caption("Scores are shown for one artifact at a time; independently trained models may have different score scales and thresholds.")
        scores = snapshot["scores"]
        st.plotly_chart(score_distribution(scores[scores["Model ID"] == selected_model]), use_container_width=True)
        st.caption("Scikit-learn decision_function: lower is more unusual; scores below zero are Anomaly, zero or above are Normal. Scores are not attack probabilities.")
        if snapshot["dates"].empty:
            st.info("Processing-date chart unavailable: no timezone-aware processing timestamps could be read.")
        else:
            st.plotly_chart(processing_counts(snapshot["dates"]), use_container_width=True)
            if len(snapshot["dates"]) == 1:
                st.caption("Only one processing date is recorded; this does not establish a historical trend.")
        if snapshot["skipped_timestamps"]:
            st.warning(f"{snapshot['skipped_timestamps']} records have invalid or timezone-ambiguous processing timestamps and were excluded from the date chart.")
elif page == "Alerts":
    st.subheader("Anomaly alerts")
    records = table_filters("alerts")["alerts"]
    if records.empty:
        st.info("No stored alerts match these filters.")
    else:
        st.caption(f"{len(records)} stored alerts · Processing time is not original event time.")
        st.dataframe(records, hide_index=True, use_container_width=True)
elif page == "Predictions":
    st.subheader("AI prediction records")
    records = table_filters("predictions", include_status=True)["predictions"]
    if records.empty:
        st.info("No stored predictions match these filters.")
    else:
        st.caption(f"{len(records)} prediction records · Reprocessing with another model creates a separate history.")
        st.dataframe(records, hide_index=True, use_container_width=True)
else:
    st.subheader("Data sources and system information")
    st.write("Source: existing local SQLite backend, schema version 1. Database paths are not displayed in reports or errors.")
    st.write("Tables: ingestion_batches, security_events, predictions, alerts.")
    st.write("Model IDs are artifact SHA-256 identifiers. The dashboard neither loads model files nor retrains models.")
    st.write("Processing timestamps are generated in UTC. Original event times and timestamp years are never inferred.")
    st.write("No raw log contents are queried or displayed. Zero raw events means none are stored, not that no activity occurred.")
    st.write("Data changes only when the separate backend writes it. Refresh or another widget interaction rereads the database; there is no automatic polling.")
    st.write("Prediction metrics and charts summarize stored records, including repeated batches/model versions. No accuracy, precision, recall, or F1 is reported.")
    st.write("Stored score conventions:")
    for convention in snapshot["score_conventions"]:
        st.text(convention)
    if not snapshot["score_conventions"]:
        st.caption("No model score conventions available until predictions are stored.")
