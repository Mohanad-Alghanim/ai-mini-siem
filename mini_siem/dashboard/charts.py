"""Plotly figures built only from queried records and aggregate counts."""

import pandas as pd
import plotly.express as px


COLORS = {"Normal": "#35c9a5", "Anomaly": "#ff6b75"}


def prediction_distribution(kpis):
    data = pd.DataFrame({"Classification": ["Normal", "Anomaly"],
                         "Predictions": [kpis["Normal Predictions"], kpis["Anomaly Predictions"]]})
    return px.pie(data, names="Classification", values="Predictions", hole=0.65,
                  color="Classification", color_discrete_map=COLORS)


def alerts_by_source(groups):
    return px.bar(groups, x="Batch ID", y="Alerts", color="Model ID", barmode="group",
                  title="Alerts by batch and model")


def score_distribution(scores):
    figure = px.histogram(scores, x="AnomalyScore", color="AnomalyStatus", barmode="overlay",
                          color_discrete_map=COLORS, nbins=20, title="Stored decision scores")
    figure.add_vline(x=0, line_dash="dash", line_color="#ffcb6b")
    return figure


def processing_counts(dates):
    figure = px.bar(dates, x="Processing date (UTC)", y="Predictions",
                    title="Predictions by processing date (UTC)", color_discrete_sequence=["#68a8ff"])
    figure.update_xaxes(type="category")
    return figure


def risk_distribution(records):
    """Count display priorities without exposing model IDs or numerical scores."""
    order = ['High', 'Medium', 'Low']
    counts = records['Risk Level'].value_counts().reindex(order, fill_value=0)
    return px.bar(x=order, y=counts.values, labels={'x':'Risk Level', 'y':'Records'},
                  color=order, color_discrete_map={'High':'#ff6b75','Medium':'#ffcb6b','Low':'#35c9a5'},
                  title='Prediction review priority')
