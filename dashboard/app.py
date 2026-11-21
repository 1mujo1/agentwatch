"""AgentWatch dashboard.

Run: streamlit run dashboard/app.py --server.address 127.0.0.1
"""
import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

LOGS = Path(__file__).resolve().parent.parent / "logs"
SEV_COLOR = {"critical": "#7f0000", "high": "#d62728", "medium": "#ff7f0e",
             "low": "#1f77b4", "info": "#7f7f7f"}
ROWS = ["ALERT", "agent", "audit", "proxy"]

st.set_page_config(page_title="AgentWatch", layout="wide")

# ---------- load what the correlator wrote ----------------------------------
alerts_file, events_file = LOGS / "alerts.json", LOGS / "events.jsonl"
if not alerts_file.exists():
    st.error("No logs/alerts.json yet. Run: python3 correlator/correlator.py")
    st.stop()
report = json.loads(alerts_file.read_text())
events = [json.loads(l) for l in events_file.read_text().splitlines() if l.strip()] \
    if events_file.exists() else []
runs = report["runs"]

# ---------- sidebar: pick a run, overall accuracy ---------------------------
st.sidebar.title("AgentWatch")
labels = {f"{r['scenario']} · {r['start'][11:19]}": r for r in runs}
run = labels[st.sidebar.radio("Run", list(labels))]
labelled = [r for r in runs if r["correct"] is not None]
if labelled:
    st.sidebar.metric("Correct verdicts", f"{sum(r['correct'] for r in labelled)}/{len(labelled)}")
st.sidebar.caption(f"Correlated at {report['generated']}")

# ---------- verdict ---------------------------------------------------------
st.title("AgentWatch")
st.caption("What the agent was asked to do, compared with what the kernel and the network saw.")

color = "#d62728" if run["verdict"] == "MISBEHAVED" else "#2ca02c"
# safe: run['verdict'] is always one of two fixed words produced by the correlator
st.markdown(f"<div style='background:{color};color:white;padding:1rem;border-radius:.5rem;"
            f"text-align:center;font-size:2.6rem;font-weight:700'>{run['verdict']}</div>",
            unsafe_allow_html=True)

st.write("")
st.text(f"Task: {run['task']}")      # st.text = shown as plain text, never as HTML
c1, c2, c3, c4 = st.columns(4)
c1.metric("Ground truth", run["expected"])
c2.metric("Risk score", run["risk"])
c3.metric("Alerts", len(run["alerts"]))
c4.metric("Mode", run["mode"])
if run["correct"] is True:
    st.success("The verdict matches the scenario's ground-truth label.")
elif run["correct"] is False:
    st.error("The verdict does NOT match the ground-truth label.")
else:
    st.info("Real agent run: no ground-truth label.")

# ---------- timeline --------------------------------------------------------
st.subheader("Timeline")
ev = pd.DataFrame([e for e in events if e["run_id"] == run["run_id"]])
if ev.empty:
    st.warning("No events for this run.")
else:
    ev["time"] = pd.to_datetime(ev["time"])
    fig = px.scatter(ev, x="time", y="source", color="kind", hover_data={"detail": True, "source": False},
                     category_orders={"source": ROWS}, height=380)
    fig.update_traces(marker_size=11)
    if run["alerts"]:
        fig.add_scatter(
            x=pd.to_datetime([a["first_seen"] for a in run["alerts"]]),
            y=["ALERT"] * len(run["alerts"]), mode="markers", name="alerts",
            marker=dict(symbol="x", size=16, color=[SEV_COLOR[a["severity"]] for a in run["alerts"]]),
            text=[f"{a['severity'].upper()}: {a['rule']}" for a in run["alerts"]],
            hovertemplate="%{text}<extra></extra>")
    fig.update_yaxes(categoryorder="array", categoryarray=ROWS[::-1], title=None)
    st.plotly_chart(fig, width="stretch")

# ---------- alerts ----------------------------------------------------------
st.subheader("Alerts")
if not run["alerts"]:
    st.success("No alerts in this run.")
else:
    st.dataframe(pd.DataFrame([{
        "Severity": a["severity"].upper(), "Rule": a["rule"], "Tags": ", ".join(a["tags"]),
        "Count": a["count"], "First seen": a["first_seen"][11:23], "Evidence": a["evidence"][0],
    } for a in run["alerts"]]), hide_index=True, width="stretch")
    for a in run["alerts"]:
        with st.expander(f"{a['severity'].upper()} · {a['rule']} · {', '.join(a['tags'])}"):
            st.text(a["description"])
            for line in a["evidence"]:
                st.code(line, language=None)   # code block = plain text, safe for agent-controlled data

with st.expander("All events in this run"):
    if not ev.empty:
        st.dataframe(ev[["time", "source", "kind", "detail"]], hide_index=True, width="stretch")

# ---------- coverage across all runs ----------------------------------------
st.subheader("Coverage: AW-* behaviours")
coverage = []
for rule in report["rules"]:
    fired = [r["scenario"] for r in runs if any(a["rule"] == rule["name"] for a in r["alerts"])]
    coverage.append({"Tags": ", ".join(rule["tags"]), "Rule": rule["name"],
                     "Severity": rule["severity"],
                     "Fired in": ", ".join(sorted(set(fired))) or "-",
                     "Status": "detected" if fired else "not tested yet"})
st.dataframe(pd.DataFrame(coverage), hide_index=True, width="stretch")
