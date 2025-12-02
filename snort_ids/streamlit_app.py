import json
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st


st.set_page_config(page_title="Snort IDS Dashboard", layout="wide")
st.title("Snort Real-Time IDS Dashboard")


def load_events(path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    rows = []
    with path.open("r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except Exception:
                continue
    df = pd.DataFrame(rows)
    if df.empty:
        return df
    # Normalize dtypes
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["priority", "sid", "gid", "rev", "src_port", "dst_port"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.sort_values("timestamp", ascending=False)
    if max_rows:
        df = df.head(max_rows)
    return df


with st.sidebar:
    st.header("Settings")
    default_path = Path("snort_ids/events.ndjson")
    events_path_str = st.text_input("Events file (NDJSON)", value=str(default_path))
    refresh = st.button("Refresh")
    max_rows = st.slider("Show last N rows", 100, 5000, 1000, step=100)

events_path = Path(events_path_str)

@st.cache_data(show_spinner=False)
def _cached_load(path_str: str, limit: int):
    return load_events(Path(path_str), max_rows=limit)

if refresh:
    _cached_load.clear()

df = _cached_load(events_path_str, max_rows)

if df.empty:
    st.info("No events loaded yet. Start Snort and the monitor.")
    st.code("""
snort -i en0 -c /opt/homebrew/etc/snort/snort.lua -A alert_json -l /opt/homebrew/var/log/snort -k none
python snort_ids/snort_monitor.py --alert-file /opt/homebrew/var/log/snort/alert_json.txt --events-out snort_ids/events.ndjson
    """)
    st.stop()

with st.container():
    st.subheader("Recent Alerts")
    # Filters
    cols = st.columns(5)
    with cols[0]:
        proto = st.multiselect("Protocol", sorted([p for p in df.get("proto", pd.Series()).dropna().unique()]))
    with cols[1]:
        priorities = st.multiselect("Priority", sorted([int(p) for p in df.get("priority", pd.Series()).dropna().unique()]))
    with cols[2]:
        src_ip = st.text_input("Source IP contains")
    with cols[3]:
        dst_ip = st.text_input("Dest IP contains")
    with cols[4]:
        search = st.text_input("Message contains")

    fdf = df.copy()
    if proto:
        fdf = fdf[fdf["proto"].isin(proto)]
    if priorities:
        fdf = fdf[fdf["priority"].isin(priorities)]
    if src_ip:
        fdf = fdf[fdf["src_ip"].astype(str).str.contains(src_ip, na=False)]
    if dst_ip:
        fdf = fdf[fdf["dst_ip"].astype(str).str.contains(dst_ip, na=False)]
    if search:
        fdf = fdf[fdf["msg"].astype(str).str.contains(search, case=False, na=False)]

    st.dataframe(fdf[[c for c in ["timestamp","priority","proto","src_ip","src_port","dst_ip","dst_port","msg"] if c in fdf.columns]], use_container_width=True, height=420)

with st.container():
    st.subheader("Trends")
    if "timestamp" in df.columns:
        ts = df.dropna(subset=["timestamp"]).set_index("timestamp")
        per_min = ts.resample("1min").size().rename("alerts_per_minute").to_frame()
        st.line_chart(per_min, height=220)
    cols = st.columns(2)
    with cols[0]:
        if "src_ip" in df.columns:
            top_src = df["src_ip"].value_counts().head(10)
            st.bar_chart(top_src)
    with cols[1]:
        if "dst_ip" in df.columns:
            top_dst = df["dst_ip"].value_counts().head(10)
            st.bar_chart(top_dst)
