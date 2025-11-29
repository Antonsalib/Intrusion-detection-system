import io
import os
import json
from pathlib import Path
from typing import Optional, Tuple

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

# Reduce noisy logs from TF/Abseil/gRPC before importing TF
os.environ.setdefault("TF_CPP_MIN_LOG_LEVEL", "2")
os.environ.setdefault("GLOG_minloglevel", "2")
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

# Optional heavy deps: available in existing venv (ids_env)
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import tensorflow as tf
from tensorflow.keras import Sequential
from tensorflow.keras.layers import Dense

# Suppress TF python logger noise
tf.get_logger().setLevel('ERROR')


st.set_page_config(page_title="Unified IDS Dashboard", layout="wide")
st.title("Unified IDS: KDD99 ML + Snort Live")


# --------------------
# Shared helpers
# --------------------
def load_ndjson(path: Path, max_rows: Optional[int] = None) -> pd.DataFrame:
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
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    for col in ["priority", "sid", "gid", "rev", "src_port", "dst_port"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.sort_values("timestamp", ascending=False)
    if max_rows:
        df = df.head(max_rows)
    return df


# --------------------
# Tab: KDD99 ML
# --------------------
def kdd_default_path() -> Path:
    # Prefer dataset in repo venv folder, then current dir
    candidates = [
        Path("ids_env/kddcup.data_10_percent.gz"),
        Path("kddcup.data_10_percent.gz"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


@st.cache_data(show_spinner=False)
def kdd_load(path_str: str) -> pd.DataFrame:
    p = Path(path_str)
    df = pd.read_csv(p, header=None, compression="gzip")
    columns = ['duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
               'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
               'root_shell','su_attempted','num_root','num_file_creations','num_shells',
               'num_access_files','num_outbound_cmds','is_host_login','is_guest_login',
               'count','srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
               'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count','dst_host_srv_count',
               'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
               'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
               'dst_host_rerror_rate','dst_host_srv_rerror_rate','label']
    df.columns = columns
    return df


@st.cache_data(show_spinner=False)
def kdd_preprocess(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, StandardScaler]:
    df = df.copy()
    for col in ['protocol_type', 'service', 'flag']:
        enc = LabelEncoder()
        df[col] = enc.fit_transform(df[col])
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal.' else 1)
    X = df.drop('label', axis=1)
    y = df['label']
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)
    return X_train, X_test, y_train.values, y_test.values, scaler


@st.cache_resource(show_spinner=False)
def kdd_train_model(X_train: np.ndarray, y_train: np.ndarray) -> Sequential:
    model = Sequential([
        Dense(32, activation='relu', input_shape=(X_train.shape[1],)),
        Dense(16, activation='relu'),
        Dense(1, activation='sigmoid')
    ])
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    model.fit(X_train, y_train, epochs=5, batch_size=64, verbose=0)
    return model


def render_kdd_tab():
    st.subheader("KDD99 Machine Learning IDS")
    ds_path = st.text_input("KDD99 gzip file", value=str(kdd_default_path()))
    go = st.button("Load & Train", type="primary")

    if not go:
        st.info("Set dataset path and click Load & Train.")
        return

    with st.spinner("Loading dataset..."):
        df = kdd_load(ds_path)
        st.write("Dataset:", df.shape)

    with st.spinner("Preprocessing..."):
        X_train, X_test, y_train, y_test, _ = kdd_preprocess(df)

    with st.spinner("Training model..."):
        model = kdd_train_model(X_train, y_train)

    # Predict
    threshold = st.slider("Decision threshold", 0.05, 0.95, 0.5, 0.05)
    y_prob = model.predict(X_test, verbose=0).ravel()
    y_pred = (y_prob > threshold).astype(int)
    acc = accuracy_score(y_test, y_pred)

    st.metric("Accuracy", f"{acc:.3f}")

    # Classification report
    report = classification_report(y_test, y_pred, output_dict=True)
    st.subheader("Classification Report")
    st.dataframe(pd.DataFrame(report).transpose())

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(4,4))
    im = ax.imshow(cm, cmap=plt.cm.Blues)
    ax.set_title("Confusion Matrix")
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    for (i, j), v in np.ndenumerate(cm):
        ax.text(j, i, int(v), ha='center', va='center', color='black')
    st.pyplot(fig)

    # Top 50 predictions table
    st.subheader("Top 50 Predictions (with probabilities)")
    results = pd.DataFrame({
        "Actual": y_test,
        "Predicted": y_pred,
        "Probability": y_prob,
    })
    st.dataframe(results.head(50))
    csv = results.to_csv(index=False).encode("utf-8")
    st.download_button("Download predictions CSV", data=csv, file_name="kdd_predictions.csv", mime="text/csv")


# --------------------
# Tab: Snort Live
# --------------------
def render_snort_tab():
    st.subheader("Snort Real-Time Alerts")
    default_events = Path("snort_ids/events.ndjson")
    events_path = st.text_input("Events NDJSON path", value=str(default_events))
    max_rows = st.slider("Show last N rows", 100, 5000, 1000, step=100)
    refresh = st.button("Refresh events")

    @st.cache_data(show_spinner=False)
    def _cached(path_str: str, limit: int):
        return load_ndjson(Path(path_str), max_rows=limit)

    if refresh:
        _cached.clear()

    df = _cached(events_path, max_rows)
    if df.empty:
        st.info("No events yet. Start Snort and the monitor.")
        st.code(
            """
snort -i en0 -c /opt/homebrew/etc/snort/snort.lua -A alert_json -l /opt/homebrew/var/log/snort -k none
python snort_ids/snort_monitor.py --alert-file /opt/homebrew/var/log/snort/alert_json.txt --events-out snort_ids/events.ndjson
            """
        )
        return

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

    st.dataframe(
        fdf[[c for c in ["timestamp","priority","proto","src_ip","src_port","dst_ip","dst_port","msg"] if c in fdf.columns]],
        use_container_width=True,
        height=420,
    )

    # Trends
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


tab1, tab2 = st.tabs(["KDD99 ML", "Snort Live"])
with tab1:
    render_kdd_tab()
with tab2:
    render_snort_tab()
