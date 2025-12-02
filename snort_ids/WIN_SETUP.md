Windows setup (PowerShell)
===========================

Quick steps I used to get this project running on Windows (PowerShell).

1) Create / activate the project virtual environment

```powershell
cd C:\Users\Admin\Documents\Intrusion-detection-system
# Create venv (if you haven't already)
python -m venv .venv
# If activation is blocked by policy, run once as user:
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force
# Activate the venv
.\.venv\Scripts\Activate.ps1
```

2) Upgrade packaging tools and install requirements

```powershell
# Upgrade pip/setuptools/wheel
python -m pip install --upgrade pip setuptools wheel
# Install repo requirements (Streamlit, pandas, rich, pyyaml)
python -m pip install -r .\snort_ids\requirements.txt
```

3) Install TensorFlow (CPU) for the KDD99 ML tab

```powershell
# Recommended: CPU-only
python -m pip install tensorflow-cpu
# Verify
python -c "import tensorflow as tf; print(tf.__version__)"
```

Notes: if you hit compatibility errors on Python 3.12, create a venv with Python 3.11 and install TF there:

```powershell
# Example using python3.11 (replace path if needed)
python3.11 -m venv .venv311
.\.venv311\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r .\snort_ids\requirements.txt
python -m pip install tensorflow-cpu
```

4) Install extra Python packages used by the unified dashboard

```powershell
python -m pip install matplotlib scikit-learn
```

5) Run the unified Streamlit dashboard

```powershell
# From repo root with venv activated
streamlit run .\snort_ids\unified_dashboard.py
```

6) Run the snort monitor (example using the included `events.ndjson` as input)

```powershell
# This reads the packaged sample events and writes a parsed copy
python .\.venv\Scripts\python.exe .\snort_ids\snort_monitor.py --alert-file .\snort_ids\events.ndjson --events-out .\snort_ids\events_copy.ndjson --from-start
# Or run with your real Snort alert file
python .\.venv\Scripts\python.exe .\snort_ids\snort_monitor.py --alert-file C:\path\to\alert_json.txt --events-out .\snort_ids\events.ndjson
```

Troubleshooting
---------------
- If `streamlit` is not found after activating the venv, ensure `python -m pip install -r .\snort_ids\requirements.txt` succeeded and that you're using the same venv.
- If TensorFlow installation fails, post the full pip error and your Python version; on Windows 3.11 is the most compatible.
- If Snort is not available on Windows, you can still use the UI with the provided `snort_ids/events.ndjson` sample file.

Contact me if you want me to add these steps to the main `README.md` instead.
