Snort-Based Real-Time IDS (macOS)

Overview

- Uses Snort 3 for packet inspection and rule-based detection.
- Python monitor tails Snort alert output and writes normalized NDJSON events.
- Streamlit dashboard visualizes real-time alerts, filters, and metrics.
  - Unified dashboard also includes an end-to-end KDD99 ML prototype.

Prerequisites (macOS)

- Homebrew installed: https://brew.sh
- Network interface name (e.g., `en0`). Find with:
  - `ifconfig | grep -E "^(en|utun|bridge)[0-9]" -A2`

Install Snort 3

- Install:
  - `brew install snort3`
- Find Homebrew prefix:
  - Apple Silicon: `/opt/homebrew`
  - Intel: `/usr/local`
- Key paths (adjust prefix if needed):
  - Config: `<prefix>/etc/snort/snort.lua`
  - Rules dir: `<prefix>/etc/snort/rules/`
  - Local rules: `<prefix>/etc/snort/rules/local.rules`
  - Log dir: `<prefix>/var/log/snort`

Enable a Test Rule

- Create or edit `local.rules` and add a simple ICMP rule:
  - `alert icmp any any -> any any (msg:"LOCAL ICMP ping"; sid:1000001; rev:1;)`

Run Snort (IDS mode)

- Create log dir (if missing):
  - Apple Silicon:
    - `sudo mkdir -p /opt/homebrew/var/log/snort && sudo chown "$USER" /opt/homebrew/var/log/snort`
  - Intel:
    - `sudo mkdir -p /usr/local/var/log/snort && sudo chown "$USER" /usr/local/var/log/snort`
- Start Snort with JSON alerts (adjust interface and prefix):
  - Apple Silicon example:
    - `snort -i en0 -c /opt/homebrew/etc/snort/snort.lua -A alert_json -l /opt/homebrew/var/log/snort -k none`
  - Intel example:
    - `snort -i en0 -c /usr/local/etc/snort/snort.lua -A alert_json -l /usr/local/var/log/snort -k none`

Python Environment

- Optional dedicated venv in repo root:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r snort_ids/requirements.txt`

Run the Monitor

- Default locations are auto-detected; you can override via flags.
- Example (Apple Silicon):
  - `python snort_ids/snort_monitor.py --alert-file /opt/homebrew/var/log/snort/alert_json.txt --events-out snort_ids/events.ndjson`
- Or spawn Snort and monitor together:
  - `python snort_ids/snort_monitor.py --spawn-snort --iface en0 --events-out snort_ids/events.ndjson`

Run the Dashboard

- Real-time alerts only:
  - `streamlit run snort_ids/streamlit_app.py`
- Unified (KDD99 ML + Snort Live):
  - `streamlit run snort_ids/unified_dashboard.py`
- Use the sidebar to set `events.ndjson` path (default: `snort_ids/events.ndjson`).

Notes

- If JSON alerts aren’t available, the monitor falls back to parsing `alert_fast` format.
- Running on wireless interfaces may require monitor mode or admin privileges.
- For production, harden Snort config, rule sets, and rotation/retention.
 - For KDD99 ML tab, the app looks for `ids_env/kddcup.data_10_percent.gz`. You can change the path in the UI.
