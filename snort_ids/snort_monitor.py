import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
import joblib
import numpy as np
try:
    from tensorflow.keras.models import load_model
except Exception:
    load_model = None


FAST_RE = re.compile(
    r"^(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?) \\[*\*\*\\] \\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\\] (?P<msg>.*?) \\[*\*\*\\] \\[Priority: (?P<prio>\d+)\\] \\{(?P<proto>[^}]+)\\} (?P<src>[^ ]+) -> (?P<dst>.+)$"
)


def detect_brew_prefix() -> Path:
    candidates = [Path("/opt/homebrew"), Path("/usr/local")]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


def default_paths():
    prefix = detect_brew_prefix()
    return {
        "config": prefix / "etc/snort/snort.lua",
        "logdir": prefix / "var/log/snort",
        "alert_json": prefix / "var/log/snort/alert_json.txt",
        "alert_fast": prefix / "var/log/snort/alert_fast.txt",
    }


def parse_fast_line(line: str):
    m = FAST_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    ts = d.get("ts")
    try:
        # Snort fast ts format: MM/DD-HH:MM:SS[.usec]
        now = datetime.now()
        dt = datetime.strptime(f"{now.year}-{ts}", "%Y-%m/%d-%H:%M:%S.%f")
    except Exception:
        dt = datetime.utcnow()

    def split_host_port(s):
        if ":" in s and not s.startswith("["):
            host, port = s.rsplit(":", 1)
            return host, port
        return s, None

    src_host, src_port = split_host_port(d.get("src", ""))
    dst_host, dst_port = split_host_port(d.get("dst", ""))

    return {
        "timestamp": dt.isoformat(),
        "gid": int(d["gid"]),
        "sid": int(d["sid"]),
        "rev": int(d["rev"]),
        "msg": d["msg"],
        "priority": int(d["prio"]),
        "proto": d["proto"],
        "src_ip": src_host,
        "src_port": src_port,
        "dst_ip": dst_host,
        "dst_port": dst_port,
        "raw": line.strip(),
        "format": "fast",
    }


def tail_file(path: Path, from_start: bool = False):
    with path.open("r", errors="ignore") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            yield line


def run_snort(args, paths):
    cmd = [
        "snort",
        "-i",
        args.iface,
        "-c",
        str(args.config or paths["config"]),
        "-A",
        "alert_json",
        "-l",
        str(args.log_dir or paths["logdir"]),
        "-k",
        "none",
    ]
    if args.extra:
        cmd.extend(args.extra)

    print(f"Starting Snort: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc


def main():
    paths = default_paths()
    parser = argparse.ArgumentParser(description="Tail Snort alerts and emit NDJSON events")
    parser.add_argument("--alert-file", type=Path, default=None, help="Path to Snort alert file (JSON preferred)")
    parser.add_argument("--events-out", type=Path, default=Path("snort_ids/events.ndjson"), help="NDJSON output file")
    parser.add_argument("--from-start", action="store_true", help="Read alert file from beginning")
    parser.add_argument("--spawn-snort", action="store_true", help="Spawn Snort with JSON alerts")
    parser.add_argument("--iface", default="en0", help="Network interface for Snort")
    parser.add_argument("--config", type=Path, default=None, help="snort.lua path")
    parser.add_argument("--log-dir", type=Path, default=None, help="Snort log directory")
    parser.add_argument("--extra", nargs=argparse.REMAINDER, help="Extra args passed to Snort after '--' separator")
    parser.add_argument("--ml-service", type=str, default=None, help="URL of ML scoring service (e.g. http://127.0.0.1:8000)")

    args = parser.parse_args()

    # Try to load ML artifacts (model + scaler + encoders) for local inference
    ML_MODEL = None
    ML_SCALER = None
    ML_ENCODERS = {}
    models_dir = Path(__file__).parent / 'models'
    try:
        if args.ml_service is None:
            # only load local artifacts when ml_service not used
            if (models_dir / 'kdd_model.h5').exists() and load_model is not None:
                ML_MODEL = load_model(models_dir / 'kdd_model.h5')
            if (models_dir / 'scaler.pkl').exists():
                ML_SCALER = joblib.load(models_dir / 'scaler.pkl')
            # load optional encoders
            for nm in ['protocol_type_enc.pkl', 'service_enc.pkl', 'flag_enc.pkl']:
                p = models_dir / nm
                if p.exists():
                    ML_ENCODERS[nm.split('_enc')[0]] = joblib.load(p)
    except Exception:
        ML_MODEL = None
        ML_SCALER = None
        ML_ENCODERS = {}

    # If ml_service is provided, use remote scoring
    ML_SERVICE_URL = args.ml_service
    if ML_SERVICE_URL:
        try:
            import requests
        except Exception:
            print('requests library required to call ML service; install it or omit --ml-service')
            ML_SERVICE_URL = None

    def features_from_event(event: dict):
        """Produce a feature vector matching the exact 41 KDD99 features used in training."""
        
        proto = str(event.get('proto', '')).upper()
        dst_port = int(event.get('dst_port') or 0)
        src_bytes = int(event.get('src_bytes') or 0)
        dst_bytes = int(event.get('dst_bytes') or 0)
        
        # Encode protocol_type (0=tcp, 1=udp, 2=icmp, 3=other)
        if proto == 'TCP':
            protocol_type = 0
        elif proto == 'UDP':
            protocol_type = 1
        elif proto == 'ICMP':
            protocol_type = 2
        else:
            protocol_type = 3
        
        # Map destination port to service (0-50 categories)
        service_map = {
            20: 0, 21: 1, 22: 2, 23: 3, 25: 4, 53: 5, 69: 6, 79: 7, 80: 8, 110: 9,
            111: 10, 113: 11, 135: 12, 139: 13, 143: 14, 179: 15, 389: 16, 427: 17,
            443: 18, 445: 19, 465: 20, 513: 21, 514: 22, 515: 23, 543: 24, 544: 25,
            548: 26, 554: 27, 587: 28, 631: 29, 636: 30, 646: 31, 873: 32, 902: 33,
            989: 34, 990: 35, 993: 36, 995: 37, 1433: 38, 1521: 39, 3306: 40, 3389: 41,
            5432: 42, 5984: 43, 6379: 44, 8080: 45, 8443: 46, 9200: 47, 27017: 48, 50500: 49
        }
        service = service_map.get(dst_port, 50)
        
        # Build 41-feature vector in exact KDD order
        vec = [
            0.0,  # 0: duration
            float(protocol_type),  # 1: protocol_type
            float(service),  # 2: service
            0.0,  # 3: flag
            float(src_bytes),  # 4: src_bytes
            float(dst_bytes),  # 5: dst_bytes
            0.0,  # 6: land
            0.0,  # 7: wrong_fragment
            0.0,  # 8: urgent
            0.0,  # 9: hot
            0.0,  # 10: num_failed_logins
            0.0,  # 11: logged_in
            0.0,  # 12: num_compromised
            0.0,  # 13: root_shell
            0.0,  # 14: su_attempted
            0.0,  # 15: num_root
            0.0,  # 16: num_file_creations
            0.0,  # 17: num_shells
            0.0,  # 18: num_access_files
            0.0,  # 19: num_outbound_cmds
            0.0,  # 20: is_host_login
            0.0,  # 21: is_guest_login
            1.0,  # 22: count
            1.0,  # 23: srv_count
            0.0,  # 24: serror_rate
            0.0,  # 25: srv_serror_rate
            0.0,  # 26: rerror_rate
            0.0,  # 27: srv_rerror_rate
            1.0,  # 28: same_srv_rate
            0.0,  # 29: diff_srv_rate
            0.0,  # 30: srv_diff_host_rate
            1.0,  # 31: dst_host_count
            1.0,  # 32: dst_host_srv_count
            1.0,  # 33: dst_host_same_srv_rate
            0.0,  # 34: dst_host_diff_srv_rate
            1.0,  # 35: dst_host_same_src_port_rate
            0.0,  # 36: dst_host_srv_diff_host_rate
            0.0,  # 37: dst_host_serror_rate
            0.0,  # 38: dst_host_srv_serror_rate
            0.0,  # 39: dst_host_rerror_rate
            0.0,  # 40: dst_host_srv_rerror_rate
        ]
        
        assert len(vec) == 41, f"Feature vector has {len(vec)} elements, expected 41"
        return np.array(vec, dtype=float).reshape(1, -1)

    def score_event_local(event: dict):
        if ML_MODEL is None or ML_SCALER is None:
            return event
        try:
            X = features_from_event(event)
            Xs = ML_SCALER.transform(X)
            prob = float(ML_MODEL.predict(Xs, verbose=0).ravel()[0])
            event['ml_score'] = prob
            event['ml_label'] = 1 if prob > 0.5 else 0
        except Exception:
            event['ml_score'] = None
            event['ml_label'] = None
        return event

    def score_event_remote(event: dict):
        if not ML_SERVICE_URL:
            return event
        try:
            import requests
            resp = requests.post(ML_SERVICE_URL.rstrip('/') + '/score', json={'event': event}, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                event['ml_score'] = data.get('ml_score')
                event['ml_label'] = data.get('ml_label')
            else:
                event['ml_score'] = None
                event['ml_label'] = None
        except Exception:
            event['ml_score'] = None
            event['ml_label'] = None
        return event

    def score_event(event: dict):
        if ML_SERVICE_URL:
            return score_event_remote(event)
        return score_event_local(event)

    def candidate_alerts():
        if args.log_dir:
            base = Path(args.log_dir)
            return [base / "alert_json.txt", base / "alert_fast.txt"]
        return [paths["alert_json"], paths["alert_fast"]]

    alert_file = args.alert_file
    if alert_file is None:
        # Pick first existing from candidates; otherwise first candidate (json) and hope Snort creates it
        cands = candidate_alerts()
        found = next((p for p in cands if p.exists()), None)
        alert_file = found or cands[0]

    if not Path(alert_file).exists() and not args.spawn_snort:
        print(f"Alert file not found: {alert_file}. Use --spawn-snort or point --alert-file.")
        sys.exit(1)

    snort_proc = None
    if args.spawn_snort:
        snort_proc = run_snort(args, paths)
        # Snort may take a moment to create the alert file
        timeout = time.time() + 20
        cands = candidate_alerts()
        while time.time() < timeout:
            for p in cands:
                if p.exists():
                    alert_file = p
                    break
            if Path(alert_file).exists():
                break
            time.sleep(0.5)

    events_out = args.events_out
    events_out.parent.mkdir(parents=True, exist_ok=True)
    print(f"Tailing: {alert_file}")
    print(f"Writing events to: {events_out}")

    stop = False

    def handle_sigint(signum, frame):
        nonlocal stop
        stop = True
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    with events_out.open("a") as out:
        try:
            for line in tail_file(alert_file, from_start=args.from_start):
                if stop:
                    break
                line = line.strip()
                if not line:
                    continue
                event = None
                # Prefer JSON parsing
                if line.startswith("{") and line.endswith("}"):
                    try:
                        data = json.loads(line)
                        # Normalize common fields
                        event = {
                            "timestamp": data.get("timestamp") or data.get("ts") or datetime.utcnow().isoformat(),
                            "msg": (data.get("alert") or {}).get("signature") or data.get("msg"),
                            "sid": (data.get("alert") or {}).get("signature_id") or data.get("sid"),
                            "gid": (data.get("alert") or {}).get("gid") or data.get("gid"),
                            "rev": (data.get("alert") or {}).get("rev") or data.get("rev"),
                            "priority": (data.get("alert") or {}).get("severity") or data.get("priority"),
                            "proto": (data.get("proto") or data.get("protocol")),
                            "src_ip": data.get("src_ip"),
                            "src_port": data.get("src_port"),
                            "dst_ip": data.get("dest_ip") or data.get("dst_ip"),
                            "dst_port": data.get("dest_port") or data.get("dst_port"),
                            "raw": data,
                            "format": "json",
                        }
                    except Exception:
                        event = None
                if event is None:
                    event = parse_fast_line(line)
                if event is None:
                    # Unrecognized line, skip
                    continue
                # Add ML score/label if model available
                try:
                    event = score_event(event)
                except Exception:
                    pass
                out.write(json.dumps(event) + "\n")
                out.flush()
                # Also echo a compact line to stdout for visibility
                print(
                    f"[{event.get('timestamp')}] prio={event.get('priority')} "
                    f"{event.get('proto')} {event.get('src_ip')}->{event.get('dst_ip')} - {event.get('msg')}"
                )
        finally:
            if snort_proc is not None:
                try:
                    snort_proc.terminate()
                    snort_proc.wait(timeout=5)
                except Exception:
                    snort_proc.kill()


if __name__ == "__main__":
    main()
