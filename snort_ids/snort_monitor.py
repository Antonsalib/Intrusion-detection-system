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

    args = parser.parse_args()

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
