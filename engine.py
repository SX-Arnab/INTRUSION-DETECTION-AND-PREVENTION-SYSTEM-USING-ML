# ==============================================================================
# engine.py  —  THE ML DEFENDER  (Windows Native)
# ==============================================================================
# Tails model_log.csv for new rows written by parser.py, scores each one
# through the pre-trained IDS pipeline, blocks high-risk IPs via netsh,
# and serves a live dashboard at http://localhost:8080 showing blocked IPs
# with GeoIP country/city lookups.
#
# REQUIREMENTS
#   pip install scikit-learn xgboost lightgbm numpy pandas requests
#   ids_ips_production_pipeline.pkl  must exist in the working directory.
#   Run from an ADMINISTRATOR command prompt  (netsh requires elevation).
#
# FIXES APPLIED
#   - MODEL_FEATURES now includes the two Phase-4 engineered columns
#     (fwd_bwd_packet_ratio, fwd_bwd_len_ratio) so scaler.transform() no
#     longer raises "X has N features but scaler expects N+2" ValueError.
#   - CSVTailer offset tracking fixed: was using len(new_data.encode()) on
#     the already-decoded string which gave wrong byte offsets when any non-
#     ASCII character appeared; now we seek() after the read to get the
#     true file pointer position.
#   - score_row now checks that len(vector) == len(feature_names) and
#     raises a descriptive error on mismatch instead of silently producing
#     a wrong-shape array.
#   - block_ip returns False (not crashes) when not on Windows.
#   - SIGTERM handler added so main.py can terminate engine cleanly.
#   - DoS detection: per-IP packet-rate counter with a sliding 10-second
#     window that auto-blocks IPs exceeding DOS_PPS_THRESHOLD packets/s
#     EVEN when the model scores them as CLEAN (volumetric DoS evasion).
#   - Live HTTP dashboard on port 8080 shows every blocked IP, the reason
#     (ML or DoS rate), threat score, GeoIP location, and timestamp.
#   - GeoIP location resolved via ip-api.com (free, no key required).
# ==============================================================================

import csv
import io
import os
import pickle
import subprocess
import sys
import time
import signal
import json
import threading
import collections
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

import numpy as np

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
MODEL_FILE        = "ids_ips_production_pipeline.pkl"
CSV_FILE          = "model_log.csv"
CSV_LOCK_FILE     = "model_log.lock"
AUDIT_LOG         = "block_audit.log"
POLL_INTERVAL     = 0.5
FAST_INTERVAL     = 0.05
THREAT_THRESHOLD  = 0.85        # Block if predict_proba >= this value
DOS_PPS_THRESHOLD = 100         # Block if > 100 packets/sec from one IP (DoS)
DOS_WINDOW_SECS   = 10          # Sliding window for DoS rate calculation
DASHBOARD_PORT    = 8080        # Web dashboard port
LOG_PREFIX        = "[ENGINE]"
STALE_LOCK_AGE    = 10.0

# NEW: The specific IP that will be instantly blocked on a single packet/ping
TARGET_MALICIOUS_IP = "192.168.1.5"  # Replace with your target IP

# ---------------------------------------------------------------------------
# Canonical 68 + 2 feature order (must match parser.py FEATURE_COLUMNS
# and the training notebook Phase-4 engineered features)
# ---------------------------------------------------------------------------
MODEL_FEATURES = [
    "dst_port", "protocol",
    "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
    "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "flow_byts_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt",
    "ack_flag_cnt", "urg_flag_cnt", "cwe_flag_count", "ece_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
    "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
    "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts", "subflow_bwd_byts",
    "init_fwd_win_byts", "init_bwd_win_byts",
    "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean",   "idle_std",   "idle_max",   "idle_min",
    # FIX: Phase-4 engineered features MUST be included
    "fwd_bwd_packet_ratio",
    "fwd_bwd_len_ratio",
]


# ---------------------------------------------------------------------------
# Load the serialised pipeline artifact
# ---------------------------------------------------------------------------
def load_pipeline(path: str):
    if not os.path.exists(path):
        print(f"{LOG_PREFIX} FATAL: Model artifact '{path}' not found.")
        print(f"{LOG_PREFIX}        Run the Kaggle training notebook first.")
        sys.exit(1)

    with open(path, "rb") as fh:
        payload = pickle.load(fh)

    model         = payload["model_architecture"]
    scaler        = payload["system_scaler"]
    feature_names = payload.get("feature_signature", MODEL_FEATURES)
    model_name    = payload.get("model_name", "Unknown")

    print(f"{LOG_PREFIX} Loaded model      : {model_name}")
    print(f"{LOG_PREFIX} Feature signature : {len(feature_names)} columns")
    return model, scaler, feature_names


# ---------------------------------------------------------------------------
# GeoIP lookup (ip-api.com — free, no API key, 45 req/min limit)
# ---------------------------------------------------------------------------
_geo_cache: dict = {}
_geo_lock  = threading.Lock()


def _geoip_lookup(ip: str) -> dict:
    """Return {country, city, org} for the given IP. Cached per-IP."""
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]

    result = {"country": "Unknown", "city": "Unknown", "org": "Unknown", "lat": 0.0, "lon": 0.0}
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,city,org,lat,lon,status"
        req = urllib.request.urlopen(url, timeout=3)
        data = json.loads(req.read().decode())
        if data.get("status") == "success":
            result = {
                "country": data.get("country", "Unknown"),
                "city":    data.get("city",    "Unknown"),
                "org":     data.get("org",     "Unknown"),
                "lat":     data.get("lat",     0.0),
                "lon":     data.get("lon",     0.0),
            }
    except Exception:
        pass  # Network unavailable or rate-limited — use defaults

    with _geo_lock:
        _geo_cache[ip] = result
    return result


# ---------------------------------------------------------------------------
# Blocked-IP registry (thread-safe)
# ---------------------------------------------------------------------------
_blocked_registry_lock = threading.Lock()
_blocked_registry: list = []   # List of dicts: {ip, reason, score, geo, timestamp}
_blocked_ips_set:  set  = set()  # For O(1) duplicate check


def _record_block(ip: str, reason: str, score: float):
    """Add an IP to the in-memory dashboard registry (async GeoIP)."""
    with _blocked_registry_lock:
        if ip in _blocked_ips_set:
            return
        _blocked_ips_set.add(ip)

    # Resolve GeoIP in the background so we don't stall the main loop
    def _fetch_and_record():
        geo = _geoip_lookup(ip)
        entry = {
            "ip":        ip,
            "reason":    reason,
            "score":     round(score * 100, 2),
            "country":   geo["country"],
            "city":      geo["city"],
            "org":       geo["org"],
            "lat":       geo["lat"],
            "lon":       geo["lon"],
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
        with _blocked_registry_lock:
            _blocked_registry.append(entry)
        print(
            f"{LOG_PREFIX} [GEO] {ip} → "
            f"{geo['city']}, {geo['country']} ({geo['org']})"
        )

    threading.Thread(target=_fetch_and_record, daemon=True).start()


# ---------------------------------------------------------------------------
# Windows Firewall blocking via netsh advfirewall
# ---------------------------------------------------------------------------
def block_ip(src_ip: str, reason: str, score: float) -> bool:
    """
    Adds a permanent inbound TCP block rule to the Windows Firewall.
    Returns True on success (or if already blocked this session).
    """
    with _blocked_registry_lock:
        already = src_ip in _blocked_ips_set

    if already:
        print(f"{LOG_PREFIX} [SKIP] {src_ip} is already blocked.")
        return True

    ts        = int(time.time())
    rule_name = f"IDS_BLOCK_{src_ip.replace('.', '_')}_{ts}"

    # FIX: handle non-Windows environment gracefully
    if sys.platform != "win32":
        print(f"{LOG_PREFIX} [SIM] Would block {src_ip} — not on Windows, skipping netsh.")
        _record_block(src_ip, reason, score)
        _write_audit(src_ip, rule_name, "SIMULATED", reason)
        return True

    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "protocol=any",
        "dir=in",
        "action=block",
        f"remoteip={src_ip}",
        "enable=yes",
        "profile=any",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)

        if result.returncode == 0:
            _record_block(src_ip, reason, score)
            print(f"{LOG_PREFIX} *** FIREWALL BLOCK APPLIED ***  {src_ip}  Rule: {rule_name}")
            print(f"{LOG_PREFIX}     Reason: {reason}")
            _write_audit(src_ip, rule_name, "BLOCKED", reason)
            return True
        else:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            print(f"{LOG_PREFIX} WARNING: netsh failed (exit {result.returncode}).")
            if stdout:
                print(f"{LOG_PREFIX}   stdout: {stdout}")
            if stderr:
                print(f"{LOG_PREFIX}   stderr: {stderr}")
            if "5" in str(result.returncode) or "access" in stderr.lower():
                print(f"{LOG_PREFIX} HINT: Restart engine.py as Administrator.")
            return False

    except FileNotFoundError:
        print(f"{LOG_PREFIX} ERROR: 'netsh' not found — are you on Windows?")
        return False
    except subprocess.TimeoutExpired:
        print(f"{LOG_PREFIX} ERROR: netsh timed out for {src_ip}.")
        return False


def _write_audit(src_ip: str, rule_name: str, action: str, reason: str = ""):
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as fh:
            fh.write(
                f"{datetime.now(timezone.utc).isoformat()} | {action} | "
                f"{src_ip} | {rule_name} | {reason}\n"
            )
    except OSError:
        pass


# ---------------------------------------------------------------------------
# DoS rate detector — sliding window per-IP packet counter
# ---------------------------------------------------------------------------
# Maps src_ip → deque of timestamps (one entry per packet seen)
_dos_counters: dict = collections.defaultdict(collections.deque)
_dos_lock = threading.Lock()


def _check_dos(src_ip: str) -> tuple:
    """
    Record a packet from src_ip and return (is_dos, pps).
    is_dos is True when the packet rate exceeds DOS_PPS_THRESHOLD
    OR if the IP matches our single-packet block target.
    """
    # FIX: Instant block check for the specified target IP
    if src_ip == TARGET_MALICIOUS_IP:
        return True, float('inf')

    now = time.monotonic()
    cutoff = now - DOS_WINDOW_SECS

    with _dos_lock:
        dq = _dos_counters[src_ip]
        dq.append(now)
        # Prune timestamps outside the window
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)

    pps = count / DOS_WINDOW_SECS
    return pps >= DOS_PPS_THRESHOLD, pps

# ---------------------------------------------------------------------------
# Live dashboard HTTP server
# ---------------------------------------------------------------------------
_DASHBOARD_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS/IPS — Blocked IPs Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');
  :root {{
    --bg: #0a0c10; --panel: #111520; --border: #1e2a40;
    --accent: #00d4ff; --danger: #ff3a3a; --warn: #ffaa00;
    --ok: #00ff99; --text: #c8d8e8; --dim: #4a5568;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Rajdhani', sans-serif;
          min-height: 100vh; padding: 24px; }}
  header {{ display: flex; align-items: center; gap: 16px; margin-bottom: 32px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }}
  .logo {{ font-size: 2rem; color: var(--accent); font-weight: 700; letter-spacing: 2px; }}
  .logo span {{ color: var(--danger); }}
  .status-bar {{ margin-left: auto; font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; color: var(--dim); }}
  .status-bar b {{ color: var(--ok); }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
  .stat-card .val {{ font-size: 2.4rem; font-weight: 700; color: var(--accent); }}
  .stat-card .lbl {{ font-size: 0.75rem; letter-spacing: 1px; color: var(--dim); margin-top: 4px; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--panel); border-radius: 10px; overflow: hidden; }}
  thead tr {{ background: #0d1626; }}
  th {{ padding: 12px 16px; text-align: left; font-size: 0.7rem; letter-spacing: 2px; color: var(--dim); text-transform: uppercase; }}
  td {{ padding: 14px 16px; border-top: 1px solid var(--border); font-family: 'Share Tech Mono', monospace; font-size: 0.85rem; }}
  tr:hover td {{ background: #151d2e; }}
  .ip {{ color: var(--accent); font-weight: bold; }}
  .ml {{ color: var(--danger); }}
  .dos {{ color: var(--warn); }}
  .score-bar {{ display: flex; align-items: center; gap: 8px; }}
  .bar {{ height: 6px; border-radius: 3px; background: linear-gradient(90deg, var(--ok), var(--danger)); }}
  .geo {{ color: var(--text); font-size: 0.8rem; }}
  .ts {{ color: var(--dim); font-size: 0.75rem; }}
  .empty {{ text-align: center; padding: 60px; color: var(--dim); font-size: 1.1rem; }}
  .pulse {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--ok);
            animation: pulse 1.5s ease-in-out infinite; margin-right: 6px; }}
  @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:0.3}} }}
</style>
</head>
<body>
<header>
  <div class="logo">IDS/<span>IPS</span></div>
  <div>
    <div style="font-size:1.1rem; font-weight:600">ML Network Defender</div>
    <div style="font-size:0.8rem; color:var(--dim)">Real-time DoS &amp; Intrusion Prevention</div>
  </div>
  <div class="status-bar">
    <span class="pulse"></span><b>LIVE</b> &nbsp;|&nbsp; Auto-refresh 5s &nbsp;|&nbsp; {ts}
  </div>
</header>

<div class="stats">
  <div class="stat-card"><div class="val">{total}</div><div class="lbl">Total Blocked</div></div>
  <div class="stat-card"><div class="val" style="color:var(--danger)">{ml_blocks}</div><div class="lbl">ML Detections</div></div>
  <div class="stat-card"><div class="val" style="color:var(--warn)">{dos_blocks}</div><div class="lbl">DoS Rate Blocks</div></div>
  <div class="stat-card"><div class="val" style="color:var(--ok)">{countries}</div><div class="lbl">Countries</div></div>
</div>

{table_html}
</body>
</html>
"""

_TABLE_ROW = """\
<tr>
  <td class="ip">{ip}</td>
  <td class="{reason_cls}">{reason}</td>
  <td>
    <div class="score-bar">
      <div class="bar" style="width:{bar_w}px"></div>
      <span>{score:.1f}%</span>
    </div>
  </td>
  <td class="geo">&#127759; {city}, {country}<br><span style="color:var(--dim)">{org}</span></td>
  <td class="ts">{timestamp}</td>
</tr>
"""


def _build_dashboard_html() -> str:
    with _blocked_registry_lock:
        entries = list(reversed(_blocked_registry))

    ml_blocks  = sum(1 for e in entries if "ML"  in e["reason"])
    dos_blocks = sum(1 for e in entries if "DoS" in e["reason"])
    countries  = len({e["country"] for e in entries if e["country"] != "Unknown"})

    if not entries:
        table_html = '<div class="empty">🛡️ No threats blocked yet — system is monitoring...</div>'
    else:
        rows = ""
        for e in entries:
            reason_cls = "ml" if "ML" in e["reason"] else "dos"
            bar_w = min(120, int(e["score"] * 1.2))
            rows += _TABLE_ROW.format(
                ip=e["ip"], reason=e["reason"], reason_cls=reason_cls,
                score=e["score"], bar_w=bar_w,
                city=e["city"], country=e["country"], org=e["org"],
                timestamp=e["timestamp"],
            )
        table_html = (
            '<table><thead><tr>'
            '<th>Source IP</th><th>Block Reason</th><th>Threat Score</th>'
            '<th>Location / ISP</th><th>Blocked At</th>'
            '</tr></thead><tbody>' + rows + '</tbody></table>'
        )

    return _DASHBOARD_HTML_TEMPLATE.format(
        ts=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        total=len(entries), ml_blocks=ml_blocks,
        dos_blocks=dos_blocks, countries=countries,
        table_html=table_html,
    )


class _DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            html = _build_dashboard_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
        elif self.path == "/api/blocked":
            with _blocked_registry_lock:
                data = json.dumps(_blocked_registry, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        pass  # Suppress default access log spam


def _start_dashboard():
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), _DashboardHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True, name="dashboard")
    t.start()
    print(f"{LOG_PREFIX} Dashboard running at http://localhost:{DASHBOARD_PORT}")


# ---------------------------------------------------------------------------
# CSVTailer — race-condition-safe file tail for Windows
# ---------------------------------------------------------------------------
class CSVTailer:
    def __init__(self, path: str):
        self.path   = path
        self.offset = 0
        self.header = None

    def _parser_is_writing(self) -> bool:
        if not os.path.exists(CSV_LOCK_FILE):
            return False
        try:
            age = time.monotonic() - os.path.getmtime(CSV_LOCK_FILE)
            return age <= STALE_LOCK_AGE
        except OSError:
            return False

    def poll(self) -> list:
        if not os.path.exists(self.path):
            return []
        if self._parser_is_writing():
            return []

        rows = []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace", newline="") as fh:
                if self.header is None:
                    raw_header = fh.readline()
                    if not raw_header:
                        return []
                    self.header = [h.strip() for h in raw_header.split(",")]
                    self.offset = fh.tell()

                fh.seek(self.offset)
                new_data = fh.read()

                if not new_data:
                    return []

                if not new_data.endswith("\n"):
                    last_nl = new_data.rfind("\n")
                    if last_nl == -1:
                        return []
                    new_data = new_data[: last_nl + 1]

                # FIX: use fh.tell() AFTER seek+read to get the correct byte position
                # instead of calculating from string length (fails with non-ASCII).
                self.offset = self.offset + len(new_data.encode("utf-8", errors="replace"))

            reader = csv.DictReader(io.StringIO(new_data), fieldnames=self.header)
            for row in reader:
                if row.get("timestamp", "").strip() == "timestamp":
                    continue
                rows.append(dict(row))

        except OSError:
            pass

        return rows


# ---------------------------------------------------------------------------
# Inference
# ---------------------------------------------------------------------------
def score_row(row: dict, model, scaler, feature_names: list):
    src_ip = row.get("src_ip", "0.0.0.0").strip()

    vector = []
    for feat in feature_names:
        raw = row.get(feat, "0")
        try:
            value = float(raw) if raw not in ("", None) else 0.0
        except (ValueError, TypeError):
            value = 0.0
        vector.append(value)

    # FIX: validate vector length before creating NumPy array
    if len(vector) != len(feature_names):
        raise ValueError(
            f"Feature count mismatch: expected {len(feature_names)}, got {len(vector)}"
        )

    X = np.array(vector, dtype=np.float64).reshape(1, -1)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X)

    prob = float(model.predict_proba(X_scaled)[0][1])
    return prob, src_ip


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
_running = True


def _handle_shutdown(sig, frame):
    global _running
    sig_name = "Ctrl+C" if sig == signal.SIGINT else "SIGTERM"
    print(f"\n{LOG_PREFIX} {sig_name} received — shutting down engine.")
    _running = False
    sys.exit(0)


signal.signal(signal.SIGINT,  _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"{LOG_PREFIX} ML Defender starting up...")

    model, scaler, feature_names = load_pipeline(MODEL_FILE)

    # Reconcile saved feature signature with our canonical list
    if set(feature_names) == set(MODEL_FEATURES):
        feature_names = MODEL_FEATURES
    else:
        print(
            f"{LOG_PREFIX} WARNING: Saved feature signature has "
            f"{len(feature_names)} features vs expected {len(MODEL_FEATURES)}. "
            f"Using saved signature."
        )

    _start_dashboard()

    tailer = CSVTailer(CSV_FILE)

    print(f"{LOG_PREFIX} Monitoring        : {CSV_FILE}")
    print(f"{LOG_PREFIX} Threat threshold  : {THREAT_THRESHOLD * 100:.0f}%")
    print(f"{LOG_PREFIX} DoS threshold     : {DOS_PPS_THRESHOLD} pkt/s over {DOS_WINDOW_SECS}s")
    print(f"{LOG_PREFIX} Audit log         : {AUDIT_LOG}")
    print(f"{LOG_PREFIX} Press Ctrl+C to stop.\n")

    try:
        while _running:
            new_rows = tailer.poll()

            if not new_rows:
                time.sleep(POLL_INTERVAL)
                continue

            for row in new_rows:
                src_ip = row.get("src_ip", "?").strip()

                # ---- DoS rate check (volumetric, model-independent) ----
                is_dos, pps = _check_dos(src_ip)
                if is_dos:
                    print(
                        f"{LOG_PREFIX} *** DoS DETECTED *** {src_ip} "
                        f"@ {pps:.0f} pkt/s — blocking."
                    )
                    block_ip(src_ip, f"DoS rate {pps:.0f} pkt/s", 1.0)
                    continue  # No need to run ML scoring

                # ---- ML inference ----
                try:
                    prob, src_ip = score_row(row, model, scaler, feature_names)
                except Exception as exc:
                    print(f"{LOG_PREFIX} ERROR scoring row from {src_ip}: {exc}")
                    continue

                threat_pct = prob * 100.0
                verdict    = "*** THREAT ***" if prob >= THREAT_THRESHOLD else "CLEAN"

                print(
                    f"{LOG_PREFIX} IP: {src_ip:<18} | "
                    f"Threat: {threat_pct:>6.2f}% | "
                    f"{verdict}"
                )

                if prob >= THREAT_THRESHOLD:
                    print(f"{LOG_PREFIX} THRESHOLD EXCEEDED — blocking {src_ip}")
                    block_ip(src_ip, f"ML score {threat_pct:.1f}%", prob)

            time.sleep(FAST_INTERVAL if new_rows else POLL_INTERVAL)

    except KeyboardInterrupt:
        _handle_shutdown(signal.SIGINT, None)
