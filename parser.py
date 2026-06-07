import csv
import json
import os
import sys
import time
import signal
from datetime import datetime, timezone


BUFFER_FILE    = "packet_stream.tmp"
LOCK_FILE      = "packet_stream.lock"
CSV_LOCK_FILE  = "model_log.lock"
OUTPUT_CSV     = "model_log.csv"
POLL_INTERVAL  = 0.25
FAST_INTERVAL  = 0.01
LOG_PREFIX     = "[PARSER]"
STALE_LOCK_AGE = 10.0


PSEUDO_DURATION = 1.0


def _acquire_lock(lock_path: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                age = time.monotonic() - os.path.getmtime(lock_path)
                if age > STALE_LOCK_AGE:
                    os.remove(lock_path)
                    continue
            except OSError:
                pass
            time.sleep(0.005)
    return False


def _release_lock(lock_path: str):
    try:
        os.remove(lock_path)
    except OSError:
        pass


# Data which would be fed to model
FEATURE_COLUMNS = [
    "timestamp", "src_ip",
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
    "fwd_bwd_packet_ratio",
    "fwd_bwd_len_ratio",
]



def build_feature_row(record: dict) -> dict:
    flags    = record.get("flags", {})
    pkt_len  = float(record.get("pkt_length", 0))
    dst_port = int(record.get("dst_port", 0))
    protocol = int(record.get("protocol", 6))

    tcp_window     = int(record.get("tcp_window", 0))
    fwd_header_len = 20  # Minimum TCP header (no options)

    flow_byts_s = pkt_len / PSEUDO_DURATION
    flow_pkts_s = 1.0    / PSEUDO_DURATION

    tot_fwd_pkts     = 1
    tot_bwd_pkts     = 0
    totlen_fwd_pkts  = pkt_len
    totlen_bwd_pkts  = 0.0

    fwd_bwd_packet_ratio = tot_fwd_pkts  / (tot_bwd_pkts  + 1e-5)
    fwd_bwd_len_ratio    = totlen_fwd_pkts / (totlen_bwd_pkts + 1e-5)

    return {
        "timestamp":             record.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "src_ip":                record.get("src_ip", "0.0.0.0"),

        "dst_port":              dst_port,
        "protocol":              protocol,

        "flow_duration":         0.0,
        "tot_fwd_pkts":          tot_fwd_pkts,
        "tot_bwd_pkts":          tot_bwd_pkts,
        "totlen_fwd_pkts":       totlen_fwd_pkts,
        "totlen_bwd_pkts":       totlen_bwd_pkts,

        "fwd_pkt_len_max":       pkt_len,
        "fwd_pkt_len_min":       pkt_len,
        "fwd_pkt_len_mean":      pkt_len,
        "fwd_pkt_len_std":       0.0,

        "bwd_pkt_len_max":       0.0,
        "bwd_pkt_len_min":       0.0,
        "bwd_pkt_len_mean":      0.0,
        "bwd_pkt_len_std":       0.0,

        "flow_byts_s":           flow_byts_s,
        "flow_pkts_s":           flow_pkts_s,

        "flow_iat_mean":         0.0,
        "flow_iat_std":          0.0,
        "flow_iat_max":          0.0,
        "flow_iat_min":          0.0,
        "fwd_iat_tot":           0.0,
        "fwd_iat_mean":          0.0,
        "fwd_iat_std":           0.0,
        "fwd_iat_max":           0.0,
        "fwd_iat_min":           0.0,
        "bwd_iat_tot":           0.0,
        "bwd_iat_mean":          0.0,
        "bwd_iat_std":           0.0,
        "bwd_iat_max":           0.0,
        "bwd_iat_min":           0.0,

        "fwd_psh_flags":         flags.get("PSH", 0),
        "bwd_psh_flags":         0,
        "fwd_urg_flags":         flags.get("URG", 0),
        "bwd_urg_flags":         0,

        "fwd_header_len":        fwd_header_len,
        "bwd_header_len":        0,
        "fwd_pkts_s":            flow_pkts_s,
        "bwd_pkts_s":            0.0,

        "pkt_len_min":           pkt_len,
        "pkt_len_max":           pkt_len,
        "pkt_len_mean":          pkt_len,
        "pkt_len_std":           0.0,
        "pkt_len_var":           0.0,

        "fin_flag_cnt":          flags.get("FIN", 0),
        "syn_flag_cnt":          flags.get("SYN", 0),
        "rst_flag_cnt":          flags.get("RST", 0),
        "psh_flag_cnt":          flags.get("PSH", 0),
        "ack_flag_cnt":          flags.get("ACK", 0),
        "urg_flag_cnt":          flags.get("URG", 0),
        "cwe_flag_count":        flags.get("CWR", 0),
        "ece_flag_cnt":          flags.get("ECE", 0),

        "down_up_ratio":         0.0,
        "pkt_size_avg":          pkt_len,
        "fwd_seg_size_avg":      pkt_len,
        "bwd_seg_size_avg":      0.0,
        "fwd_byts_b_avg":        0.0,
        "fwd_pkts_b_avg":        0.0,
        "fwd_blk_rate_avg":      0.0,
        "bwd_byts_b_avg":        0.0,
        "bwd_pkts_b_avg":        0.0,
        "bwd_blk_rate_avg":      0.0,

        "subflow_fwd_pkts":      tot_fwd_pkts,
        "subflow_fwd_byts":      totlen_fwd_pkts,
        "subflow_bwd_pkts":      tot_bwd_pkts,
        "subflow_bwd_byts":      totlen_bwd_pkts,

        "init_fwd_win_byts":     tcp_window,   # FIX: was always 0
        "init_bwd_win_byts":     0,
        "fwd_act_data_pkts":     1,
        "fwd_seg_size_min":      fwd_header_len,

        "active_mean":           0.0,
        "active_std":            0.0,
        "active_max":            0.0,
        "active_min":            0.0,
        "idle_mean":             0.0,
        "idle_std":              0.0,
        "idle_max":              0.0,
        "idle_min":              0.0,

        "fwd_bwd_packet_ratio":  fwd_bwd_packet_ratio,
        "fwd_bwd_len_ratio":     fwd_bwd_len_ratio,
    }


def drain_buffer() -> list:
    """
    Atomically steal all pending JSON lines from packet_stream.tmp.
    Uses os.replace() which is atomic on NTFS within the same volume.
    """
    if not os.path.exists(BUFFER_FILE):
        return []

    # Respect sniffer.py's write lock
    if os.path.exists(LOCK_FILE):
        try:
            age = time.monotonic() - os.path.getmtime(LOCK_FILE)
            if age <= STALE_LOCK_AGE:
                return []
        except OSError:
            return []

    sidecar = BUFFER_FILE + ".reading"
    records = []

    try:
        os.replace(BUFFER_FILE, sidecar)
    except (PermissionError, OSError, FileNotFoundError):
        # sniffer.py opened the file between our check and rename — retry next cycle
        return []

    try:
        with open(sidecar, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    finally:
        try:
            os.remove(sidecar)
        except OSError:
            pass

    return records


def append_to_csv(row: dict):
    """Append one feature row to model_log.csv, writing the header when needed."""
    # FIX: check existence each time — engine.py might have been restarted
    needs_header = not os.path.exists(OUTPUT_CSV) or os.path.getsize(OUTPUT_CSV) == 0

    if not _acquire_lock(CSV_LOCK_FILE):
        print(f"{LOG_PREFIX} WARNING: CSV lock timeout — row skipped.")
        return

    try:
        with open(OUTPUT_CSV, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=FEATURE_COLUMNS)
            if needs_header:
                writer.writeheader()
            writer.writerow({col: row.get(col, 0.0) for col in FEATURE_COLUMNS})
    except OSError as exc:
        print(f"{LOG_PREFIX} ERROR writing CSV: {exc}")
    finally:
        _release_lock(CSV_LOCK_FILE)



_running = True


def _handle_shutdown(sig, frame):
    global _running
    sig_name = "Ctrl+C" if sig == signal.SIGINT else "SIGTERM"
    print(f"\n{LOG_PREFIX} {sig_name} received — shutting down parser.")
    _running = False
    _release_lock(CSV_LOCK_FILE)
    sys.exit(0)


signal.signal(signal.SIGINT,  _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


if __name__ == "__main__":
    _release_lock(CSV_LOCK_FILE)

    print(f"{LOG_PREFIX} Feature compiler started.")
    print(f"{LOG_PREFIX} Monitoring buffer : {BUFFER_FILE}")
    print(f"{LOG_PREFIX} Writing CSV to    : {OUTPUT_CSV}")
    print(f"{LOG_PREFIX} Press Ctrl+C to stop.\n")

    try:
        while _running:
            records = drain_buffer()

            if not records:
                time.sleep(POLL_INTERVAL)
                continue

            for record in records:
                try:
                    feature_row = build_feature_row(record)
                    append_to_csv(feature_row)
                    print(
                        f"{LOG_PREFIX} Formatted & Appended IP: {feature_row['src_ip']}"
                        f"  | SYN:{feature_row['syn_flag_cnt']}"
                        f" ACK:{feature_row['ack_flag_cnt']}"
                        f" FIN:{feature_row['fin_flag_cnt']}"
                        f" PSH:{feature_row['psh_flag_cnt']}"
                        f" WIN:{feature_row['init_fwd_win_byts']}"
                    )
                except Exception as exc:
                    print(f"{LOG_PREFIX} ERROR processing record: {exc}")

            time.sleep(FAST_INTERVAL if records else POLL_INTERVAL)

    except KeyboardInterrupt:
        _handle_shutdown(signal.SIGINT, None)