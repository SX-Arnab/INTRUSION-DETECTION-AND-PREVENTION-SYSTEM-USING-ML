import json
import os
import socket
import sys
import time
import signal
from datetime import datetime, timezone


try:
    from scapy.all import sniff, IP, TCP, Ether, conf, get_if_list
except ImportError:
    print("[SNIFFER] FATAL: scapy is not installed.")
    print("         Run:  pip install scapy")
    sys.exit(1)

TARGET_PORT = int(os.environ.get("TARGET_PORT", "5000"))

PACKET_LOG_FILE = os.environ.get("PACKET_LOG_FILE", "log.log")
# Stores every captured packet JSON line for archive/review.
BUFFER_FILE     = "packet_stream.tmp"
LOCK_FILE       = "packet_stream.lock"
LOG_PREFIX      = "[SNIFFER]"
LOCK_TIMEOUT    = 5.0
STALE_LOCK_AGE  = 10.0


def _acquire_lock(timeout: float = LOCK_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, str(os.getpid()).encode())
            os.close(fd)
            return True
        except FileExistsError:
            try:
                age = time.monotonic() - os.path.getmtime(LOCK_FILE)
                if age > STALE_LOCK_AGE:
                    os.remove(LOCK_FILE)
                    continue
            except OSError:
                pass
            time.sleep(0.005)
    return False


def _release_lock():
    try:
        os.remove(LOCK_FILE)
    except OSError:
        pass



def _get_local_ips() -> set:
    local = {"127.0.0.1", "0.0.0.0", "::1"}
    # Standard socket approach
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if ":" not in addr:
                local.add(addr)
    except Exception:
        pass
    # Scapy interface approach (catches VPN / bridge adapters)
    try:
        from scapy.all import get_if_addr
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr and addr != "0.0.0.0":
                    local.add(addr)
            except Exception:
                pass
    except Exception:
        pass
    return local


LOCAL_IPS = _get_local_ips()



def _decode_tcp_flags(flags_int: int) -> dict:
    return {
        "FIN": int(bool(flags_int & 0x01)),
        "SYN": int(bool(flags_int & 0x02)),
        "RST": int(bool(flags_int & 0x04)),
        "PSH": int(bool(flags_int & 0x08)),
        "ACK": int(bool(flags_int & 0x10)),
        "URG": int(bool(flags_int & 0x20)),
        "ECE": int(bool(flags_int & 0x40)),
        "CWR": int(bool(flags_int & 0x80)),
    }



def packet_handler(pkt):
    """
    Called by Scapy for every packet that passes the BPF filter.

    Two-layer self-traffic guard:
      Layer 1 — BPF  "tcp"  (Npcap / kernel level)
      Layer 2 — SOFTWARE  src_ip in LOCAL_IPS  (Python fallback)
    """
    if IP not in pkt or TCP not in pkt:
        return

    src_ip = pkt[IP].src
    if src_ip in LOCAL_IPS:
        return  

    ip_hdr_len  = pkt[IP].ihl * 4          
    ip_total    = pkt[IP].len             
    pkt_length  = max(ip_total, len(pkt[IP]))  
    tcp_window = int(pkt[TCP].window)

    src_mac = pkt[Ether].src if Ether in pkt else "00:00:00:00:00:00"

    record = {
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "src_ip":          src_ip,
        "src_mac":         src_mac,
        "src_port":        int(pkt[TCP].sport),
        "dst_port":        int(pkt[TCP].dport),
        "protocol":        6,
        "pkt_length":      pkt_length,
        "ip_ttl":          int(pkt[IP].ttl),
        "tcp_window":      tcp_window,
        "flags":           _decode_tcp_flags(int(pkt[TCP].flags)),
    }

    if _acquire_lock():
        try:

            line = json.dumps(record) + "\n"
            with open(BUFFER_FILE, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(line)
            if PACKET_LOG_FILE:
                with open(PACKET_LOG_FILE, "a", encoding="utf-8", newline="\n") as logfh:
                    logfh.write(line)
        except OSError as exc:
            print(f"{LOG_PREFIX} WARNING: Buffer write failed — {exc}")
        finally:
            _release_lock()
    else:
        print(f"{LOG_PREFIX} WARNING: Lock timeout — packet dropped.")
        return

    print(
        f"{LOG_PREFIX} Captured | IP: {src_ip} | "
        f"Size: {pkt_length}B | "
        f"Win: {tcp_window} | "
        f"Flags: {int(pkt[TCP].flags):#04x}"
    )


_running = True


def _handle_shutdown(sig, frame):
    global _running
    sig_name = "Ctrl+C" if sig == signal.SIGINT else "SIGTERM"
    print(f"\n{LOG_PREFIX} {sig_name} received — shutting down sniffer.")
    _running = False
    _release_lock()
    sys.exit(0)


signal.signal(signal.SIGINT,  _handle_shutdown)
signal.signal(signal.SIGTERM, _handle_shutdown)


if __name__ == "__main__":
    open(BUFFER_FILE, "w").close()
    _release_lock()

    print(f"{LOG_PREFIX} Windows IDS Sensor — starting up.")
    print(f"{LOG_PREFIX} Self-traffic filter: {LOCAL_IPS}")
    print(f"{LOG_PREFIX} Listening for inbound TCP packets on all ports (ALL interfaces)...")
    print(f"{LOG_PREFIX} Target port setting: {TARGET_PORT}")
    print(f"{LOG_PREFIX} Packet archive: {PACKET_LOG_FILE}")
    print(f"{LOG_PREFIX} Press Ctrl+C to stop.\n")

    try:
        sniff(
            filter="tcp",
            prn=packet_handler,
            store=False,
            stop_filter=lambda _: not _running,
            iface=None,       # ALL interfaces
        )
    except KeyboardInterrupt:
        _handle_shutdown(signal.SIGINT, None)
    except Exception as exc:
        print(f"{LOG_PREFIX} FATAL: Scapy error — {exc}")
        print(f"{LOG_PREFIX} Is Npcap installed? Is this CMD running as Administrator?")
        sys.exit(1)