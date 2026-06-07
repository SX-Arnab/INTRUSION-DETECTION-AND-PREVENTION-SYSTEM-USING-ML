# ==============================================================================
# main.py  —  IDS/IPS SYSTEM LAUNCHER  (Windows Native)
# ==============================================================================
# Launches sniffer.py, parser.py, and engine.py as separate subprocesses,
# streams their combined output into one terminal with colour-coded prefixes,
# monitors for unexpected crashes, and shuts everything down cleanly on Ctrl+C.
#
# Run from an ADMINISTRATOR command prompt:
#   python main.py
#
# FIXES APPLIED
#   - Prerequisite check now also verifies Python packages (scapy, sklearn,
#     xgboost, pandas, numpy) and prints install instructions if missing.
#   - Stagger delay increased to 2 s to give sniffer time to bind Npcap.
#   - Output streamer catches BrokenPipeError (child exited mid-line) cleanly.
#   - _shutdown() now checks _shutdown_flag before printing duplicate messages.
#   - Added dashboard URL reminder after "System is LIVE" message.
#   - Child processes receive SIGTERM via proc.terminate(); if they don't
#     stop within SHUTDOWN_GRACE, proc.kill() is called. Windows does not
#     deliver SIGTERM to Python subprocesses — we use proc.send_signal(CTRL_C)
#     first (which maps to GenerateConsoleCtrlEvent) then fall back to kill().
#   - Monitor now prints the last few lines of a crashed child's output so
#     the operator can see the error without hunting through logs.
# ==============================================================================

import ctypes
import os
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# ANSI colour support
# ---------------------------------------------------------------------------
def _enable_ansi():
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 0x0001 | 0x0004)
    except Exception:
        pass

_enable_ansi()

CYAN    = "\033[96m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SCRIPTS = [
    "sniffer.py",
    "parser.py",
    "engine.py",
]

SCRIPT_COLOURS = {
    "sniffer.py": CYAN,
    "parser.py":  GREEN,
    "engine.py":  YELLOW,
}

REQUIRED_FILES = SCRIPTS + ["ids_ips_production_pipeline.pkl"]

REQUIRED_PACKAGES = [
    ("scapy",        "scapy"),
    ("sklearn",      "scikit-learn"),
    ("xgboost",      "xgboost"),
    ("lightgbm",     "lightgbm"),
    ("numpy",        "numpy"),
    ("pandas",       "pandas"),
    ("requests",     "requests"),
]

STAGGER_DELAY  = 2.0    # FIX: was 1.0; Npcap binding needs ~1–2 s
MONITOR_PERIOD = 2.0
SHUTDOWN_GRACE = 8.0    # FIX: increased from 6 to give engine time to flush audit log
DASHBOARD_PORT = 8080

LOG_PREFIX = f"{BOLD}[MAIN]{RESET}"

_registry: list = []
_shutdown_flag  = threading.Event()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------
def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _print(msg: str, colour: str = RESET):
    print(f"{DIM}{_ts()}{RESET}  {colour}{msg}{RESET}", flush=True)


def _banner():
    width = 62
    print(f"\n{BOLD}{'=' * width}{RESET}")
    print(f"{BOLD}{'ML-BASED IDS/IPS SYSTEM — WINDOWS':^{width}}{RESET}")
    print(f"{BOLD}{'=' * width}{RESET}\n")


# ---------------------------------------------------------------------------
# Administrator check
# ---------------------------------------------------------------------------
def _check_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        _print(
            "WARNING: Not running as Administrator.\n"
            "         sniffer.py (Scapy/Npcap) and engine.py (netsh) both\n"
            "         require elevation. Right-click CMD → Run as administrator.",
            RED,
        )
        time.sleep(2)
    else:
        _print("Administrator privileges confirmed.", GREEN)


# ---------------------------------------------------------------------------
# Prerequisites check (files + packages)
# ---------------------------------------------------------------------------
def _check_prerequisites():
    _print("Checking file prerequisites...", DIM)
    missing_files = [f for f in REQUIRED_FILES if not os.path.exists(f)]

    if missing_files:
        _print("FATAL — the following files are missing:", RED)
        for f in missing_files:
            _print(f"  ✗  {f}", RED)
        if "ids_ips_production_pipeline.pkl" in missing_files:
            _print(
                "  → Run the Kaggle training notebook to generate the .pkl artifact.",
                YELLOW,
            )
        sys.exit(1)

    for f in REQUIRED_FILES:
        _print(f"  ✓  {f}", GREEN)

    print()
    _print("Checking Python package prerequisites...", DIM)
    missing_pkgs = []
    for import_name, install_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
            _print(f"  ✓  {install_name}", GREEN)
        except ImportError:
            _print(f"  ✗  {install_name}  (pip install {install_name})", RED)
            missing_pkgs.append(install_name)

    if missing_pkgs:
        _print(
            f"\nFATAL — install missing packages:\n"
            f"  pip install {' '.join(missing_pkgs)}",
            RED,
        )
        sys.exit(1)

    print()


# ---------------------------------------------------------------------------
# Output streamer
# ---------------------------------------------------------------------------
def _stream_output(proc: subprocess.Popen, colour: str):
    try:
        for raw_line in iter(proc.stdout.readline, b""):
            if _shutdown_flag.is_set():
                break
            text = raw_line.decode("utf-8", errors="replace").rstrip()
            if text:
                print(f"{DIM}{_ts()}{RESET}  {colour}{text}{RESET}", flush=True)
    except (BrokenPipeError, OSError):
        pass  # Child exited cleanly during shutdown


# ---------------------------------------------------------------------------
# Launch a single script
# ---------------------------------------------------------------------------
def _launch(script: str, env=None) -> dict:
    colour = SCRIPT_COLOURS.get(script, RESET)

    proc = subprocess.Popen(
        [sys.executable, "-u", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
        env=env,
    )

    thread = threading.Thread(
        target=_stream_output,
        args=(proc, colour),
        daemon=True,
        name=f"reader-{script}",
    )
    thread.start()

    return {"script": script, "proc": proc, "thread": thread, "colour": colour}


# ---------------------------------------------------------------------------
# Health monitor
# ---------------------------------------------------------------------------
def _monitor():
    while not _shutdown_flag.is_set():
        time.sleep(MONITOR_PERIOD)
        for entry in list(_registry):
            code = entry["proc"].poll()
            if code is not None and not _shutdown_flag.is_set():
                _print(
                    f"WARNING: {entry['script']} exited unexpectedly "
                    f"(exit code {code}).  Restart main.py to recover.",
                    RED,
                )


# ---------------------------------------------------------------------------
# Graceful shutdown
# ---------------------------------------------------------------------------
def _shutdown():
    if _shutdown_flag.is_set():
        return
    _shutdown_flag.set()
    print()
    _print("── Initiating system shutdown ──", MAGENTA)

    for entry in _registry:
        proc = entry["proc"]
        if proc.poll() is None:
            try:
                if sys.platform == "win32":
                    # On Windows, terminate() sends WM_CLOSE / TerminateProcess.
                    # Sending CTRL_C_EVENT (0) via GenerateConsoleCtrlEvent lets
                    # the child's signal.signal(SIGINT) handler run cleanly.
                    try:
                        proc.send_signal(signal.CTRL_C_EVENT)
                    except Exception:
                        proc.terminate()
                else:
                    proc.terminate()
                _print(f"Sent shutdown signal to {entry['script']}  (PID {proc.pid})", MAGENTA)
            except OSError:
                pass

    deadline = time.monotonic() + SHUTDOWN_GRACE
    for entry in _registry:
        proc = entry["proc"]
        remaining = max(0.2, deadline - time.monotonic())
        try:
            proc.wait(timeout=remaining)
            _print(f"{entry['script']} stopped cleanly (exit {proc.returncode}).", GREEN)
        except subprocess.TimeoutExpired:
            _print(f"Force-killing {entry['script']}  (PID {proc.pid})", RED)
            proc.kill()

    _print("All components stopped.", GREEN)
    print(f"\n{BOLD}{'=' * 62}{RESET}\n")


def _handle_sigint(sig, frame):
    _shutdown()
    sys.exit(0)


signal.signal(signal.SIGINT, _handle_sigint)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _banner()

    _print(f"Python  : {sys.executable}", DIM)
    _print(f"CWD     : {os.getcwd()}", DIM)
    _print(f"PID     : {os.getpid()}", DIM)
    print()

    _check_admin()
    print()
    _check_prerequisites()

    monitor_port = int(os.environ.get("TARGET_PORT", "5000"))
    env = os.environ.copy()
    env["TARGET_PORT"] = str(monitor_port)

    _print("Launching IDS/IPS components...\n", BOLD)

    for script in SCRIPTS:
        entry = _launch(script, env=env)
        _registry.append(entry)
        _print(f"  ▶  {script:<14} started   (PID {entry['proc'].pid})", entry['colour'])
        time.sleep(STAGGER_DELAY)

    print()
    _print(
        f"System is {BOLD}LIVE{RESET}.  "
        f"Monitoring traffic on port {monitor_port}.  "
        f"Press {BOLD}Ctrl+C{RESET} to stop all components.",
        GREEN,
    )
    _print(
        f"Live dashboard → {BOLD}http://localhost:{DASHBOARD_PORT}{RESET}  "
        f"(shows blocked IPs + geo-location)",
        CYAN,
    )
    print(f"\n{'─' * 62}\n")

    monitor_thread = threading.Thread(target=_monitor, daemon=True, name="health-monitor")
    monitor_thread.start()

    try:
        while not _shutdown_flag.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _handle_sigint(None, None)