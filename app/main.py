import shutil
import signal
import subprocess
import sys
import threading
import time

from .config import SETTINGS
from .server import run_server
from .service import ObservatoryService


def _capture_preflight() -> tuple[bool, str]:
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return False, "tcpdump is not installed. Install it before starting the observatory."

    getcap = shutil.which("getcap")
    if getcap:
        result = subprocess.run([getcap, tcpdump], capture_output=True, text=True, check=False)
        capabilities = result.stdout.strip()
        if "cap_net_raw" not in capabilities:
            return (
                False,
                "tcpdump lacks CAP_NET_RAW. Run: sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f \"$(which tcpdump)\")\"",
            )
    return True, "capture preflight passed"


def main() -> int:
    SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
    ok, message = _capture_preflight()
    if not ok:
        print(f"PRE-FLIGHT FAILED: {message}")
        return 2

    service = ObservatoryService()
    service.start()
    stop = threading.Event()

    def handle_signal(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    server_thread = threading.Thread(target=run_server, args=(service,), name="observatory-http", daemon=True)
    server_thread.start()

    print()
    print("Campus Network Observatory")
    print("--------------------------")
    print("Architecture : single-process session-safe Stage-1 foundation")
    print("Interface    : automatic")
    print("Capture      : passive IPv4/ARP binary PCAP")
    print("Live state   : memory only; current session only")
    print(f"History      : {SETTINGS.history_db}")
    print(f"Dashboard    : http://{SETTINGS.host}:{SETTINGS.port}/")
    print(f"Topology     : http://{SETTINGS.host}:{SETTINGS.port}/topology.html")
    print()
    print("Ctrl+C to stop")
    print()

    try:
        while not stop.wait(1.0):
            status = service.state.status_snapshot()
            session = status.get("session") or {}
            print(
                f"\r{status['state']:<18} "
                f"if={session.get('interface','-'):<8} "
                f"ip={session.get('sensor_ip','-'):<16} "
                f"session={session.get('session_id','-')[:8] if session.get('session_id') else '-':<8}",
                end="",
                flush=True,
            )
    finally:
        print()
        service.stop()
        print("Observatory stopped cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
