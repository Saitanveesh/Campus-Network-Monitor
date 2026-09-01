import platform
import shutil
import signal
import subprocess
import sys
import threading

from .capture import capture_backend
from .config import SETTINGS
from .server import run_server
from .service import ObservatoryService


def _capture_preflight() -> tuple[bool, str]:
    system = platform.system().lower()
    backend, executable = capture_backend()

    if system == "windows":
        if backend != "TSHARK_NPCAP_PCAP" or not executable:
            return (
                False,
                "Windows capture requires Wireshark/TShark with Npcap. Install with: winget install --id WiresharkFoundation.Wireshark -e ; during setup keep Npcap enabled, then reopen PowerShell.",
            )
        try:
            result = subprocess.run(
                [executable, "-D"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
        except OSError as error:
            return False, f"Unable to execute TShark: {error}"
        if result.returncode != 0 or not result.stdout.strip():
            return (
                False,
                "TShark is installed but no Npcap capture interfaces are available. Repair/reinstall Wireshark with Npcap and, if Npcap is administrator-only, run PowerShell as Administrator.",
            )
        return True, f"Windows capture preflight passed ({executable})."

    if system == "linux":
        if backend != "TCPDUMP_PCAP_BINARY" or not executable:
            return False, "tcpdump is not installed. Install it before starting the observatory."

        getcap = shutil.which("getcap")
        if getcap:
            result = subprocess.run([getcap, executable], capture_output=True, text=True, check=False)
            capabilities = result.stdout.strip()
            if "cap_net_raw" not in capabilities:
                return (
                    False,
                    "tcpdump lacks CAP_NET_RAW. Run: sudo setcap cap_net_raw,cap_net_admin=eip \"$(readlink -f \"$(which tcpdump)\")\"",
                )
        return True, "Linux capture preflight passed."

    return False, f"Unsupported operating system for Stage 1: {platform.system()}"


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
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_signal)

    server_thread = threading.Thread(target=run_server, args=(service,), name="observatory-http", daemon=True)
    server_thread.start()

    backend, _ = capture_backend()

    print()
    print("Campus Network Observatory")
    print("--------------------------")
    print("Architecture : single-process session-safe Stage-1 foundation")
    print(f"Platform     : {platform.system()}")
    print("Interface    : automatic")
    print(f"Capture      : {backend or 'unavailable'}")
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
            session_id = session.get("session_id")
            print(
                f"\r{status['state']:<18} "
                f"if={session.get('interface','-'):<20} "
                f"ip={session.get('sensor_ip','-'):<16} "
                f"session={session_id[:8] if session_id else '-':<8}",
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
