import os
import platform
import queue
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from .config import SETTINGS
from .network import InterfaceCandidate
from .pcap import PcapStreamReader, parse_ethernet_packet
from .state import LiveState


def find_tshark() -> Optional[str]:
    discovered = shutil.which("tshark") or shutil.which("tshark.exe")
    if discovered:
        return discovered

    if platform.system().lower() == "windows":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Wireshark" / "tshark.exe",
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Wireshark" / "tshark.exe",
        ]
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)
    return None


def capture_backend() -> tuple[Optional[str], Optional[str]]:
    system = platform.system().lower()
    if system == "windows":
        tshark = find_tshark()
        return ("TSHARK_NPCAP_PCAP", tshark) if tshark else (None, None)
    if system == "linux":
        tcpdump = shutil.which("tcpdump")
        return ("TCPDUMP_PCAP_BINARY", tcpdump) if tcpdump else (None, None)
    return None, None


class CaptureWorker:
    def __init__(self, state: LiveState):
        self.state = state
        self._thread: Optional[threading.Thread] = None
        self._reader_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._process: Optional[subprocess.Popen] = None
        self._candidate: Optional[InterfaceCandidate] = None
        self._parsed = 0
        self._rejected = 0
        self._bytes = 0
        self._last_packet_at: Optional[float] = None
        self._last_os_rx: Optional[int] = None
        self._backend_name = "NOT_CONFIGURED"

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, candidate: InterfaceCandidate) -> None:
        self.stop()
        self._candidate = candidate
        self._stop = threading.Event()
        self._parsed = 0
        self._rejected = 0
        self._bytes = 0
        self._last_packet_at = None
        self._last_os_rx = candidate.rx_packets
        self._backend_name = "NOT_CONFIGURED"
        self._thread = threading.Thread(target=self._run, name="capture-worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=2)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        if self._reader_thread and self._reader_thread.is_alive():
            self._reader_thread.join(timeout=1)
        self._thread = None
        self._reader_thread = None
        self._process = None

    def _read_os_rx(self) -> Optional[int]:
        if not self._candidate:
            return None
        if platform.system().lower() != "linux":
            # Windows adapter counters are refreshed by the supervisor. Capture
            # health does not compare those sampled counters against filtered
            # IPv4/ARP packet timestamps because the quantities are not equivalent.
            return None
        try:
            path = Path("/sys/class/net") / self._candidate.name / "statistics" / "rx_packets"
            return int(path.read_text().strip())
        except (OSError, ValueError):
            return None

    def _publish_health(self, status: str, reason: str) -> None:
        current_rx = self._read_os_rx()
        rx_delta = 0
        if current_rx is not None and self._last_os_rx is not None:
            rx_delta = max(0, current_rx - self._last_os_rx)
        if current_rx is not None:
            self._last_os_rx = current_rx
        self.state.update_capture_health(
            status=status,
            reason=reason,
            last_packet_at=self._last_packet_at,
            parsed_packets=self._parsed,
            rejected_packets=self._rejected,
            captured_bytes=self._bytes,
            os_rx_packets=current_rx,
            os_rx_delta=rx_delta,
            backend=self._backend_name,
        )

    def _command(self) -> Optional[list[str]]:
        assert self._candidate is not None
        backend, executable = capture_backend()
        if not backend or not executable:
            return None

        self._backend_name = backend
        capture_device = self._candidate.capture_device or self._candidate.name

        if backend == "TSHARK_NPCAP_PCAP":
            return [
                executable,
                "-n",
                "-i",
                capture_device,
                "-f",
                "ip or arp",
                "-s",
                "0",
                "-F",
                "pcap",
                "-w",
                "-",
            ]

        return [
            executable,
            "-U",
            "-n",
            "-i",
            capture_device,
            "-s",
            "0",
            "-w",
            "-",
            "ip or arp",
        ]

    def _run(self) -> None:
        assert self._candidate is not None
        command = self._command()
        if command is None:
            if platform.system().lower() == "windows":
                self._publish_health(
                    "CAPTURE_ERROR",
                    "TShark/Wireshark with Npcap is not available. Install Wireshark with Npcap enabled.",
                )
            else:
                self._publish_health("CAPTURE_ERROR", "tcpdump is not installed or not in PATH.")
            return

        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
        except OSError as error:
            self._publish_health("CAPTURE_ERROR", f"Unable to start packet capture: {error}")
            return

        if self._process.stdout is None:
            self._publish_health("CAPTURE_ERROR", "Capture stdout is unavailable.")
            return

        chunks: queue.Queue[Optional[bytes]] = queue.Queue(maxsize=64)

        def reader_loop() -> None:
            try:
                while not self._stop.is_set():
                    chunk = os.read(self._process.stdout.fileno(), 65536)
                    if not chunk:
                        break
                    try:
                        chunks.put(chunk, timeout=1)
                    except queue.Full:
                        self._publish_health("CAPTURE_ERROR", "Capture reader queue overflowed; failing closed.")
                        break
            except OSError:
                pass
            finally:
                try:
                    chunks.put(None, timeout=0.2)
                except queue.Full:
                    pass

        self._reader_thread = threading.Thread(target=reader_loop, name="capture-pipe-reader", daemon=True)
        self._reader_thread.start()

        reader = PcapStreamReader()
        self._publish_health("LINK_UP_IDLE", "Capture started; waiting for qualifying IPv4/ARP traffic.")
        last_health = 0.0

        while not self._stop.is_set():
            if self._process.poll() is not None and chunks.empty():
                self._publish_health(
                    "CAPTURE_ERROR",
                    "Capture process exited unexpectedly. On Windows, run PowerShell as Administrator and verify Npcap; on Linux, check capture permissions.",
                )
                return

            chunk: Optional[bytes]
            try:
                chunk = chunks.get(timeout=0.5)
            except queue.Empty:
                chunk = b""

            if chunk is None:
                if not self._stop.is_set():
                    self._publish_health("CAPTURE_ERROR", "Capture stream closed unexpectedly.")
                return

            if chunk:
                try:
                    reader.feed(chunk)
                    records = reader.parse_available()
                    if reader.linktype is not None and reader.linktype != 1:
                        self._publish_health(
                            "CAPTURE_ERROR",
                            f"Unsupported link type {reader.linktype}; Ethernet link type 1 is required for Stage 1.",
                        )
                        return
                    for packet_timestamp, frame, original_length in records:
                        parsed = parse_ethernet_packet(packet_timestamp, frame, original_length)
                        if parsed is None:
                            self._rejected += 1
                            continue
                        accepted = self.state.ingest(parsed)
                        if accepted:
                            self._parsed += 1
                            self._bytes += original_length
                            self._last_packet_at = packet_timestamp
                        else:
                            self._rejected += 1
                except Exception as error:
                    self._publish_health("PARSER_DEGRADED", f"Packet parser failed closed: {error}")
                    return

            current = time.time()
            if current - last_health >= 2.0:
                packet_age = None if self._last_packet_at is None else current - self._last_packet_at
                if packet_age is not None and packet_age <= SETTINGS.capture_idle_seconds:
                    status = "CAPTURE_ACTIVE"
                    reason = "Current-session IPv4/ARP packets are actively being parsed."
                else:
                    status = "LINK_UP_IDLE"
                    reason = (
                        "Capture process is healthy but no recent qualifying IPv4/ARP packet was observed. "
                        "Other layer-2 traffic may still be present."
                    )
                self._publish_health(status, reason)
                last_health = current

        self._publish_health("NOT_RUNNING", "Capture worker stopped.")
