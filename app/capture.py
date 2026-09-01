import os
import select
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


class CaptureWorker:
    def __init__(self, state: LiveState):
        self.state = state
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._process: Optional[subprocess.Popen] = None
        self._candidate: Optional[InterfaceCandidate] = None
        self._parsed = 0
        self._rejected = 0
        self._bytes = 0
        self._last_packet_at: Optional[float] = None
        self._last_os_rx: Optional[int] = None

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
        self._thread = None
        self._process = None

    def _read_os_rx(self) -> Optional[int]:
        if not self._candidate:
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
            backend="TCPDUMP_PCAP_BINARY",
        )

    def _run(self) -> None:
        tcpdump = shutil.which("tcpdump")
        if not tcpdump:
            self._publish_health("CAPTURE_ERROR", "tcpdump is not installed or not in PATH.")
            return
        assert self._candidate is not None

        command = [
            tcpdump,
            "-U",
            "-n",
            "-i",
            self._candidate.name,
            "-s",
            "0",
            "-w",
            "-",
            "ip or arp",
        ]
        try:
            self._process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                bufsize=0,
            )
        except OSError as error:
            self._publish_health("CAPTURE_ERROR", f"Unable to start tcpdump: {error}")
            return

        if self._process.stdout is None:
            self._publish_health("CAPTURE_ERROR", "tcpdump stdout is unavailable.")
            return

        reader = PcapStreamReader()
        self._publish_health("LINK_UP_IDLE", "Capture started; waiting for qualifying IPv4/ARP traffic.")
        last_health = 0.0

        while not self._stop.is_set():
            if self._process.poll() is not None:
                self._publish_health("CAPTURE_ERROR", "tcpdump exited unexpectedly. Check capture permissions.")
                return

            try:
                ready, _, _ = select.select([self._process.stdout], [], [], 0.5)
            except (ValueError, OSError) as error:
                self._publish_health("CAPTURE_ERROR", f"Capture stream error: {error}")
                return

            if ready:
                try:
                    chunk = os.read(self._process.stdout.fileno(), 65536)
                except OSError as error:
                    self._publish_health("CAPTURE_ERROR", f"Capture read failed: {error}")
                    return
                if not chunk:
                    self._publish_health("CAPTURE_ERROR", "tcpdump capture stream closed.")
                    return

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
                    # The OS RX counter covers all layer-2 traffic, while Stage 1
                    # deliberately captures only IPv4/ARP. A rising RX counter
                    # therefore cannot prove the filtered capture is stalled; it
                    # may simply be IPv6 or other traffic. Do not manufacture a
                    # CAPTURE_STALLED state from incomparable counters.
                    status = "LINK_UP_IDLE"
                    reason = "Capture process is healthy but no recent qualifying IPv4/ARP packet was observed. Other layer-2 traffic may still be present."

                self._publish_health(status, reason)
                last_health = current

        self._publish_health("NOT_RUNNING", "Capture worker stopped.")
