import threading
import time
from typing import Optional

from .capture import CaptureWorker
from .config import SETTINGS
from .history import HistoryStore
from .network import InterfaceCandidate, discover_interfaces, elect_interface
from .state import LiveState


class ObservatoryService:
    def __init__(self):
        SETTINGS.data_dir.mkdir(parents=True, exist_ok=True)
        self.state = LiveState()
        self.history = HistoryStore(SETTINGS.history_db)
        self.capture = CaptureWorker(self.state)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._previous_rx: dict[str, int] = {}
        self._current_name: Optional[str] = None
        self._candidate: Optional[InterfaceCandidate] = None
        self._last_capture_restart = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._supervisor_loop, name="sensor-supervisor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self.capture.stop()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        if self.state.session:
            snapshot = self.state.end_session("STOPPED", "Observatory service stopped.")
            self.history.archive(snapshot)
        self._thread = None

    def _rotate_session(self, state: str, reason: str) -> None:
        self.capture.stop()
        if self.state.session:
            snapshot = self.state.end_session(state, reason)
            self.history.archive(snapshot)
        else:
            self.state.set_sensor_state(state, reason)
        self._candidate = None
        self._current_name = None

    def _begin_session(self, candidate: InterfaceCandidate, reason: str) -> None:
        self._candidate = candidate
        self._current_name = candidate.name
        self.state.start_session(candidate)
        self.state.set_sensor_state("SESSION_STARTING", reason)
        self.capture.start(candidate)
        self._last_capture_restart = time.time()

    def _supervisor_loop(self) -> None:
        while not self._stop.is_set():
            try:
                candidates, new_rx = discover_interfaces(self._previous_rx)
                self._previous_rx = new_rx
                selected = elect_interface(candidates, self._current_name)

                if selected is None:
                    if self.state.session:
                        self._rotate_session("NETWORK_DOWN", "No usable carrier+IPv4 interface is currently available.")
                    else:
                        self.state.set_sensor_state("NETWORK_DOWN", "No usable carrier+IPv4 interface is currently available.")
                    self.state.tick()
                    self._stop.wait(SETTINGS.supervisor_interval)
                    continue

                if not selected.ipv4 or selected.prefix_length is None or not selected.subnet or not selected.fingerprint:
                    if self.state.session:
                        self._rotate_session("ADDRESS_PENDING", f"{selected.name} does not have a complete usable IPv4 configuration.")
                    else:
                        self.state.set_sensor_state("ADDRESS_PENDING", f"{selected.name} does not have a complete usable IPv4 configuration.")
                    self.state.tick()
                    self._stop.wait(SETTINGS.supervisor_interval)
                    continue

                if self.state.session is None:
                    self._begin_session(
                        selected,
                        "Automatically selected a validated interface using carrier, IPv4 and route evidence.",
                    )
                elif self.state.session.fingerprint != selected.fingerprint:
                    old = self.state.session
                    self._rotate_session(
                        "SWITCHING_NETWORK",
                        f"Network fingerprint changed from {old.interface}/{old.subnet}; old live state was invalidated.",
                    )
                    self._begin_session(selected, "Started a fresh session after interface/address/route change.")
                else:
                    # Refresh selection metadata without changing session truth.
                    self._candidate = selected
                    self._current_name = selected.name

                    # Capture failures are recoverable in-process. The session is kept only
                    # when the network fingerprint itself remains valid; the live API still
                    # fails closed while capture health is bad.
                    if not self.capture.running:
                        health = self.state.capture_health.get("status")
                        if health in {"CAPTURE_ERROR", "CAPTURE_STALLED", "PARSER_DEGRADED", "NOT_RUNNING"}:
                            if time.time() - self._last_capture_restart >= 5.0:
                                self.state.set_sensor_state("SESSION_STARTING", "Restarting capture worker on the still-valid network session.")
                                self.capture.start(selected)
                                self._last_capture_restart = time.time()

                self.state.tick()

            except Exception as error:
                # Unknown supervisor failures fail closed and end the current live session.
                self._rotate_session("SUPERVISOR_ERROR", f"Supervisor failed closed: {type(error).__name__}: {error}")

            self._stop.wait(SETTINGS.supervisor_interval)
