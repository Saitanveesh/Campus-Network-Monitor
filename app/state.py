import ipaddress
import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass
from typing import Optional

from .config import SETTINGS
from .network import InterfaceCandidate
from .pcap import ParsedPacket, valid_unicast_mac


LOCAL_CLASSES = {"SENSOR", "INFRASTRUCTURE", "LOCAL_SUBNET_ENDPOINT"}


@dataclass
class Session:
    session_id: str
    started_at: float
    interface: str
    interface_mac: Optional[str]
    sensor_ip: str
    prefix_length: int
    subnet: str
    gateway: Optional[str]
    fingerprint: str


class LiveState:
    """Thread-safe current-session state.

    No method in this class reads history. A session rotation clears every live
    entity before a new session is exposed.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self.session: Optional[Session] = None
        self.sensor_state = "NETWORK_DOWN"
        self.sensor_reason = "No validated network session."
        self.capture_health = {
            "status": "NOT_RUNNING",
            "reason": "Capture has not started.",
            "heartbeat": None,
            "last_packet_at": None,
            "parsed_packets": 0,
            "rejected_packets": 0,
            "captured_bytes": 0,
            "os_rx_packets": None,
            "os_rx_delta": 0,
            "parser_error_rate": 0.0,
            "backend": None,
        }
        self.endpoints: dict[str, dict] = {}
        self.flows: dict[str, dict] = {}
        self.arp: dict[tuple[str, str], dict] = {}
        self.packets = deque(maxlen=SETTINGS.packet_ring_size)
        self.traffic_samples = deque(maxlen=1200)
        self._event_id = 0
        self._sample_started = time.time()
        self._sample_packets = 0
        self._sample_bytes = 0

    def start_session(self, candidate: InterfaceCandidate) -> Session:
        assert candidate.ipv4 and candidate.prefix_length is not None and candidate.subnet and candidate.fingerprint
        with self._lock:
            self._clear_live_locked()
            self.session = Session(
                session_id=str(uuid.uuid4()),
                started_at=time.time(),
                interface=candidate.name,
                interface_mac=candidate.mac,
                sensor_ip=candidate.ipv4,
                prefix_length=candidate.prefix_length,
                subnet=candidate.subnet,
                gateway=candidate.gateway,
                fingerprint=candidate.fingerprint,
            )
            self.sensor_state = "SESSION_STARTING"
            self.sensor_reason = "Validated network selected; capture is starting."
            self.capture_health = {
                "status": "STARTING",
                "reason": "Capture worker is starting.",
                "heartbeat": time.time(),
                "last_packet_at": None,
                "parsed_packets": 0,
                "rejected_packets": 0,
                "captured_bytes": 0,
                "os_rx_packets": candidate.rx_packets,
                "os_rx_delta": 0,
                "parser_error_rate": 0.0,
                "backend": "TCPDUMP_PCAP_BINARY",
            }
            return Session(**asdict(self.session))

    def end_session(self, state: str, reason: str) -> Optional[dict]:
        with self._lock:
            snapshot = self.history_snapshot_locked() if self.session else None
            self.session = None
            self._clear_live_locked()
            self.sensor_state = state
            self.sensor_reason = reason
            self.capture_health.update(
                status="NOT_RUNNING",
                reason=reason,
                heartbeat=time.time(),
                last_packet_at=None,
            )
            return snapshot

    def set_sensor_state(self, state: str, reason: str) -> None:
        with self._lock:
            self.sensor_state = state
            self.sensor_reason = reason

    def update_capture_health(self, **values) -> None:
        with self._lock:
            self.capture_health.update(values)
            self.capture_health["heartbeat"] = time.time()
            total = int(self.capture_health.get("parsed_packets", 0)) + int(self.capture_health.get("rejected_packets", 0))
            self.capture_health["parser_error_rate"] = (
                int(self.capture_health.get("rejected_packets", 0)) / total if total else 0.0
            )
            status = self.capture_health.get("status")
            if status in {"CAPTURE_ACTIVE", "LINK_UP_IDLE"}:
                self.sensor_state = status
                self.sensor_reason = self.capture_health.get("reason", "")
            elif status in {"CAPTURE_ERROR", "CAPTURE_STALLED", "PARSER_DEGRADED"}:
                self.sensor_state = status
                self.sensor_reason = self.capture_health.get("reason", "")

    def classify_ip(self, ip_text: str) -> str:
        with self._lock:
            return self._classify_ip_locked(ip_text)

    def _classify_ip_locked(self, ip_text: str) -> str:
        if not self.session:
            return "INVALID"
        try:
            ip = ipaddress.ip_address(ip_text)
            network = ipaddress.ip_network(self.session.subnet, strict=False)
        except ValueError:
            return "INVALID"
        if ip.version != 4:
            return "SPECIAL_ADDRESS"
        if ip_text == self.session.sensor_ip:
            return "SENSOR"
        if self.session.gateway and ip_text == self.session.gateway:
            return "INFRASTRUCTURE"
        if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
            return "SPECIAL_ADDRESS"
        if ip.is_multicast:
            return "MULTICAST"
        if ip == ipaddress.IPv4Address("255.255.255.255") or ip == network.broadcast_address:
            return "BROADCAST"
        if ip in network:
            return "LOCAL_SUBNET_ENDPOINT"
        if ip.is_private:
            return "PRIVATE_OFF_SUBNET_PEER"
        if ip.is_global:
            return "PUBLIC_PEER"
        return "SPECIAL_ADDRESS"

    def ingest(self, packet: ParsedPacket) -> bool:
        with self._lock:
            if not self.session:
                return False

            if packet.protocol == "ARP":
                return self._ingest_arp_locked(packet)

            if not packet.source_ip or not packet.destination_ip:
                return False

            source_class = self._classify_ip_locked(packet.source_ip)
            destination_class = self._classify_ip_locked(packet.destination_ip)
            if "INVALID" in {source_class, destination_class}:
                return False

            # Endpoint inventory is source-evidence only. A destination IP is
            # never promoted to a local device merely because it was addressed.
            if source_class in LOCAL_CLASSES and valid_unicast_mac(packet.source_mac):
                self._upsert_endpoint_locked(
                    packet.source_ip,
                    packet.source_mac,
                    source_class,
                    "IPV4_SOURCE_FRAME",
                    packet.timestamp,
                    packet.frame_bytes,
                )

            traffic_type = self._traffic_type(source_class, destination_class)
            flow_key = "|".join(
                [
                    packet.source_ip,
                    packet.destination_ip,
                    packet.protocol or "",
                    str(packet.source_port),
                    str(packet.destination_port),
                ]
            )
            flow = self.flows.get(flow_key)
            if flow is None:
                flow = {
                    "flow_id": flow_key,
                    "source_ip": packet.source_ip,
                    "destination_ip": packet.destination_ip,
                    "protocol": packet.protocol,
                    "source_port": packet.source_port,
                    "destination_port": packet.destination_port,
                    "source_class": source_class,
                    "destination_class": destination_class,
                    "traffic_type": traffic_type,
                    "tcp_flags": packet.tcp_flags,
                    "first_seen": packet.timestamp,
                    "last_seen": packet.timestamp,
                    "packets": 0,
                    "bytes": 0,
                }
                self.flows[flow_key] = flow
            flow["last_seen"] = packet.timestamp
            flow["packets"] += 1
            flow["bytes"] += packet.frame_bytes
            if packet.tcp_flags:
                flow["tcp_flags"] = packet.tcp_flags

            self._event_id += 1
            self.packets.append(
                {
                    "id": self._event_id,
                    "session_id": self.session.session_id,
                    "timestamp": packet.timestamp,
                    "source_ip": packet.source_ip,
                    "destination_ip": packet.destination_ip,
                    "source_mac": packet.source_mac,
                    "destination_mac": packet.destination_mac,
                    "source_port": packet.source_port,
                    "destination_port": packet.destination_port,
                    "protocol": packet.protocol,
                    "tcp_flags": packet.tcp_flags,
                    "source_class": source_class,
                    "destination_class": destination_class,
                    "traffic_type": traffic_type,
                    "frame_bytes": packet.frame_bytes,
                    "vlan_ids": list(packet.vlan_ids),
                    "evidence": "OBSERVED_IPV4_FRAME",
                }
            )
            self._count_sample_locked(packet.frame_bytes)
            self._prune_locked(packet.timestamp)
            return True

    def _ingest_arp_locked(self, packet: ParsedPacket) -> bool:
        if not packet.arp_sender_ip or not packet.arp_sender_mac:
            return False
        # Defend against inconsistent ARP claims at the parser boundary.
        if packet.arp_sender_mac.lower() != packet.source_mac.lower():
            return False
        if not valid_unicast_mac(packet.arp_sender_mac):
            return False
        classification = self._classify_ip_locked(packet.arp_sender_ip)
        if classification not in LOCAL_CLASSES:
            return True

        key = (packet.arp_sender_ip, packet.arp_sender_mac)
        row = self.arp.get(key)
        if row is None:
            row = {
                "ip": packet.arp_sender_ip,
                "mac": packet.arp_sender_mac,
                "first_seen": packet.timestamp,
                "last_seen": packet.timestamp,
                "observations": 0,
            }
            self.arp[key] = row
        row["last_seen"] = packet.timestamp
        row["observations"] += 1
        self._upsert_endpoint_locked(
            packet.arp_sender_ip,
            packet.arp_sender_mac,
            classification,
            "ARP_SENDER",
            packet.timestamp,
            0,
        )
        self._count_sample_locked(packet.frame_bytes)
        self._prune_locked(packet.timestamp)
        return True

    def _upsert_endpoint_locked(self, ip: str, mac: str, classification: str, evidence: str, ts: float, frame_bytes: int) -> None:
        row = self.endpoints.get(ip)
        if row is None:
            row = {
                "ip": ip,
                "mac": mac,
                "classification": classification,
                "evidence_type": evidence,
                "first_seen": ts,
                "last_seen": ts,
                "packets": 0,
                "bytes": 0,
            }
            self.endpoints[ip] = row
        row.update(mac=mac, classification=classification, evidence_type=evidence, last_seen=ts)
        row["packets"] += 1
        row["bytes"] += frame_bytes

    @staticmethod
    def _traffic_type(source_class: str, destination_class: str) -> str:
        if "MULTICAST" in {source_class, destination_class}:
            return "MULTICAST"
        if "BROADCAST" in {source_class, destination_class}:
            return "BROADCAST"
        source_local = source_class in LOCAL_CLASSES
        destination_local = destination_class in LOCAL_CLASSES
        if source_local and destination_local:
            return "INTERNAL_INTERNAL"
        if source_local and not destination_local:
            return "INTERNAL_EXTERNAL"
        if not source_local and destination_local:
            return "EXTERNAL_INTERNAL"
        return "OTHER"

    def _count_sample_locked(self, frame_bytes: int) -> None:
        self._sample_packets += 1
        self._sample_bytes += frame_bytes
        current = time.time()
        interval = current - self._sample_started
        if interval >= SETTINGS.traffic_sample_interval:
            self.traffic_samples.append(
                {
                    "timestamp": current,
                    "interval_seconds": interval,
                    "packets": self._sample_packets,
                    "bytes": self._sample_bytes,
                    "packets_per_second": self._sample_packets / max(interval, 0.001),
                    "bytes_per_second": self._sample_bytes / max(interval, 0.001),
                }
            )
            self._sample_started = current
            self._sample_packets = 0
            self._sample_bytes = 0

    def tick(self) -> None:
        with self._lock:
            self._prune_locked(time.time())
            # Generate explicit zero samples on a valid but idle link.
            current = time.time()
            interval = current - self._sample_started
            if self.session and interval >= SETTINGS.traffic_sample_interval:
                self.traffic_samples.append(
                    {
                        "timestamp": current,
                        "interval_seconds": interval,
                        "packets": self._sample_packets,
                        "bytes": self._sample_bytes,
                        "packets_per_second": self._sample_packets / max(interval, 0.001),
                        "bytes_per_second": self._sample_bytes / max(interval, 0.001),
                    }
                )
                self._sample_started = current
                self._sample_packets = 0
                self._sample_bytes = 0

    def _prune_locked(self, current: float) -> None:
        endpoint_cutoff = current - SETTINGS.endpoint_ttl
        flow_cutoff = current - SETTINGS.flow_ttl
        packet_cutoff = current - SETTINGS.packet_ttl
        self.endpoints = {ip: row for ip, row in self.endpoints.items() if row["last_seen"] >= endpoint_cutoff}
        self.flows = {key: row for key, row in self.flows.items() if row["last_seen"] >= flow_cutoff}
        self.arp = {key: row for key, row in self.arp.items() if row["last_seen"] >= endpoint_cutoff}
        while self.packets and self.packets[0]["timestamp"] < packet_cutoff:
            self.packets.popleft()

    def _clear_live_locked(self) -> None:
        self.endpoints.clear()
        self.flows.clear()
        self.arp.clear()
        self.packets.clear()
        self.traffic_samples.clear()
        self._event_id = 0
        self._sample_started = time.time()
        self._sample_packets = 0
        self._sample_bytes = 0

    def status_snapshot(self) -> dict:
        with self._lock:
            session = asdict(self.session) if self.session else None
            health = dict(self.capture_health)
            live_ok = bool(
                session
                and self.sensor_state in {"CAPTURE_ACTIVE", "LINK_UP_IDLE"}
                and health.get("status") in {"CAPTURE_ACTIVE", "LINK_UP_IDLE"}
            )
            return {
                "timestamp": time.time(),
                "state": self.sensor_state,
                "reason": self.sensor_reason,
                "live_data_available": live_ok,
                "session": session,
                "capture": health,
            }

    def live_snapshot(self) -> dict:
        with self._lock:
            status = self.status_snapshot()
            if not status["live_data_available"]:
                return {
                    "status": status,
                    "endpoints": [],
                    "flows": [],
                    "arp": [],
                    "packets": [],
                    "traffic": [],
                }
            return {
                "status": status,
                "endpoints": sorted((dict(row) for row in self.endpoints.values()), key=lambda row: row["last_seen"], reverse=True),
                "flows": sorted((dict(row) for row in self.flows.values()), key=lambda row: row["last_seen"], reverse=True),
                "arp": sorted((dict(row) for row in self.arp.values()), key=lambda row: row["last_seen"], reverse=True),
                "packets": [dict(row) for row in self.packets],
                "traffic": [dict(row) for row in self.traffic_samples],
            }

    def history_snapshot_locked(self) -> dict:
        return {
            "session": asdict(self.session) if self.session else None,
            "ended_at": time.time(),
            "end_state": self.sensor_state,
            "end_reason": self.sensor_reason,
            "endpoints": [dict(row) for row in self.endpoints.values()],
            "flows": [dict(row) for row in self.flows.values()],
        }
