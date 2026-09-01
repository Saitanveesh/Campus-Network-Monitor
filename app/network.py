import hashlib
import ipaddress
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


EXCLUDED_PREFIXES = ("lo", "docker", "veth", "virbr", "br-")
DEPRIORITIZED_PREFIXES = ("tun", "tap", "wg", "tailscale", "zt", "ham")


@dataclass(frozen=True)
class InterfaceCandidate:
    name: str
    mac: Optional[str]
    carrier: bool
    operstate: str
    ipv4: Optional[str]
    prefix_length: Optional[int]
    subnet: Optional[str]
    gateway: Optional[str]
    route_metric: Optional[int]
    rx_packets: int
    tx_packets: int
    score: int
    reasons: tuple[str, ...]

    @property
    def usable(self) -> bool:
        return bool(self.carrier and self.ipv4 and self.prefix_length is not None)

    @property
    def fingerprint(self) -> Optional[str]:
        if not self.usable:
            return None
        material = "|".join(
            [
                self.name,
                self.mac or "",
                self.ipv4 or "",
                str(self.prefix_length),
                self.subnet or "",
                self.gateway or "",
            ]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _run_json(args: List[str]):
    result = subprocess.run(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=3,
        check=False,
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def _read_int(path: Path) -> int:
    try:
        return int(path.read_text().strip())
    except (OSError, ValueError):
        return 0


def _read_text(path: Path, default: str = "unknown") -> str:
    try:
        return path.read_text().strip()
    except OSError:
        return default


def _valid_primary_ipv4(items) -> tuple[Optional[str], Optional[int]]:
    for item in items:
        if item.get("family") != "inet":
            continue
        address = item.get("local")
        prefix = item.get("prefixlen")
        if address is None or prefix is None:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
            continue
        return str(ip), int(prefix)
    return None, None


def _subnet(ipv4: Optional[str], prefix: Optional[int]) -> Optional[str]:
    if not ipv4 or prefix is None:
        return None
    try:
        return str(ipaddress.ip_interface(f"{ipv4}/{prefix}").network)
    except ValueError:
        return None


def discover_interfaces(previous_rx: Optional[Dict[str, int]] = None) -> tuple[list[InterfaceCandidate], Dict[str, int]]:
    previous_rx = previous_rx or {}
    links = {row.get("ifname"): row for row in _run_json(["ip", "-j", "link", "show"]) if row.get("ifname")}
    addr_rows = _run_json(["ip", "-j", "-4", "addr", "show"])
    addresses = {row.get("ifname"): row.get("addr_info", []) for row in addr_rows if row.get("ifname")}
    routes = _run_json(["ip", "-j", "route", "show", "default"])

    route_by_if: Dict[str, dict] = {}
    for route in routes:
        name = route.get("dev")
        if not name:
            continue
        metric = int(route.get("metric", 0) or 0)
        current = route_by_if.get(name)
        if current is None or metric < int(current.get("metric", 0) or 0):
            route_by_if[name] = route

    candidates: list[InterfaceCandidate] = []
    new_rx: Dict[str, int] = {}

    for name, link in links.items():
        if any(name.startswith(prefix) for prefix in EXCLUDED_PREFIXES):
            continue

        sys_path = Path("/sys/class/net") / name
        carrier = _read_int(sys_path / "carrier") == 1
        operstate = _read_text(sys_path / "operstate")
        rx_packets = _read_int(sys_path / "statistics" / "rx_packets")
        tx_packets = _read_int(sys_path / "statistics" / "tx_packets")
        new_rx[name] = rx_packets
        rx_delta = max(0, rx_packets - previous_rx.get(name, rx_packets))

        ipv4, prefix = _valid_primary_ipv4(addresses.get(name, []))
        route = route_by_if.get(name)
        gateway = route.get("gateway") if route else None
        metric = int(route.get("metric", 0) or 0) if route else None

        score = 0
        reasons: list[str] = []
        if carrier:
            score += 40
            reasons.append("CARRIER_UP")
        if operstate in {"up", "unknown"}:
            score += 10
            reasons.append("OPERSTATE_UP")
        if ipv4:
            score += 25
            reasons.append("USABLE_IPV4")
        if route:
            score += 50
            reasons.append("DEFAULT_ROUTE")
        if rx_delta > 0:
            score += 5
            reasons.append("RX_ACTIVITY")
        if any(name.startswith(prefix) for prefix in DEPRIORITIZED_PREFIXES):
            score -= 30
            reasons.append("VIRTUAL_INTERFACE_PENALTY")
        else:
            score += 5
            reasons.append("PRIMARY_INTERFACE_CLASS")
        if not carrier:
            score -= 100
            reasons.append("CARRIER_DOWN")

        candidates.append(
            InterfaceCandidate(
                name=name,
                mac=link.get("address"),
                carrier=carrier,
                operstate=operstate,
                ipv4=ipv4,
                prefix_length=prefix,
                subnet=_subnet(ipv4, prefix),
                gateway=gateway,
                route_metric=metric,
                rx_packets=rx_packets,
                tx_packets=tx_packets,
                score=score,
                reasons=tuple(reasons),
            )
        )

    candidates.sort(
        key=lambda c: (
            c.score,
            -(c.route_metric if c.route_metric is not None else 1_000_000),
        ),
        reverse=True,
    )
    return candidates, new_rx


def elect_interface(candidates: list[InterfaceCandidate], current_name: Optional[str] = None) -> Optional[InterfaceCandidate]:
    usable = [candidate for candidate in candidates if candidate.usable]
    if not usable:
        return None

    if current_name:
        current = next((candidate for candidate in usable if candidate.name == current_name), None)
        if current is not None:
            best = usable[0]
            # Keep a valid current interface unless another interface has become the
            # operating system's clearly preferred default-route interface.
            current_has_default = "DEFAULT_ROUTE" in current.reasons
            best_has_default = "DEFAULT_ROUTE" in best.reasons
            if current_has_default or not best_has_default:
                return current

    return usable[0]
