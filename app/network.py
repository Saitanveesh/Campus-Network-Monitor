import hashlib
import ipaddress
import json
import platform
import shutil
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
    capture_device: Optional[str] = None

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
        timeout=5,
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


def _valid_windows_ipv4(address: object, prefix: object) -> tuple[Optional[str], Optional[int]]:
    if address is None or prefix is None:
        return None, None
    try:
        ip = ipaddress.ip_address(str(address))
        prefix_int = int(prefix)
    except (ValueError, TypeError):
        return None, None
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        return None, None
    return str(ip), prefix_int


def _subnet(ipv4: Optional[str], prefix: Optional[int]) -> Optional[str]:
    if not ipv4 or prefix is None:
        return None
    try:
        return str(ipaddress.ip_interface(f"{ipv4}/{prefix}").network)
    except ValueError:
        return None


def _score_candidate(
    *,
    name: str,
    carrier: bool,
    operstate: str,
    ipv4: Optional[str],
    has_default_route: bool,
    rx_delta: int,
) -> tuple[int, tuple[str, ...]]:
    score = 0
    reasons: list[str] = []

    if carrier:
        score += 40
        reasons.append("CARRIER_UP")
    else:
        score -= 100
        reasons.append("CARRIER_DOWN")

    if operstate in {"up", "unknown"}:
        score += 10
        reasons.append("OPERSTATE_UP")

    if ipv4:
        score += 25
        reasons.append("USABLE_IPV4")

    if has_default_route:
        score += 50
        reasons.append("DEFAULT_ROUTE")

    if rx_delta > 0:
        score += 5
        reasons.append("RX_ACTIVITY")

    lowered = name.lower()
    if any(lowered.startswith(prefix) for prefix in DEPRIORITIZED_PREFIXES):
        score -= 30
        reasons.append("VIRTUAL_INTERFACE_PENALTY")
    else:
        score += 5
        reasons.append("PRIMARY_INTERFACE_CLASS")

    return score, tuple(reasons)


def _discover_linux(previous_rx: Dict[str, int]) -> tuple[list[InterfaceCandidate], Dict[str, int]]:
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
        score, reasons = _score_candidate(
            name=name,
            carrier=carrier,
            operstate=operstate,
            ipv4=ipv4,
            has_default_route=route is not None,
            rx_delta=rx_delta,
        )

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
                reasons=reasons,
                capture_device=name,
            )
        )

    return candidates, new_rx


def _powershell_executable() -> Optional[str]:
    return shutil.which("powershell.exe") or shutil.which("pwsh.exe") or shutil.which("powershell") or shutil.which("pwsh")


def _discover_windows(previous_rx: Dict[str, int]) -> tuple[list[InterfaceCandidate], Dict[str, int]]:
    powershell = _powershell_executable()
    if not powershell:
        return [], {}

    script = r'''
$ErrorActionPreference = 'SilentlyContinue'
$items = @()
Get-NetAdapter -IncludeHidden | Where-Object { $_.HardwareInterface -eq $true } | ForEach-Object {
    $a = $_
    $addr = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.AddressState -ne 'Duplicate' } |
        Select-Object -First 1
    $ipif = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Select-Object -First 1
    $route = Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Sort-Object RouteMetric |
        Select-Object -First 1
    $stats = Get-NetAdapterStatistics -InterfaceIndex $a.ifIndex
    $rx = 0
    $tx = 0
    if ($stats) {
        $rx = [int64]$stats.ReceivedUnicastPackets + [int64]$stats.ReceivedBroadcastPackets + [int64]$stats.ReceivedMulticastPackets
        $tx = [int64]$stats.SentUnicastPackets + [int64]$stats.SentBroadcastPackets + [int64]$stats.SentMulticastPackets
    }
    $metric = $null
    if ($route) {
        $metric = [int]$route.RouteMetric
        if ($ipif) { $metric += [int]$ipif.InterfaceMetric }
    }
    $items += [PSCustomObject]@{
        Name = [string]$a.Name
        Mac = [string]$a.MacAddress
        Status = [string]$a.Status
        Guid = [string]$a.InterfaceGuid
        IPv4 = $(if ($addr) { [string]$addr.IPAddress } else { $null })
        Prefix = $(if ($addr) { [int]$addr.PrefixLength } else { $null })
        Gateway = $(if ($route) { [string]$route.NextHop } else { $null })
        RouteMetric = $metric
        RxPackets = [int64]$rx
        TxPackets = [int64]$tx
    }
}
$items | ConvertTo-Json -Compress
'''

    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return [], {}

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError:
        return [], {}

    if isinstance(raw, dict):
        rows = [raw]
    elif isinstance(raw, list):
        rows = raw
    else:
        rows = []

    candidates: list[InterfaceCandidate] = []
    new_rx: Dict[str, int] = {}

    for row in rows:
        name = str(row.get("Name") or "").strip()
        if not name:
            continue

        carrier = str(row.get("Status") or "").lower() == "up"
        operstate = "up" if carrier else "down"
        ipv4, prefix = _valid_windows_ipv4(row.get("IPv4"), row.get("Prefix"))
        gateway = str(row.get("Gateway") or "").strip() or None

        try:
            metric = int(row["RouteMetric"]) if row.get("RouteMetric") is not None else None
        except (TypeError, ValueError):
            metric = None

        try:
            rx_packets = int(row.get("RxPackets") or 0)
            tx_packets = int(row.get("TxPackets") or 0)
        except (TypeError, ValueError):
            rx_packets = 0
            tx_packets = 0

        new_rx[name] = rx_packets
        rx_delta = max(0, rx_packets - previous_rx.get(name, rx_packets))
        score, reasons = _score_candidate(
            name=name,
            carrier=carrier,
            operstate=operstate,
            ipv4=ipv4,
            has_default_route=bool(gateway),
            rx_delta=rx_delta,
        )

        mac = str(row.get("Mac") or "").strip().replace("-", ":").lower() or None
        guid = str(row.get("Guid") or "").strip().strip("{}")
        capture_device = f"\\Device\\NPF_{{{guid}}}" if guid else name

        candidates.append(
            InterfaceCandidate(
                name=name,
                mac=mac,
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
                reasons=reasons,
                capture_device=capture_device,
            )
        )

    return candidates, new_rx


def discover_interfaces(previous_rx: Optional[Dict[str, int]] = None) -> tuple[list[InterfaceCandidate], Dict[str, int]]:
    previous_rx = previous_rx or {}
    system = platform.system().lower()

    if system == "windows":
        candidates, new_rx = _discover_windows(previous_rx)
    elif system == "linux":
        candidates, new_rx = _discover_linux(previous_rx)
    else:
        return [], {}

    candidates.sort(
        key=lambda candidate: (
            -candidate.score,
            candidate.route_metric if candidate.route_metric is not None else 1_000_000,
            candidate.name.lower(),
        )
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
            current_has_default = "DEFAULT_ROUTE" in current.reasons
            best_has_default = "DEFAULT_ROUTE" in best.reasons
            if current_has_default or not best_has_default:
                return current

    return usable[0]
