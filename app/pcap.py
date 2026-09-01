import ipaddress
import struct
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ParsedPacket:
    timestamp: float
    frame_bytes: int
    source_mac: str
    destination_mac: str
    ether_type: int
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    tcp_flags: Optional[str] = None
    arp_sender_ip: Optional[str] = None
    arp_sender_mac: Optional[str] = None
    arp_target_ip: Optional[str] = None
    vlan_ids: tuple[int, ...] = ()


def mac_text(raw: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in raw)


def ipv4_text(raw: bytes) -> Optional[str]:
    try:
        return str(ipaddress.IPv4Address(raw))
    except (ipaddress.AddressValueError, ValueError):
        return None


def valid_unicast_mac(mac: str) -> bool:
    try:
        raw = bytes.fromhex(mac.replace(":", ""))
    except ValueError:
        return False
    return len(raw) == 6 and raw != b"\x00" * 6 and raw != b"\xff" * 6 and not (raw[0] & 0x01)


class PcapStreamReader:
    def __init__(self):
        self.buffer = bytearray()
        self.endian: Optional[str] = None
        self.nanosecond = False
        self.linktype: Optional[int] = None
        self.header_read = False

    def feed(self, data: bytes) -> None:
        self.buffer.extend(data)

    def parse_available(self) -> list[tuple[float, bytes, int]]:
        packets: list[tuple[float, bytes, int]] = []
        if not self.header_read:
            if len(self.buffer) < 24:
                return packets
            magic = bytes(self.buffer[:4])
            variants = {
                b"\xd4\xc3\xb2\xa1": ("<", False),
                b"\xa1\xb2\xc3\xd4": (">", False),
                b"\x4d\x3c\xb2\xa1": ("<", True),
                b"\xa1\xb2\x3c\x4d": (">", True),
            }
            if magic not in variants:
                raise ValueError("unsupported PCAP magic")
            self.endian, self.nanosecond = variants[magic]
            header = bytes(self.buffer[:24])
            _, _, _, _, _, _, network = struct.unpack(self.endian + "IHHIIII", header)
            self.linktype = int(network)
            del self.buffer[:24]
            self.header_read = True

        while len(self.buffer) >= 16:
            ts_sec, ts_fraction, captured_len, original_len = struct.unpack(
                self.endian + "IIII", bytes(self.buffer[:16])
            )
            if captured_len > 16_777_216:
                raise ValueError("invalid PCAP packet length")
            required = 16 + captured_len
            if len(self.buffer) < required:
                break
            frame = bytes(self.buffer[16:required])
            del self.buffer[:required]
            divisor = 1_000_000_000 if self.nanosecond else 1_000_000
            packets.append((ts_sec + ts_fraction / divisor, frame, original_len))
        return packets


def parse_ethernet_packet(timestamp: float, frame: bytes, original_length: int) -> Optional[ParsedPacket]:
    if len(frame) < 14:
        return None

    destination_mac = mac_text(frame[0:6])
    source_mac = mac_text(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    vlan_ids: list[int] = []

    while ether_type in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < offset + 4:
            return None
        tci = struct.unpack("!H", frame[offset:offset + 2])[0]
        vlan_ids.append(tci & 0x0FFF)
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4

    common = dict(
        timestamp=timestamp,
        frame_bytes=original_length,
        source_mac=source_mac,
        destination_mac=destination_mac,
        ether_type=ether_type,
        vlan_ids=tuple(vlan_ids),
    )

    if ether_type == 0x0800:
        if len(frame) < offset + 20:
            return None
        first = frame[offset]
        version = first >> 4
        ihl = (first & 0x0F) * 4
        if version != 4 or ihl < 20 or len(frame) < offset + ihl:
            return None
        total_length = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        if total_length < ihl:
            return None
        source_ip = ipv4_text(frame[offset + 12:offset + 16])
        destination_ip = ipv4_text(frame[offset + 16:offset + 20])
        if not source_ip or not destination_ip:
            return None

        proto_number = frame[offset + 9]
        fragment = struct.unpack("!H", frame[offset + 6:offset + 8])[0] & 0x1FFF
        transport = offset + ihl
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto_number, f"IP-{proto_number}")
        source_port = destination_port = None
        tcp_flags = None

        if fragment == 0 and proto_number == 6 and len(frame) >= transport + 20:
            source_port, destination_port = struct.unpack("!HH", frame[transport:transport + 4])
            flag_byte = frame[transport + 13]
            names = []
            for mask, name in ((1, "F"), (2, "S"), (4, "R"), (8, "P"), (16, "A"), (32, "U"), (64, "E"), (128, "C")):
                if flag_byte & mask:
                    names.append(name)
            tcp_flags = "".join(names)
        elif fragment == 0 and proto_number == 17 and len(frame) >= transport + 8:
            source_port, destination_port = struct.unpack("!HH", frame[transport:transport + 4])

        return ParsedPacket(
            **common,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            tcp_flags=tcp_flags,
        )

    if ether_type == 0x0806:
        if len(frame) < offset + 28:
            return None
        hardware_type, protocol_type, hardware_len, protocol_len, _operation = struct.unpack(
            "!HHBBH", frame[offset:offset + 8]
        )
        if (hardware_type, protocol_type, hardware_len, protocol_len) != (1, 0x0800, 6, 4):
            return None
        sender_mac = mac_text(frame[offset + 8:offset + 14])
        sender_ip = ipv4_text(frame[offset + 14:offset + 18])
        target_ip = ipv4_text(frame[offset + 24:offset + 28])
        if not sender_ip or not target_ip:
            return None
        return ParsedPacket(
            **common,
            arp_sender_ip=sender_ip,
            arp_sender_mac=sender_mac,
            arp_target_ip=target_ip,
            protocol="ARP",
        )

    return None
