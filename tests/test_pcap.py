import struct
import unittest

from app.pcap import parse_ethernet_packet


class PcapParserTests(unittest.TestCase):
    def test_short_frame_is_rejected(self):
        self.assertIsNone(parse_ethernet_packet(1.0, b"\x00" * 10, 10))

    def test_ipv4_tcp_frame_parses_structured_fields(self):
        dst_mac = bytes.fromhex("020000000030")
        src_mac = bytes.fromhex("020000000020")
        ethernet = dst_mac + src_mac + struct.pack("!H", 0x0800)
        version_ihl = 0x45
        total_length = 40
        ipv4 = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            0,
            total_length,
            1,
            0,
            64,
            6,
            0,
            bytes([10, 10, 0, 55]),
            bytes([8, 8, 8, 8]),
        )
        tcp = struct.pack("!HHLLBBHHH", 50000, 443, 0, 0, 0x50, 0x02, 65535, 0, 0)
        packet = parse_ethernet_packet(1234.0, ethernet + ipv4 + tcp, len(ethernet + ipv4 + tcp))
        self.assertIsNotNone(packet)
        self.assertEqual(packet.source_ip, "10.10.0.55")
        self.assertEqual(packet.destination_ip, "8.8.8.8")
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.destination_port, 443)
        self.assertEqual(packet.tcp_flags, "S")


if __name__ == "__main__":
    unittest.main()
