import unittest

from app.network import InterfaceCandidate
from app.pcap import ParsedPacket
from app.state import LiveState


class LiveStateTests(unittest.TestCase):
    def candidate(self, ip="10.10.0.10", gateway="10.10.0.1"):
        return InterfaceCandidate(
            name="eth0",
            mac="02:00:00:00:00:10",
            carrier=True,
            operstate="up",
            ipv4=ip,
            prefix_length=24,
            subnet="10.10.0.0/24",
            gateway=gateway,
            route_metric=100,
            rx_packets=100,
            tx_packets=100,
            score=100,
            reasons=("CARRIER_UP", "USABLE_IPV4", "DEFAULT_ROUTE"),
        )

    def packet(self, source_ip, destination_ip, source_mac="02:00:00:00:00:20"):
        return ParsedPacket(
            timestamp=1000.0,
            frame_bytes=100,
            source_mac=source_mac,
            destination_mac="02:00:00:00:00:30",
            ether_type=0x0800,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol="TCP",
            source_port=50000,
            destination_port=443,
            tcp_flags="S",
        )

    def test_destination_only_local_ip_is_not_promoted_to_endpoint(self):
        state = LiveState()
        state.start_session(self.candidate())
        state.ingest(self.packet("8.8.8.8", "10.10.0.55", source_mac="02:00:00:00:00:99"))
        self.assertNotIn("10.10.0.55", state.endpoints)

    def test_local_source_creates_evidence_backed_endpoint(self):
        state = LiveState()
        state.start_session(self.candidate())
        state.ingest(self.packet("10.10.0.55", "8.8.8.8"))
        self.assertEqual(state.endpoints["10.10.0.55"]["evidence_type"], "IPV4_SOURCE_FRAME")
        self.assertEqual(state.endpoints["10.10.0.55"]["classification"], "LOCAL_SUBNET_ENDPOINT")

    def test_session_end_clears_all_live_entities(self):
        state = LiveState()
        state.start_session(self.candidate())
        state.ingest(self.packet("10.10.0.55", "8.8.8.8"))
        self.assertTrue(state.endpoints)
        snapshot = state.end_session("NETWORK_DOWN", "test disconnect")
        self.assertIsNotNone(snapshot)
        self.assertFalse(state.endpoints)
        self.assertFalse(state.flows)
        self.assertFalse(state.packets)
        self.assertIsNone(state.session)


if __name__ == "__main__":
    unittest.main()
