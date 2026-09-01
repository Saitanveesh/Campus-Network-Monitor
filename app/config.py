from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    host: str = "127.0.0.1"
    port: int = 8080
    supervisor_interval: float = 2.0
    endpoint_ttl: float = 60.0
    flow_ttl: float = 30.0
    packet_ttl: float = 15.0
    traffic_sample_interval: float = 3.0
    packet_ring_size: int = 500
    capture_idle_seconds: float = 5.0
    capture_stall_seconds: float = 10.0
    os_rx_stall_threshold: int = 25

    @property
    def project_root(self) -> Path:
        return Path(__file__).resolve().parent.parent

    @property
    def web_dir(self) -> Path:
        return self.project_root / "web"

    @property
    def data_dir(self) -> Path:
        return self.project_root / "data"

    @property
    def history_db(self) -> Path:
        return self.data_dir / "history.db"


SETTINGS = Settings()
