import json
import sqlite3
from pathlib import Path
from typing import Optional


class HistoryStore:
    """Persistent closed-session archive.

    The live API never reads this store. Keeping the archive behind a separate
    class is an intentional boundary against stale-session leakage.
    """

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        return db

    def _initialise(self) -> None:
        db = self._connect()
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions
            (
                session_id TEXT PRIMARY KEY,
                started_at REAL NOT NULL,
                ended_at REAL NOT NULL,
                interface TEXT,
                sensor_ip TEXT,
                subnet TEXT,
                gateway TEXT,
                fingerprint TEXT,
                end_state TEXT,
                end_reason TEXT,
                endpoint_count INTEGER,
                flow_count INTEGER,
                snapshot_json TEXT NOT NULL
            )
            """
        )
        db.execute("CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at DESC)")
        db.commit()
        db.close()

    def archive(self, snapshot: Optional[dict]) -> None:
        if not snapshot or not snapshot.get("session"):
            return
        session = snapshot["session"]
        db = self._connect()
        db.execute(
            """
            INSERT OR REPLACE INTO sessions
            (
                session_id, started_at, ended_at, interface, sensor_ip,
                subnet, gateway, fingerprint, end_state, end_reason,
                endpoint_count, flow_count, snapshot_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session["session_id"],
                session["started_at"],
                snapshot["ended_at"],
                session["interface"],
                session["sensor_ip"],
                session["subnet"],
                session.get("gateway"),
                session["fingerprint"],
                snapshot.get("end_state"),
                snapshot.get("end_reason"),
                len(snapshot.get("endpoints", [])),
                len(snapshot.get("flows", [])),
                json.dumps(snapshot, separators=(",", ":")),
            ),
        )
        db.commit()
        db.close()

    def list_sessions(self, limit: int = 50) -> list[dict]:
        limit = max(1, min(int(limit), 500))
        db = self._connect()
        db.row_factory = sqlite3.Row
        rows = db.execute(
            """
            SELECT session_id, started_at, ended_at, interface, sensor_ip,
                   subnet, gateway, end_state, end_reason,
                   endpoint_count, flow_count
            FROM sessions
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        db.close()
        return [dict(row) for row in rows]

    def get_session(self, session_id: str) -> Optional[dict]:
        db = self._connect()
        row = db.execute("SELECT snapshot_json FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        db.close()
        return json.loads(row[0]) if row else None
