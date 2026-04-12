"""SQLite storage helpers for split-engine."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = ROOT / "state" / "split-engine.db"
SCHEMA_PATH = ROOT / "schema" / "schema.sql"


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")


def connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    schema = SCHEMA_PATH.read_text()
    with connect() as conn:
        conn.executescript(schema)
        conn.commit()


def upsert_domain_observation(domain: str, peer: str | None = None, seen_at: str | None = None) -> None:
    seen_at = seen_at or utc_now()
    with connect() as conn:
        row = conn.execute("SELECT domain, peer_count, hit_count FROM domains WHERE domain = ?", (domain,)).fetchone()
        if row:
            conn.execute(
                "UPDATE domains SET last_seen_at = ?, hit_count = hit_count + 1 WHERE domain = ?",
                (seen_at, domain),
            )
        else:
            conn.execute(
                """
                INSERT INTO domains (domain, first_seen_at, last_seen_at, hit_count, peer_count, state)
                VALUES (?, ?, ?, 1, ?, 'new')
                """,
                (domain, seen_at, seen_at, 1 if peer else 0),
            )
        conn.commit()


def insert_probe_result(result: dict[str, Any], created_at: str | None = None) -> int:
    created_at = created_at or utc_now()
    with connect() as conn:
        cur = conn.execute(
            """
            INSERT INTO probes (
                domain, dns_ok, tcp_ok, tls_ok, http_ok,
                resolved_ips_json, failure_reason, latency_ms, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result["domain"],
                _bool_to_int(result.get("dns_ok")),
                _bool_to_int(result.get("tcp_ok")),
                _bool_to_int(result.get("tls_ok")),
                _bool_to_int(result.get("http_ok")),
                json.dumps(result.get("resolved_ips", [])),
                result.get("failure_reason"),
                result.get("latency_ms"),
                created_at,
            ),
        )
        probe_id = int(cur.lastrowid)
        conn.execute("UPDATE domains SET last_probe_id = ? WHERE domain = ?", (probe_id, result["domain"]))
        conn.commit()
        return probe_id


def list_recent_domains(limit: int = 100) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM domains ORDER BY last_seen_at DESC LIMIT ?",
            (limit,),
        ).fetchall()


def _bool_to_int(value: bool | None) -> int | None:
    if value is None:
        return None
    return 1 if value else 0
