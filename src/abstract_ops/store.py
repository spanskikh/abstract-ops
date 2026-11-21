from __future__ import annotations

import json
from pathlib import Path

import duckdb

from abstract_ops.contracts import PolicyAuditVerdict


class PolicyAuditStore:
    """Журнал формальной верификации политик и CEGIS-метрик в DuckDB."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = duckdb.connect(str(db_path))
        self._conn.execute("SET memory_limit='512MB'; SET threads=2;")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS policy_audits (
                ts TIMESTAMP DEFAULT current_timestamp,
                policy_name VARCHAR NOT NULL,
                status VARCHAR NOT NULL,
                rule_count INTEGER NOT NULL,
                violations_json VARCHAR NOT NULL,
                counterexample_json VARCHAR
            )
            """
        )

    def record(self, verdict: PolicyAuditVerdict) -> None:
        self._conn.execute(
            """
            INSERT INTO policy_audits (
                policy_name, status, rule_count, violations_json, counterexample_json
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                verdict.policy_name,
                verdict.status,
                verdict.rule_count,
                json.dumps(verdict.violations, ensure_ascii=False),
                json.dumps(verdict.counterexample, ensure_ascii=False)
                if verdict.counterexample is not None
                else None,
            ],
        )

    def close(self) -> None:
        self._conn.close()
