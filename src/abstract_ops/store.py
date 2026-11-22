from __future__ import annotations

import json
from pathlib import Path

import duckdb

from abstract_ops.contracts import PolicyAuditVerdict


class PolicyAuditStore:
    """Formal policy verification and CEGIS convergence audit log in DuckDB."""

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
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cegis_benchmarks (
                ts TIMESTAMP DEFAULT current_timestamp,
                suite_name VARCHAR NOT NULL,
                total_specs INTEGER NOT NULL,
                false_sat_count INTEGER NOT NULL,
                converged_count INTEGER NOT NULL,
                max_iterations INTEGER NOT NULL,
                mean_iterations DOUBLE NOT NULL,
                passed_gate BOOLEAN NOT NULL
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

    def record_cegis_benchmark(
        self,
        suite_name: str,
        total_specs: int,
        false_sat_count: int,
        converged_count: int,
        max_iterations: int,
        mean_iterations: float,
        passed_gate: bool,
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO cegis_benchmarks (
                suite_name,
                total_specs,
                false_sat_count,
                converged_count,
                max_iterations,
                mean_iterations,
                passed_gate
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                suite_name,
                total_specs,
                false_sat_count,
                converged_count,
                max_iterations,
                mean_iterations,
                passed_gate,
            ],
        )

    def count_audits(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM policy_audits").fetchone()
        return int(row[0]) if row else 0

    def count_cegis_benchmarks(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM cegis_benchmarks").fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        self._conn.close()
