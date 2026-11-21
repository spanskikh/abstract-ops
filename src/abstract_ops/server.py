from __future__ import annotations

import os
from typing import Any

from fastmcp import FastMCP

from abstract_ops.cegis import run_policy_cegis
from abstract_ops.contracts import RuleSetProposal
from abstract_ops.store import PolicyAuditStore
from abstract_ops.verifier import verify_policy_ruleset

mcp = FastMCP("abstract-ops-auditor")
DB_PATH = os.getenv("AUDIT_DB_PATH", "/app/data/abstract_audit.duckdb")


@mcp.tool()
def audit_policy_ruleset(ruleset_json: dict[str, Any]) -> dict[str, object]:
    """Формально проверяет набор правил (JSON RuleSetProposal) через Z3 SMT Solver."""
    proposal = RuleSetProposal.model_validate(ruleset_json)
    verdict = verify_policy_ruleset(proposal)
    store = PolicyAuditStore(DB_PATH)
    try:
        store.record(verdict)
    finally:
        store.close()
    return verdict.model_dump()


@mcp.tool()
async def synthesize_verified_policy(specification: str, max_iters: int = 5) -> dict[str, object]:
    """Синтезирует формально непротиворечивую политику из ТЗ через CEGIS (Ollama + Z3)."""
    res = await run_policy_cegis(specification=specification, db_path=DB_PATH, max_iters=max_iters)
    return {
        "converged": res.converged,
        "iterations": res.iterations,
        "final_verdict": res.final_verdict.model_dump() if res.final_verdict else None,
        "final_ruleset": res.final_ruleset.model_dump() if res.final_ruleset else None,
    }


if __name__ == "__main__":
    mcp.run(transport="stdio")
