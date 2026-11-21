from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any

import httpx
from pydantic import ValidationError

from abstract_ops.contracts import PolicyAuditVerdict, RuleSetProposal
from abstract_ops.store import PolicyAuditStore
from abstract_ops.verifier import verify_policy_ruleset

DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")


@dataclass(frozen=True)
class PolicyCegisResult:
    converged: bool
    iterations: int
    final_verdict: PolicyAuditVerdict | None
    final_ruleset: RuleSetProposal | None
    history: list[PolicyAuditVerdict]


async def _synthesize_ruleset(
    client: httpx.AsyncClient,
    ollama_url: str,
    model: str,
    specification: str,
    feedback: list[str],
    seed: int = 42,
) -> RuleSetProposal:
    system_prompt = (
        "You are a formal policy engineer. Generate a JSON RuleSetProposal matching the schema. "
        "Available fields: clearance_level (int 1..5), is_external (bool), "
        "amount (int 0..1000000), mfa_verified (bool). "
        "Avoid overlapping ALLOW/DENY rules at the same priority, dead contradictory conditions, "
        "and NEVER allow is_external==true when mfa_verified==false."
    )
    user_prompt = f"Specification:\n{specification}\n"
    if feedback:
        joined = "\n".join(f"- Iteration {i + 1}: {msg}" for i, msg in enumerate(feedback))
        user_prompt += f"\nZ3 Formal Counterexamples to fix:\n{joined}\n"

    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": RuleSetProposal.model_json_schema(),
        "options": {"temperature": 0.0, "seed": seed, "num_ctx": 4096},
    }
    resp = await client.post(f"{ollama_url}/api/chat", json=payload, timeout=120.0)
    resp.raise_for_status()
    return RuleSetProposal.model_validate_json(resp.json()["message"]["content"])


async def run_policy_cegis(
    specification: str,
    db_path: str = ":memory:",
    max_iters: int = 5,
    ollama_url: str = DEFAULT_OLLAMA_URL,
    model: str = DEFAULT_MODEL,
    transport: httpx.AsyncBaseTransport | None = None,
) -> PolicyCegisResult:
    feedback: list[str] = []
    history: list[PolicyAuditVerdict] = []
    last_ruleset: RuleSetProposal | None = None
    store = PolicyAuditStore(db_path)

    try:
        async with httpx.AsyncClient(transport=transport) as client:
            for step in range(max_iters):
                try:
                    ruleset = await _synthesize_ruleset(
                        client=client,
                        ollama_url=ollama_url,
                        model=model,
                        specification=specification,
                        feedback=feedback,
                        seed=42 + step,
                    )
                except (ValidationError, json.JSONDecodeError, KeyError) as exc:
                    feedback.append(f"Schema/JSON error: {exc}")
                    continue

                last_ruleset = ruleset
                verdict = verify_policy_ruleset(ruleset)
                store.record(verdict)
                history.append(verdict)

                if verdict.status == "SAT":
                    return PolicyCegisResult(
                        converged=True,
                        iterations=step + 1,
                        final_verdict=verdict,
                        final_ruleset=ruleset,
                        history=history,
                    )

                feedback.append("; ".join(verdict.violations))

        return PolicyCegisResult(
            converged=False,
            iterations=max_iters,
            final_verdict=history[-1] if history else None,
            final_ruleset=last_ruleset,
            history=history,
        )
    finally:
        store.close()


def main() -> None:
    spec = (
        "Create policy 'treasury-transfer': "
        "1) Internal users: clearance_level >= 3 and amount <= 50000 -> ALLOW (priority 10). "
        "2) External users with mfa_verified == true, clearance_level >= 4, and amount <= 10000 "
        "are ALLOWED (priority 10). "
        "3) Any transfer with amount > 50000 is DENIED (priority 10)."
    )
    db = "/app/data/abstract_audit.duckdb"
    res = asyncio.run(run_policy_cegis(spec, db_path=db, max_iters=4))
    print(f"Converged: {res.converged} in {res.iterations} iteration(s)")
    for idx, v in enumerate(res.history, 1):
        print(f"  Iter {idx}: status={v.status} rules={v.rule_count} violations={v.violations}")


if __name__ == "__main__":
    main()
