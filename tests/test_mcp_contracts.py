from __future__ import annotations

import json
import os
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.types import CallToolResult, TextContent

REPO_ROOT = Path(__file__).resolve().parents[1]

EXPECTED_TOOLS: dict[str, set[str]] = {
    "audit_policy_ruleset": {"ruleset_json"},
    "synthesize_verified_policy": {"specification"},
}

HARNESS_ENTRYPOINT = textwrap.dedent(
    """
    from unittest.mock import AsyncMock, patch
    from abstract_ops import server
    from abstract_ops.cegis import PolicyCegisResult
    from abstract_ops.contracts import (
        PolicyAuditVerdict,
        PolicyRule,
        RuleCondition,
        RuleSetProposal,
    )

    async def _fake_policy_cegis(
        specification: str,
        db_path: str,
        max_iters: int = 5,
    ) -> PolicyCegisResult:
        ruleset = RuleSetProposal(
            policy_name="synthesized_mfa_guard",
            rules=[
                PolicyRule(
                    rule_id="r_allow_mfa",
                    priority=10,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="clearance_level", op=">=", value=3),
                        RuleCondition(field="mfa_verified", op="==", value=True),
                    ],
                )
            ],
        )
        verdict = PolicyAuditVerdict(
            status="SAT",
            policy_name=ruleset.policy_name,
            rule_count=1,
            violations=[],
            counterexample=None,
        )
        return PolicyCegisResult(
            converged=True,
            iterations=1,
            final_verdict=verdict,
            final_ruleset=ruleset,
            history=[verdict],
        )

    with patch.object(server, "run_policy_cegis", new=AsyncMock(side_effect=_fake_policy_cegis)):
        server.mcp.run(transport="stdio")
    """
).strip()


def _extract_payload(result: CallToolResult) -> dict[str, Any]:
    assert not result.is_error, f"Unexpected MCP tool error: {result.content}"
    if isinstance(result.structured_content, dict):
        return result.structured_content
    first = result.content[0]
    assert isinstance(first, TextContent)
    parsed = json.loads(first.text)
    assert isinstance(parsed, dict)
    return parsed


def _server_params(tmp_path: Path) -> StdioServerParameters:
    db_file = tmp_path / "abstract_contract_audit.duckdb"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    env["AUDIT_DB_PATH"] = str(db_file)
    return StdioServerParameters(
        command=sys.executable,
        args=["-c", HARNESS_ENTRYPOINT],
        env=env,
    )


@pytest.mark.asyncio
async def test_stdio_tool_discovery_and_schemas(tmp_path: Path) -> None:
    async with stdio_client(_server_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()

    tools_by_name = {tool.name: tool for tool in listed.tools}
    assert set(tools_by_name) == set(EXPECTED_TOOLS)

    for name, expected_required in EXPECTED_TOOLS.items():
        schema = tools_by_name[name].input_schema
        assert schema.get("type") == "object"
        required = set(schema.get("required", []))
        assert expected_required.issubset(required)


@pytest.mark.asyncio
async def test_stdio_z3_sat_and_unsat_policy_audits(tmp_path: Path) -> None:
    sat_ruleset = {
        "policy_name": "strict_internal_access",
        "rules": [
            {
                "rule_id": "allow_internal_mfa",
                "priority": 10,
                "effect": "ALLOW",
                "conditions": [
                    {"field": "is_external", "op": "==", "value": False},
                    {"field": "mfa_verified", "op": "==", "value": True},
                    {"field": "clearance_level", "op": ">=", "value": 3},
                ],
            }
        ],
    }

    unsat_conflicting_ruleset = {
        "policy_name": "ambiguous_same_priority",
        "rules": [
            {
                "rule_id": "allow_high_clearance",
                "priority": 10,
                "effect": "ALLOW",
                "conditions": [{"field": "clearance_level", "op": ">=", "value": 2}],
            },
            {
                "rule_id": "deny_external",
                "priority": 10,
                "effect": "DENY",
                "conditions": [{"field": "is_external", "op": "==", "value": True}],
            },
        ],
    }

    async with stdio_client(_server_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            sat_res = await session.call_tool("audit_policy_ruleset", {"ruleset_json": sat_ruleset})
            sat_data = _extract_payload(sat_res)
            assert sat_data["status"] == "SAT"
            assert sat_data["policy_name"] == "strict_internal_access"
            assert sat_data["violations"] == []

            unsat_res = await session.call_tool(
                "audit_policy_ruleset",
                {"ruleset_json": unsat_conflicting_ruleset},
            )
            unsat_data = _extract_payload(unsat_res)
            assert unsat_data["status"] == "UNSAT"
            assert len(unsat_data["violations"]) >= 1
            assert unsat_data["counterexample"] is not None

            cegis_res = await session.call_tool(
                "synthesize_verified_policy",
                {"specification": "Allow clearance >= 3 with MFA", "max_iters": 2},
            )
            cegis_data = _extract_payload(cegis_res)
            assert cegis_data["converged"] is True
            assert cegis_data["final_verdict"]["status"] == "SAT"


@pytest.mark.asyncio
async def test_stdio_pydantic_validation_rejection(tmp_path: Path) -> None:
    malformed_ruleset = {
        "policy_name": "bad_field_policy",
        "rules": [
            {
                "rule_id": "r1",
                "priority": 10,
                "effect": "ALLOW",
                "conditions": [{"field": "unknown_attribute", "op": "==", "value": True}],
            }
        ],
    }

    async with stdio_client(_server_params(tmp_path)) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            bad_schema = await session.call_tool(
                "audit_policy_ruleset",
                {"ruleset_json": malformed_ruleset},
            )
            assert bad_schema.is_error is True

            missing_arg = await session.call_tool("audit_policy_ruleset", {})
            assert missing_arg.is_error is True
