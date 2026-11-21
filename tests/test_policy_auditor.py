from __future__ import annotations

import json

import httpx
from hypothesis import given, settings
from hypothesis import strategies as st

from abstract_ops.cegis import run_policy_cegis
from abstract_ops.contracts import PolicyRule, RuleCondition, RuleSetProposal
from abstract_ops.verifier import verify_policy_ruleset


def test_detects_ambiguous_allow_deny_conflict_with_counterexample() -> None:
    ruleset = RuleSetProposal(
        policy_name="conflict-demo",
        rules=[
            PolicyRule(
                rule_id="allow_high_clearance",
                priority=10,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="clearance_level", op=">=", value=4),
                    RuleCondition(field="mfa_verified", op="==", value=True),
                ],
            ),
            PolicyRule(
                rule_id="deny_large_amount",
                priority=10,
                effect="DENY",
                conditions=[RuleCondition(field="amount", op=">", value=100_000)],
            ),
        ],
    )
    verdict = verify_policy_ruleset(ruleset)
    assert verdict.status == "UNSAT"
    assert verdict.counterexample is not None
    assert int(verdict.counterexample["clearance_level"]) >= 4
    assert int(verdict.counterexample["amount"]) > 100_000


def test_detects_dead_contradictory_rule() -> None:
    ruleset = RuleSetProposal(
        policy_name="dead-rule-demo",
        rules=[
            PolicyRule(
                rule_id="impossible_amount",
                priority=10,
                effect="DENY",
                conditions=[
                    RuleCondition(field="amount", op=">", value=50_000),
                    RuleCondition(field="amount", op="<", value=10_000),
                ],
            )
        ],
    )
    verdict = verify_policy_ruleset(ruleset)
    assert verdict.status == "UNSAT"
    assert any("Unreachable (dead) rule" in v for v in verdict.violations)


def test_detects_external_without_mfa_security_breach() -> None:
    ruleset = RuleSetProposal(
        policy_name="mfa-breach-demo",
        rules=[
            PolicyRule(
                rule_id="allow_level_5_any",
                priority=10,
                effect="ALLOW",
                conditions=[RuleCondition(field="clearance_level", op="==", value=5)],
            )
        ],
    )
    verdict = verify_policy_ruleset(ruleset)
    assert verdict.status == "UNSAT"
    assert verdict.counterexample is not None
    assert verdict.counterexample["is_external"] is True
    assert verdict.counterexample["mfa_verified"] is False


@settings(max_examples=80, deadline=None)
@given(
    threshold_allow=st.integers(min_value=1_000, max_value=500_000),
    threshold_deny=st.integers(min_value=1_000, max_value=500_000),
)
def test_property_allow_deny_disjoint_iff_thresholds_ordered(
    threshold_allow: int, threshold_deny: int
) -> None:
    ruleset = RuleSetProposal(
        policy_name="prop-thresholds",
        rules=[
            PolicyRule(
                rule_id="r_allow",
                priority=10,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=False),
                    RuleCondition(field="amount", op="<=", value=threshold_allow),
                ],
            ),
            PolicyRule(
                rule_id="r_deny",
                priority=10,
                effect="DENY",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=False),
                    RuleCondition(field="amount", op=">=", value=threshold_deny),
                ],
            ),
        ],
    )
    verdict = verify_policy_ruleset(ruleset)
    assert (verdict.status == "SAT") is (threshold_allow < threshold_deny)


async def test_policy_cegis_repairs_security_violation() -> None:
    step = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal step
        step += 1
        if step == 1:
            # Шаг 1: LLM забыла проверить mfa_verified == True
            bad_ruleset = {
                "policy_name": "api-access",
                "rules": [
                    {
                        "rule_id": "allow_ext",
                        "priority": 10,
                        "effect": "ALLOW",
                        "conditions": [{"field": "is_external", "op": "==", "value": True}],
                    }
                ],
            }
            return httpx.Response(200, json={"message": {"content": json.dumps(bad_ruleset)}})

        body = json.loads(request.content.decode())
        assert "external user without MFA granted ALLOW" in body["messages"][-1]["content"]
        fixed_ruleset = {
            "policy_name": "api-access",
            "rules": [
                {
                    "rule_id": "allow_ext_mfa",
                    "priority": 10,
                    "effect": "ALLOW",
                    "conditions": [
                        {"field": "is_external", "op": "==", "value": True},
                        {"field": "mfa_verified", "op": "==", "value": True},
                    ],
                }
            ],
        }
        return httpx.Response(200, json={"message": {"content": json.dumps(fixed_ruleset)}})

    res = await run_policy_cegis(
        specification="Allow external users",
        db_path=":memory:",
        max_iters=3,
        transport=httpx.MockTransport(handler),
    )
    assert res.converged is True
    assert res.iterations == 2


def test_detects_shadowed_redundant_rule() -> None:
    proposal = RuleSetProposal(
        policy_name="shadowing-test",
        rules=[
            PolicyRule(
                rule_id="broad_internal_allow",
                priority=20,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=False),
                    RuleCondition(field="clearance_level", op=">=", value=3),
                ],
            ),
            PolicyRule(
                rule_id="narrow_internal_allow",
                priority=10,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=False),
                    RuleCondition(field="clearance_level", op=">=", value=4),
                    RuleCondition(field="amount", op="<=", value=5000),
                ],
            ),
        ],
    )
    verdict = verify_policy_ruleset(proposal)
    assert verdict.status == "UNSAT"
    assert any("Shadowed redundant rule 'narrow_internal_allow'" in v for v in verdict.violations)
    assert verdict.counterexample is not None
