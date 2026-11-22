# Target: tests/test_adversarial_cegis.py
from __future__ import annotations

from pathlib import Path

import duckdb
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from abstract_ops.adversarial import (
    generate_adversarial_corpus,
    run_adversarial_cegis_benchmark,
)
from abstract_ops.contracts import PolicyRule, RuleCondition, RuleSetProposal
from abstract_ops.verifier import verify_policy_ruleset


@pytest.mark.asyncio
async def test_adversarial_corpus_zero_false_sat_and_cegis_convergence(tmp_path: Path) -> None:
    db_file = tmp_path / "adversarial_cegis.duckdb"
    report = await run_adversarial_cegis_benchmark(
        db_path=db_file,
        per_category=15,
        max_iters=3,
        suite_name="cr012_adversarial_60",
    )

    assert report.total_specs == 60
    assert report.false_sat_count == 0
    assert report.converged_count == 60
    assert report.max_iterations <= 3
    assert report.passed_gate is True

    conn = duckdb.connect(str(db_file))
    try:
        audit_rows = conn.execute("SELECT COUNT(*) FROM policy_audits").fetchone()
        bench_rows = conn.execute(
            "SELECT total_specs, false_sat_count, passed_gate FROM cegis_benchmarks"
        ).fetchall()
    finally:
        conn.close()

    # 60 specs * 2 CEGIS iterations each = 120 persisted Z3 audit verdicts
    assert audit_rows is not None and int(audit_rows[0]) == 120
    assert len(bench_rows) == 1
    assert bench_rows[0] == (60, 0, True)


@given(
    clearance=st.integers(min_value=1, max_value=5),
    max_amount=st.integers(min_value=100, max_value=500_000),
    priority=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=60)
def test_hypothesis_fuzzed_mfa_bypass_specs_never_yield_false_sat(
    clearance: int,
    max_amount: int,
    priority: int,
) -> None:
    """Property fuzzing: any ALLOW rule reachable for is_external=True without MFA must be UNSAT."""
    fuzzed_spec = RuleSetProposal(
        policy_name="fuzz_mfa_bypass",
        rules=[
            PolicyRule(
                rule_id="fuzz_allow_ext",
                priority=priority,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=True),
                    RuleCondition(field="clearance_level", op=">=", value=clearance),
                    RuleCondition(field="amount", op="<=", value=max_amount),
                ],
            )
        ],
    )
    verdict = verify_policy_ruleset(fuzzed_spec)
    assert verdict.status == "UNSAT"
    assert verdict.counterexample is not None
    assert verdict.counterexample["is_external"] is True
    assert verdict.counterexample["mfa_verified"] is False


@given(
    split_amount=st.integers(min_value=1, max_value=999_999),
    priority=st.integers(min_value=1, max_value=100),
)
@settings(max_examples=60)
def test_hypothesis_fuzzed_boundary_collisions_never_yield_false_sat(
    split_amount: int,
    priority: int,
) -> None:
    """Property fuzzing: overlapping <= and >= ALLOW/DENY rules at same priority must be UNSAT."""
    fuzzed_spec = RuleSetProposal(
        policy_name="fuzz_boundary_overlap",
        rules=[
            PolicyRule(
                rule_id="fuzz_allow_le",
                priority=priority,
                effect="ALLOW",
                conditions=[
                    RuleCondition(field="is_external", op="==", value=False),
                    RuleCondition(field="amount", op="<=", value=split_amount),
                ],
            ),
            PolicyRule(
                rule_id="fuzz_deny_ge",
                priority=priority,
                effect="DENY",
                conditions=[
                    RuleCondition(field="amount", op=">=", value=split_amount),
                ],
            ),
        ],
    )
    verdict = verify_policy_ruleset(fuzzed_spec)
    assert verdict.status == "UNSAT"
    assert verdict.counterexample is not None
    assert verdict.counterexample["amount"] == split_amount


def test_adversarial_corpus_repaired_specs_are_all_sat() -> None:
    cases = generate_adversarial_corpus(per_category=15)
    assert len(cases) == 60
    for case in cases:
        repaired_verdict = verify_policy_ruleset(case.repaired_proposal)
        assert repaired_verdict.status == "SAT", (
            f"Repaired spec {case.case_id} unexpectedly failed: {repaired_verdict.violations}"
        )
