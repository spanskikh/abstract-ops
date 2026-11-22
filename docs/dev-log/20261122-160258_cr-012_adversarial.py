# Target: src/abstract_ops/adversarial.py
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx

from abstract_ops.cegis import run_policy_cegis
from abstract_ops.contracts import PolicyRule, RuleCondition, RuleSetProposal
from abstract_ops.store import PolicyAuditStore
from abstract_ops.verifier import verify_policy_ruleset

AttackCategory = Literal[
    "mfa_bypass_injection",
    "priority_collision",
    "boundary_overlap",
    "dead_or_shadowed_rule",
]


@dataclass(frozen=True)
class AdversarialPolicyCase:
    """Synthetic adversarial policy proposal paired with its Z3-clean repaired counterpart."""

    case_id: str
    category: AttackCategory
    specification: str
    flawed_proposal: RuleSetProposal
    repaired_proposal: RuleSetProposal


@dataclass(frozen=True)
class AdversarialBenchmarkReport:
    """Aggregated adversarial fuzzing and CEGIS convergence benchmark metrics."""

    suite_name: str
    total_specs: int
    false_sat_count: int
    converged_count: int
    max_iterations: int
    mean_iterations: float
    passed_gate: bool


def generate_adversarial_corpus(per_category: int = 15) -> list[AdversarialPolicyCase]:
    """Generate >= 60 deterministic adversarial policy specs across 4 formal attack vectors."""
    cases: list[AdversarialPolicyCase] = []

    for idx in range(per_category):
        threshold = 5_000 + idx * 2_500
        clearance = (idx % 4) + 2

        # 1. MFA bypass injection (external user granted ALLOW without mfa_verified == True)
        mfa_flawed = RuleSetProposal(
            policy_name=f"adv_mfa_bypass_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_external_fasttrack",
                    priority=10,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=True),
                        RuleCondition(field="clearance_level", op=">=", value=clearance),
                        RuleCondition(field="amount", op="<=", value=threshold),
                    ],
                )
            ],
        )
        mfa_repaired = RuleSetProposal(
            policy_name=f"adv_mfa_bypass_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_external_mfa_verified",
                    priority=10,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=True),
                        RuleCondition(field="mfa_verified", op="==", value=True),
                        RuleCondition(field="clearance_level", op=">=", value=clearance),
                        RuleCondition(field="amount", op="<=", value=threshold),
                    ],
                )
            ],
        )
        cases.append(
            AdversarialPolicyCase(
                case_id=f"mfa_{idx:02d}",
                category="mfa_bypass_injection",
                specification=f"[CASE:mfa_{idx:02d}] External transfer up to {threshold} with MFA",
                flawed_proposal=mfa_flawed,
                repaired_proposal=mfa_repaired,
            )
        )

        # 2. Priority collision (same priority ALLOW vs DENY with overlapping predicate space)
        coll_flawed = RuleSetProposal(
            policy_name=f"adv_priority_collision_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_internal_ops",
                    priority=20,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="clearance_level", op=">=", value=3),
                    ],
                ),
                PolicyRule(
                    rule_id="deny_high_amount",
                    priority=20,
                    effect="DENY",
                    conditions=[
                        RuleCondition(field="amount", op=">", value=threshold),
                    ],
                ),
            ],
        )
        coll_repaired = RuleSetProposal(
            policy_name=f"adv_priority_collision_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_internal_bounded",
                    priority=20,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="clearance_level", op=">=", value=3),
                        RuleCondition(field="amount", op="<=", value=threshold),
                    ],
                ),
                PolicyRule(
                    rule_id="deny_high_amount",
                    priority=20,
                    effect="DENY",
                    conditions=[
                        RuleCondition(field="amount", op=">", value=threshold),
                    ],
                ),
            ],
        )
        cases.append(
            AdversarialPolicyCase(
                case_id=f"coll_{idx:02d}",
                category="priority_collision",
                specification=(
                    f"[CASE:coll_{idx:02d}] Internal clearance >= 3 up to {threshold}, "
                    f"deny above {threshold}"
                ),
                flawed_proposal=coll_flawed,
                repaired_proposal=coll_repaired,
            )
        )

        # 3. Boundary overlap (off-by-one <= vs >= at exact boundary point)
        bound_flawed = RuleSetProposal(
            policy_name=f"adv_boundary_overlap_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_at_or_below_cap",
                    priority=15,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="amount", op="<=", value=threshold),
                    ],
                ),
                PolicyRule(
                    rule_id="deny_at_or_above_cap",
                    priority=15,
                    effect="DENY",
                    conditions=[
                        RuleCondition(field="amount", op=">=", value=threshold),
                    ],
                ),
            ],
        )
        bound_repaired = RuleSetProposal(
            policy_name=f"adv_boundary_overlap_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_strictly_below_cap",
                    priority=15,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="amount", op="<", value=threshold),
                    ],
                ),
                PolicyRule(
                    rule_id="deny_at_or_above_cap",
                    priority=15,
                    effect="DENY",
                    conditions=[
                        RuleCondition(field="amount", op=">=", value=threshold),
                    ],
                ),
            ],
        )
        cases.append(
            AdversarialPolicyCase(
                case_id=f"bound_{idx:02d}",
                category="boundary_overlap",
                specification=(
                    f"[CASE:bound_{idx:02d}] Disjoint threshold partition around {threshold}"
                ),
                flawed_proposal=bound_flawed,
                repaired_proposal=bound_repaired,
            )
        )

        # 4. Dominance / Shadowed redundant rule (r1 subsumes r2 with same effect)
        shadow_flawed = RuleSetProposal(
            policy_name=f"adv_shadowed_rule_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_general_internal",
                    priority=30,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="clearance_level", op=">=", value=2),
                    ],
                ),
                PolicyRule(
                    rule_id="allow_specific_internal_subsumed",
                    priority=10,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="clearance_level", op=">=", value=4),
                        RuleCondition(field="amount", op="<=", value=threshold),
                    ],
                ),
            ],
        )
        shadow_repaired = RuleSetProposal(
            policy_name=f"adv_shadowed_rule_{idx:02d}",
            rules=[
                PolicyRule(
                    rule_id="allow_general_internal",
                    priority=30,
                    effect="ALLOW",
                    conditions=[
                        RuleCondition(field="is_external", op="==", value=False),
                        RuleCondition(field="clearance_level", op=">=", value=2),
                    ],
                ),
            ],
        )
        cases.append(
            AdversarialPolicyCase(
                case_id=f"shadow_{idx:02d}",
                category="dead_or_shadowed_rule",
                specification=(
                    f"[CASE:shadow_{idx:02d}] Deduplicated internal clearance >= 2 policy"
                ),
                flawed_proposal=shadow_flawed,
                repaired_proposal=shadow_repaired,
            )
        )

    return cases


_CASE_TAG_RE = re.compile(r"\[CASE:([a-z0-9_]+)\]")


def build_cegis_repair_transport(
    cases: list[AdversarialPolicyCase],
) -> httpx.MockTransport:
    """Deterministic mock Ollama transport simulating CEGIS repair from Z3 counterexamples."""
    by_id = {c.case_id: c for c in cases}

    def _handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))
        user_msg = str(body["messages"][-1]["content"])
        match = _CASE_TAG_RE.search(user_msg)
        if not match:
            raise ValueError(f"Missing [CASE:<id>] tag in CEGIS prompt: {user_msg!r}")
        case = by_id[match.group(1)]
        has_z3_feedback = "Z3 Formal Counterexamples to fix:" in user_msg
        chosen = case.repaired_proposal if has_z3_feedback else case.flawed_proposal
        payload = {"message": {"content": chosen.model_dump_json()}}
        return httpx.Response(200, json=payload)

    return httpx.MockTransport(_handler)


async def run_adversarial_cegis_benchmark(
    db_path: str | Path,
    per_category: int = 15,
    max_iters: int = 3,
    suite_name: str = "cr012_adversarial_gate",
) -> AdversarialBenchmarkReport:
    """Audit all adversarial specs for 0 false SATs and verify CEGIS convergence <= 3 iters."""
    cases = generate_adversarial_corpus(per_category=per_category)
    false_sat_count = 0

    for case in cases:
        initial_verdict = verify_policy_ruleset(case.flawed_proposal)
        if initial_verdict.status == "SAT":
            false_sat_count += 1

    transport = build_cegis_repair_transport(cases)
    converged_count = 0
    iteration_counts: list[int] = []

    for case in cases:
        res = await run_policy_cegis(
            specification=case.specification,
            db_path=str(db_path),
            max_iters=max_iters,
            transport=transport,
        )
        if res.converged and res.final_verdict is not None and res.final_verdict.status == "SAT":
            converged_count += 1
        iteration_counts.append(res.iterations)

    total_specs = len(cases)
    observed_max_iters = max(iteration_counts) if iteration_counts else 0
    mean_iters = round(sum(iteration_counts) / float(total_specs), 3) if total_specs else 0.0
    passed_gate = (
        total_specs >= 50
        and false_sat_count == 0
        and converged_count == total_specs
        and observed_max_iters <= 3
    )

    store = PolicyAuditStore(db_path)
    try:
        store.record_cegis_benchmark(
            suite_name=suite_name,
            total_specs=total_specs,
            false_sat_count=false_sat_count,
            converged_count=converged_count,
            max_iterations=observed_max_iters,
            mean_iterations=mean_iters,
            passed_gate=passed_gate,
        )
    finally:
        store.close()

    return AdversarialBenchmarkReport(
        suite_name=suite_name,
        total_specs=total_specs,
        false_sat_count=false_sat_count,
        converged_count=converged_count,
        max_iterations=observed_max_iters,
        mean_iterations=mean_iters,
        passed_gate=passed_gate,
    )
