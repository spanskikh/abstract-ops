from __future__ import annotations

import z3

from abstract_ops.contracts import PolicyAuditVerdict, PolicyRule, RuleCondition, RuleSetProposal


def _build_env() -> dict[str, z3.ExprRef]:
    return {
        "clearance_level": z3.Int("clearance_level"),
        "is_external": z3.Bool("is_external"),
        "amount": z3.Int("amount"),
        "mfa_verified": z3.Bool("mfa_verified"),
    }


def _domain_constraints(env: dict[str, z3.ExprRef]) -> list[z3.BoolRef]:
    clearance = env["clearance_level"]
    amount = env["amount"]
    assert isinstance(clearance, z3.ArithRef)
    assert isinstance(amount, z3.ArithRef)
    return [
        clearance >= 1,
        clearance <= 5,
        amount >= 0,
        amount <= 1_000_000,
    ]


def _compile_condition(cond: RuleCondition, env: dict[str, z3.ExprRef]) -> z3.BoolRef:
    var = env[cond.field]
    if cond.field in ("is_external", "mfa_verified"):
        if not isinstance(cond.value, bool):
            raise ValueError(f"Boolean field '{cond.field}' requires bool, got {cond.value!r}")
        assert isinstance(var, z3.BoolRef)
        if cond.op == "==":
            return var == z3.BoolVal(cond.value)
        if cond.op == "!=":
            return var != z3.BoolVal(cond.value)
        raise ValueError(f"Unsupported operator '{cond.op}' for boolean field '{cond.field}'")

    if isinstance(cond.value, bool) or not isinstance(cond.value, int):
        raise ValueError(f"Integer field '{cond.field}' requires int, got {cond.value!r}")
    assert isinstance(var, z3.ArithRef)
    val = z3.IntVal(cond.value)
    ops: dict[str, z3.BoolRef] = {
        "==": var == val,
        "!=": var != val,
        "<": var < val,
        "<=": var <= val,
        ">": var > val,
        ">=": var >= val,
    }
    return ops[cond.op]


def _compile_rule(rule: PolicyRule, env: dict[str, z3.ExprRef]) -> z3.BoolRef:
    clauses = [_compile_condition(c, env) for c in rule.conditions]
    return z3.And(*clauses)


def _extract_model(model: z3.ModelRef, env: dict[str, z3.ExprRef]) -> dict[str, int | bool]:
    out: dict[str, int | bool] = {}
    for name, expr in env.items():
        val = model.evaluate(expr, model_completion=True)
        if z3.is_bool(val):
            out[name] = z3.is_true(val)
        elif z3.is_int_value(val):
            out[name] = val.as_long()
    return out


def verify_policy_ruleset(proposal: RuleSetProposal) -> PolicyAuditVerdict:
    """Формальный аудит набора правил в Z3: достижимость, коллизии ALLOW/DENY, инвариант MFA."""
    env = _build_env()
    domain = _domain_constraints(env)
    compiled: list[tuple[PolicyRule, z3.BoolRef]] = []

    try:
        for rule in proposal.rules:
            compiled.append((rule, _compile_rule(rule, env)))
    except ValueError as exc:
        return PolicyAuditVerdict(
            status="UNSAT",
            policy_name=proposal.policy_name,
            rule_count=len(proposal.rules),
            violations=[f"Type/operator error: {exc}"],
        )

    violations: list[str] = []
    first_ce: dict[str, int | bool] | None = None

    # 1. Проверка достижимости каждого правила (отлов dead/contradictory rules)
    for rule, expr in compiled:
        s_reach = z3.Solver()
        s_reach.add(*domain, expr)
        if s_reach.check() != z3.sat:
            violations.append(f"Unreachable (dead) rule '{rule.rule_id}': contradictory conditions")

    # 2. Попарная проверка коллизий ALLOW vs DENY на одинаковом приоритете
    for i in range(len(compiled)):
        r1, e1 = compiled[i]
        for j in range(i + 1, len(compiled)):
            r2, e2 = compiled[j]
            if r1.priority == r2.priority and r1.effect != r2.effect:
                s_conflict = z3.Solver()
                s_conflict.add(*domain, e1, e2)
                if s_conflict.check() == z3.sat:
                    ce = _extract_model(s_conflict.model(), env)
                    if first_ce is None:
                        first_ce = ce
                    violations.append(
                        f"Ambiguous conflict at priority={r1.priority} between "
                        f"'{r1.rule_id}' ({r1.effect}) and '{r2.rule_id}' ({r2.effect}) on {ce}"
                    )

    # 3. Железный инвариант безопасности: внешний пользователь без MFA не может получить ALLOW
    is_ext = env["is_external"]
    mfa_ok = env["mfa_verified"]
    assert isinstance(is_ext, z3.BoolRef) and isinstance(mfa_ok, z3.BoolRef)
    for rule, expr in compiled:
        if rule.effect == "ALLOW":
            s_sec = z3.Solver()
            s_sec.add(*domain, expr, is_ext == z3.BoolVal(True), mfa_ok == z3.BoolVal(False))
            if s_sec.check() == z3.sat:
                ce = _extract_model(s_sec.model(), env)
                if first_ce is None:
                    first_ce = ce
                violations.append(
                    f"Security invariant violated by '{rule.rule_id}': "
                    f"external user without MFA granted ALLOW on {ce}"
                )

    if violations:
        return PolicyAuditVerdict(
            status="UNSAT",
            policy_name=proposal.policy_name,
            rule_count=len(proposal.rules),
            violations=violations,
            counterexample=first_ce,
        )

    return PolicyAuditVerdict(
        status="SAT",
        policy_name=proposal.policy_name,
        rule_count=len(proposal.rules),
    )
