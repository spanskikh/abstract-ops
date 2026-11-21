from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FeatureName = Literal["clearance_level", "is_external", "amount", "mfa_verified"]
CompareOp = Literal["==", "!=", "<", "<=", ">", ">="]


class RuleCondition(BaseModel):
    """Атомарный предикат над входным вектором контекста."""

    field: FeatureName
    op: CompareOp
    value: int | bool


class PolicyRule(BaseModel):
    """Декларативное правило доступа/андеррайтинга."""

    rule_id: str = Field(min_length=1, max_length=64)
    priority: int = Field(ge=1, le=100, default=10)
    effect: Literal["ALLOW", "DENY"]
    conditions: list[RuleCondition] = Field(min_length=1, max_length=8)


class RuleSetProposal(BaseModel):
    """Набор политик, сгенерированный LLM или переданный на аудит."""

    policy_name: str = Field(min_length=1, max_length=64)
    rules: list[PolicyRule] = Field(min_length=1, max_length=32)


class PolicyAuditVerdict(BaseModel):
    """Детерминированный отчёт Z3-аудитора с точными контрпримерами."""

    status: Literal["SAT", "UNSAT"]
    policy_name: str
    rule_count: int
    violations: list[str] = Field(default_factory=list)
    counterexample: dict[str, int | bool] | None = None
