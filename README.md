# abstract-ops — Formal Policy & Rule-Set Auditor (CEGIS)

Нейро-символический аудитор декларативных политик доступа (RBAC) и финансового андеррайтинга. Компилирует JSON-правила, сгенерированные локальной LLM, в SMT-формулы Z3 для математического доказательства непротиворечивости.

## Архитектура аудита

```mermaid
flowchart TD
    SPEC[Natural Language Policy Spec] --> LLM[Ollama: qwen2.5-coder:7b]
    LLM -->|RuleSetProposal| Z3{Z3 Formal Auditor}
    Z3 -->|1. Reachability| DEAD[Dead / Contradictory Rule Check]
    Z3 -->|2. Pairwise Disjointness| CONF[ALLOW vs DENY Collision Check]
    Z3 -->|3. Security Guardrail| MFA[External User Requires MFA]
    DEAD & CONF & MFA -->|SAT| DB[(DuckDB Audit Store)]
    DEAD & CONF & MFA -->|UNSAT + Exact Vector CE| LLM
```

## Классы обнаруживаемых дефектов
* **Dead Rules:** правила с внутренне противоречивыми условиями (например, `amount > 50000` и `amount < 10000`).
* **Policy Ambiguity:** пересечение областей истинности `ALLOW` и `DENY` на одном приоритете с выдачей точного контрпримера из пространства признаков.
* **Security Invariant Breach:** формальное доказательство невозможности получения `ALLOW` при `is_external == True` и `mfa_verified == False`.

## MCP-инструменты (`FastMCP` / `stdio`)
* `audit_policy_ruleset` — детерминированный аудит набора правил `RuleSetProposal` через Z3.
* `synthesize_verified_policy` — синтез формально непротиворечивой политики из текстового ТЗ в цикле CEGIS.

## Запуск и QA-гейт
```bash
docker compose build auditor
docker compose run --rm auditor sh -c "ruff check src tests && mypy src tests && pytest -v"
docker compose run --rm auditor python -m abstract_ops.cegis
```
