# Changelog

All notable changes and formal Change Requests (CRs) for `abstract-ops` are documented in this file.

## [0.2.0] - 2026-11-21 — CR-002: Z3 Rule Dominance & Shadowing Detection
### Objective & Risk Mitigated
* **Closed Residual Risk:** Prevented silent policy bloat and unobservable logic masking where a specific rule is completely subsumed by a broader rule with the same `ALLOW`/`DENY` effect (`UNSAT(e_2 and not e_1)`).
* **Traceability:** Branch `feat/cr-002-rule-shadowing-detection` merged via `--no-ff` (`c364e28`).

### Added
* `src/abstract_ops/verifier.py`: Formal Z3 subsumption/shadowing check across all reachable same-effect rule pairs (`priority_1 >= priority_2`), extracting concrete witness vectors on violation.
* `tests/test_policy_auditor.py`: `test_detects_shadowed_redundant_rule` verifying detection of subsumed lower-priority rules.

### Verification Evidence
* `ruff check src tests`: `All checks passed!`
* `mypy src tests` (`--strict`): `0` issues across `7` source files.
* `pytest -v`: `6 passed` (100% detection of dead rules, `ALLOW`/`DENY` collisions, MFA breaches, and shadowed rules).

## [0.1.0] - 2026-11-21 — Policy Auditor & CEGIS Baseline
* Initial Z3 SMT rule-set compiler, reachability/disjointness/MFA security invariant checks, CEGIS repair loop, and `DuckDB` audit trail.
