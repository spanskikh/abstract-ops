# Changelog

All notable changes and formal Change Requests (CRs) for `abstract-ops` are documented in this file.

## [0.9.0] - 2026-11-23 — CR-026: Shared `CycloneDX` PEP 610 `file://` Sanitizer CLI Integration
### Objective & Risk Mitigated
- **Closed Residual Risk:** Replaced local inline PEP 610 `file://` SBOM sanitization in `tests/test_sbom_and_contracts.py` with delegation to the shared `sandbox_init.sbom` sanitizer CLI (`CAPA-007`) while retaining an isolated single-repo CI fallback.
- **Traceability:** Change Request `CR-026` (`tests/test_sbom_and_contracts.py`).

### Added & Changed
- `tests/test_sbom_and_contracts.py` (`CR-026` / `CAPA-007`): Invokes `python -m sandbox_init.sbom --input ... --output ... --verify --format summary` from sibling `sandbox-init/src` during two-run `CycloneDX` SBOM reproducibility and host-path hygiene verification.

### Verification Evidence
- `./scripts/run_logged.sh cr026_ruff -- .venv/bin/ruff check src tests`: `All checks passed!` (`0` errors).
- `./scripts/run_logged.sh cr026_mypy -- .venv/bin/mypy src tests --strict`: `Success: no issues found in 14 source files`.
- `./scripts/run_logged.sh cr026_pytest -- .venv/bin/pytest -v -m "not integration"`: `36 passed, 1 deselected`.

## [0.8.0] - 2026-11-23 — CR-022 & CR-023: Cross-Cluster Z3 Contract, SBOM Gate & Rubric Sign-Off
### Objective & Risk Mitigated
- **Closed Residual Risk:** Enforced cross-cluster Z3 RAM budget invariants (`hippo` 24 GiB / `rhino` 16 GiB), 12-tool FastMCP namespace disjointness, deterministic `CycloneDX` SBOM reproducibility, and grammar-constrained live Ollama documentation rubric evaluation (`>= 4/5`).
- **Traceability:** Change Requests `CR-022` and `CR-023` (`BUG-003` / `CAPA-006`) merged via `--no-ff`; release `v0.8.0`.

### Added & Changed
- `pyproject.toml` & `.github/workflows/ci.yml` (`CR-022`): Bump version to `0.8.0`, add `cyclonedx-bom>=7.2.0`, and verify two-run `CycloneDX` SBOM determinism and path hygiene in CI.
- `tests/test_sbom_and_contracts.py` (`CR-022`): Cross-cluster Z3 SAT/UNSAT budget solver, 12-tool FastMCP namespace disjointness check, and `CycloneDX` SBOM reproducibility gate.
- `tests/test_docs_quality.py` (`CR-023` / `BUG-003` / `CAPA-006`): Upgraded `_judge_doc_with_ollama` to JSON Schema grammar-constrained decoding (`DocRubricScore.model_json_schema()`, `temperature=0.0`, `timeout=180.0`).

### Verification Evidence
- `ruff check src tests` & `mypy src tests --strict`: `0` issues across all source and test modules.
- `pytest -m "not integration"`: `36 passed` (including `CR-022` Z3 cluster and `CycloneDX` SBOM gates).
- `pytest -v -m integration`: `1 passed` against live `hippo` Ollama (`qwen2.5-coder:7b`) and `rhino` PostgreSQL.

## [0.7.0] - 2026-11-23 — CR-017..CR-021: Engineering Profiles, SSoT Governance & Auditor Fix
### Objective & Risk Mitigated
- **Closed Residual Risk:** Eliminated cross-repository inconsistency in how theoretical foundations, library versions, workstation environment, SDLC/QA processes, and empirical benchmark metrics are presented to technical reviewers; enforced structural compliance via automated AST/regex quality gates.
- **Traceability:** Change Request `CR-017` implemented across `abstract-ops` (`docs/ENGINEERING_PROFILE.md`, `README.md`, `tests/test_docs_quality.py`, `RELEASES.md`).

### Added
- `docs/ENGINEERING_PROFILE.md`: Standardized 5-section engineering dossier (`1. Concepts and Theories`, `2. Frameworks and Libraries`, `3. Dev Tools and Environment`, `4. Processes and Procedures`, `5. Test Approach, Tools, Environment & Metrics`).
- `README.md`: Added direct navigation link to `docs/ENGINEERING_PROFILE.md`.
- `tests/test_docs_quality.py`: Added mandatory file, 5-heading structural assertions, signal density checks, and `2` new seeded defect counterexamples (`missing_engineering_profile`, `missing_profile_section`).

- `DEVPROCESS.md` & `tests/test_docs_quality.py` (`CR-019` / `CAPA-003`): Enforced `<= 1.5 KiB` PTY paste cap and `logs/` summary cap.

- `README.md` & SSoT Migration (`CR-020` / `CAPA-004`): Consolidated shared governance docs (`DEVPROCESS.md`, `RELEASES.md`, `docs/DEFECTS_AND_CAPA.md`, `docs/releases/*`) into `spanskikh/spanskikh` and linked canonical URLs.
- `tests/test_docs_quality.py` (`CR-021` / `BUG-002` / `CAPA-005`): Fixed Markdown auditor to scan all tracked `*.md` files recursively for Cyrillic/placeholders and enforce `CLUSTER_DOC_DUPLICATE`.

### Verification Evidence
- `ruff check .` & `mypy --strict`: `0` issues across all source and test modules.
- `pytest -m "not integration"`: All unit, contract, hygiene, and documentation quality tests green (`+2` new counterexample cases).

## [0.6.0] - 2026-11-22 — CR-014, CR-015 & CR-016: Pre-Public Hygiene Gate, Portfolio Sync & Public CI / CycloneDX Activation
### Objective & Risk Mitigated
- **Closed Residual Risk:** Enforced automated pre-public secret/PII hygiene checks, synchronized `README.md` and `docs/ARCHITECTURE.md` with adversarial CEGIS verification metrics (`0` false `SAT` across `180` specs, `2`-iteration convergence), and activated GitHub Actions CI + `CycloneDX` SBOM generation.
- **Traceability:** Branches `feat/cr-014-release-hygiene-gate` (`ae63909`), `feat/cr-015-portfolio-landing-sync` (`f1c369f`), and `CR-016` CI promotion merged via `--no-ff`; releases `v0.6.0`.

### Added
- `tests/test_release_hygiene.py`: Pre-public tracked-file secret/PII scanner and CI readiness assertions.
- `docs/ci/ci.yml` -> `.github/workflows/ci.yml` & `scripts/publish_to_github.sh`: Automated CI verification and `CycloneDX` SBOM artifact generation.
- `README.md` & `docs/ARCHITECTURE.md`: Added empirical adversarial and property-fuzzing benchmark table.

### Verification Evidence
- `./scripts/run_logged.sh cr015_ruff`: `All checks passed!`
- `./scripts/run_logged.sh cr015_mypy`: `Success: no issues found in 13 source files`
- `./scripts/run_logged.sh cr015_pytest`: `32 passed, 1 deselected`

## [0.6.0] - 2026-11-22 — CR-014, CR-015 & CR-016: Pre-Public Hygiene Gate, Portfolio Sync & Public CI / CycloneDX Activation
### Objective & Risk Mitigated
- **Closed Residual Risk:** Enforced automated pre-public secret/PII hygiene checks, synchronized `README.md` and `docs/ARCHITECTURE.md` with adversarial CEGIS verification metrics (`0` false `SAT` across `180` specs, `2`-iteration convergence), and activated GitHub Actions CI + `CycloneDX` SBOM generation.
- **Traceability:** Branches `feat/cr-014-release-hygiene-gate` (`ae63909`), `feat/cr-015-portfolio-landing-sync` (`f1c369f`), and `CR-016` CI promotion merged via `--no-ff`; releases `v0.6.0`.

### Added
- `tests/test_release_hygiene.py`: Pre-public tracked-file secret/PII scanner and CI readiness assertions.
- `docs/ci/ci.yml` -> `.github/workflows/ci.yml` & `scripts/publish_to_github.sh`: Automated CI verification and `CycloneDX` SBOM artifact generation.
- `README.md` & `docs/ARCHITECTURE.md`: Added empirical adversarial and property-fuzzing benchmark table.

### Verification Evidence
- `./scripts/run_logged.sh cr015_ruff`: `All checks passed!`
- `./scripts/run_logged.sh cr015_mypy`: `Success: no issues found in 13 source files`
- `./scripts/run_logged.sh cr015_pytest`: `32 passed, 1 deselected`

## [0.6.0] - 2026-11-22 — CR-014, CR-015 & CR-016: Pre-Public Hygiene Gate, Portfolio Sync & Public CI / CycloneDX Activation
### Objective & Risk Mitigated
- **Closed Residual Risk:** Enforced automated pre-public secret/PII hygiene checks, synchronized `README.md` and `docs/ARCHITECTURE.md` with adversarial CEGIS verification metrics (`0` false `SAT` across `180` specs, `2`-iteration convergence), and activated GitHub Actions CI + `CycloneDX` SBOM generation.
- **Traceability:** Branches `feat/cr-014-release-hygiene-gate` (`ae63909`), `feat/cr-015-portfolio-landing-sync` (`f1c369f`), and `CR-016` CI promotion merged via `--no-ff`; releases `v0.6.0`.

### Added
- `tests/test_release_hygiene.py`: Pre-public tracked-file secret/PII scanner and CI readiness assertions.
- `docs/ci/ci.yml` -> `.github/workflows/ci.yml` & `scripts/publish_to_github.sh`: Automated CI verification and `CycloneDX` SBOM artifact generation.
- `README.md` & `docs/ARCHITECTURE.md`: Added empirical adversarial and property-fuzzing benchmark table.

### Verification Evidence
- `./scripts/run_logged.sh cr015_ruff`: `All checks passed!`
- `./scripts/run_logged.sh cr015_mypy`: `Success: no issues found in 13 source files`
- `./scripts/run_logged.sh cr015_pytest`: `32 passed, 1 deselected`

## [0.6.0] - 2026-11-22 — CR-014, CR-015 & CR-016: Pre-Public Hygiene Gate, Portfolio Sync & Public CI / CycloneDX Activation
### Objective & Risk Mitigated
- **Closed Residual Risk:** Enforced automated pre-public secret/PII hygiene checks, synchronized `README.md` and `docs/ARCHITECTURE.md` with adversarial CEGIS verification metrics (`0` false `SAT` across `180` specs, `2`-iteration convergence), and activated GitHub Actions CI + `CycloneDX` SBOM generation.
- **Traceability:** Branches `feat/cr-014-release-hygiene-gate` (`ae63909`), `feat/cr-015-portfolio-landing-sync` (`f1c369f`), and `CR-016` CI promotion merged via `--no-ff`; releases `v0.6.0`.

### Added
- `tests/test_release_hygiene.py`: Pre-public tracked-file secret/PII scanner and CI readiness assertions.
- `docs/ci/ci.yml` -> `.github/workflows/ci.yml` & `scripts/publish_to_github.sh`: Automated CI verification and `CycloneDX` SBOM artifact generation.
- `README.md` & `docs/ARCHITECTURE.md`: Added empirical adversarial and property-fuzzing benchmark table.

### Verification Evidence
- `./scripts/run_logged.sh cr015_ruff`: `All checks passed!`
- `./scripts/run_logged.sh cr015_mypy`: `Success: no issues found in 13 source files`
- `./scripts/run_logged.sh cr015_pytest`: `32 passed, 1 deselected`

## [0.5.0] - 2026-11-22 — CR-010, CR-012 & CR-013: FastMCP `stdio` Contract Harness & Adversarial Policy Fuzzing Gate
### Objective & Risk Mitigated
- **Closed Residual Risk:** Proved that the Z3 policy auditor and CEGIS repair loop reject 100% of adversarial MFA bypasses, priority collisions, boundary off-by-one overlaps, and shadowed rules within bounded CPU iterations (`<= 3`), while enforcing strict MCP `stdio` JSON-RPC contracts.
- **Traceability:** Branches `feat/cr-010-mcp-stdio-contracts` and `feat/cr-012-adversarial-cegis-gate` (`cae824d`) merged via `--no-ff`; releases `v0.5.0`.

### Added
- `tests/test_mcp_contracts.py`: Real `mcp.client.stdio` discovery, JSON schema checks, `SAT`/`UNSAT` Z3 policy audit verification, and malformed payload rejection for `audit_policy_ruleset` and `synthesize_verified_policy`.
- `src/abstract_ops/adversarial.py`, `src/abstract_ops/store.py` & `tests/test_adversarial_cegis.py`: Deterministic adversarial corpus generator (`60` specs across 4 attack categories), `Hypothesis` property fuzzing (`120` randomized MFA-bypass and boundary-collision specs), CEGIS convergence benchmark (`cegis_benchmarks` table in `DuckDB`), and full audit trail (`120` Z3 verdicts persisted in `policy_audits`).
- `DEVPROCESS.md` & `docs/DEFECTS_AND_CAPA.md` (`CAPA-002`): Codified normative SDLC and English-only Git governance.

### Verification Evidence
- `./scripts/run_logged.sh cr012_ruff` (`logs/20261122-160233_cr012_ruff.log`): `All checks passed!`
- `./scripts/run_logged.sh cr012_mypy` (`logs/20261122-160233_cr012_mypy.log`): `Success: no issues found in 12 source files`
- `./scripts/run_logged.sh cr012_pytest` (`logs/20261122-160234_cr012_pytest.log`): `24 passed, 1 deselected` (`0` false `SAT` across `60` adversarial + `120` Hypothesis specs; CEGIS convergence in `2` iterations).

## [0.4.0] - 2026-11-22 — CR-009: Dev-Process Auditability, Execution Logging & Release Retrospectives
### Objective & Risk Mitigated
- **Closed Residual Risk:** Eliminated loss of iterative engineering history, unlogged local execution runs, and missing post-release retrospectives across `abstract-ops` by introducing deterministic `.stdout`/`.stderr`/`.log` capture, versioned `docs/dev-log/` artifacts, and mandatory release retrospectives enforced by automated mutation tests.
- **Traceability:** Branch `feat/cr-009-dev-process-auditability` merged via `--no-ff`; releases `v0.4.0`.

### Added
- `scripts/run_logged.sh` & `tests/test_run_logged.py`: POSIX execution wrapper capturing ISO-8601 start/end timestamps, duration, exit codes, and split `.stdout`, `.stderr`, and `.log` artifacts in gitignored `logs/`.
- `docs/dev-log/`: Versioned raw patch/script artifact history (`20261122-130500_cr-009_install-run-logged.sh`, `20261122-130800_cr-009_enforce-release-retrospectives.py`).
- `docs/releases/v0.3.0-retrospective.md` & `tests/test_docs_quality.py`: Post-release retrospective capturing Lessons Learned, Rejected Ideas, Unlucky Probe-Runs, and Release Chat Digest, enforced by an 8th seeded mutation counterexample (`missing_retrospective_section`).

### Verification Evidence
- `./scripts/run_logged.sh cr009_final_gate`: `ruff check src tests` (`All checks passed!`), `mypy src tests --strict` (`Success: no issues found`), `pytest -v -m "not integration"` (`16 passed, 1 deselected`).

## [0.3.0] - 2026-11-22 — CR-008: Documentation Quality Gates, Mutation Counterexamples & Live Rubric Evaluation
### Objective & Risk Mitigated
- **Closed Residual Risk:** Eliminated documentation drift, broken relative links, unclosed Mermaid diagrams, unresolved placeholders, and hollow marketing claims across `abstract-ops` through deterministic structural/style/market-value checks, 7 seeded negative mutation counterexamples, and live `Ollama` rubric grading.
- **Traceability:** Branch `feat/cr-008-docs-quality-tests` merged via `--no-ff`; releases `v0.3.0`.

### Added
- `docs/ARCHITECTURE.md`: Added Level-2 domain architecture with Mermaid topology, ADRs, and trade-off/risk control matrix.
- `tests/test_docs_quality.py`: `DocQualityAuditor` (`Pydantic v2`), 7 parametrized negative mutation counterexamples (`MISSING_REQUIRED_FILE`, `LANGUAGE_DRIFT_CYRILLIC`, `MISSING_REQUIRED_SECTION`, `PLACEHOLDER_LEAK`, `BROKEN_MERMAID_BLOCK`, `BROKEN_RELATIVE_LINK`, `LOW_MARKET_SIGNAL_OR_HYPE`), and `@pytest.mark.integration` live `Ollama` rubric test (`num_ctx=2048`, `num_predict=160`, `timeout=180.0` tuned for CPU inference on `hippo`).
- `pyproject.toml`: Standardized version `0.3.0`, `[project.optional-dependencies] dev`, `pythonpath = ["src"]`, and `@pytest.mark.integration` marker.

### Verification Evidence
- `ruff check src tests`: `All checks passed!`
- `mypy src tests --strict`: `Success: no issues found`
- `pytest -v -m "not integration"`: `14 passed, 1 deselected` (including all 7 seeded mutation counterexamples)
- `pytest -v -m "integration"`: `1 passed, 14 deselected` (live `Ollama` rubric >= 4/5 on real docs and <= 2/5 on weak counterexample)

## [0.3.0-cr006] - 2026-11-22 — CR-006: Offline GitHub Actions CI & CycloneDX SBOM Blueprints
### Objective & Risk Mitigated
- **Closed Residual Risk:** Standardized pre-release verification (`ruff`, `mypy --strict`, `pytest -m "not integration"`) and supply-chain `CycloneDX` SBOM generation across `abstract-ops` without triggering premature CI runs while the repository remains private.
- **Traceability:** Branch `feat/cr-006-ci-blueprints` merged via `--no-ff`.

### Added
- `docs/ci/ci.yml`: Staged GitHub Actions workflow (`uv`, `ruff`, `mypy --strict`, `pytest`, `cyclonedx-py` SBOM artifact upload).
- `scripts/publish_to_github.sh`: Deterministic pre-flight and promotion script (`git mv docs/ci/ci.yml .github/workflows/ci.yml` + `gh repo edit --visibility public`).

### Verification Evidence
- `docs/ci/ci.yml` YAML indentation validated and staged cleanly; `.github/workflows/` kept absent until public release.

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
