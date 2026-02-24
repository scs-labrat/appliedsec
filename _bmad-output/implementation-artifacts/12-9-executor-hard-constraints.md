# Story 12.9: Executor Hard Constraints

Status: review

## Story

As a platform resilient to compromised LLM output,
I want hard constraints enforced in the orchestrator code (not the LLM) preventing LLM output from changing routing policy, bypassing confidence thresholds, executing non-allowlisted playbooks, or exfiltrating data,
so that even a fully compromised LLM cannot cause unauthorized actions.

## Acceptance Criteria

1. **Given** LLM output requesting a playbook not in the allowlist, **When** processed by the response agent, **Then** the playbook execution is blocked and logged to audit with `constraint_blocked_type: "unauthorized_playbook"`.
2. **Given** auto-close action, **When** attempted, **Then** it requires BOTH confidence > threshold AND FP pattern match — enforced in `ResponseAgent` code, not LLM compliance.
3. **Given** the `ROLE_PERMISSIONS` matrix, **When** an agent attempts an action outside its allowed set, **Then** the action is blocked by code enforcement.
4. **Given** an integration test with injection payload in alert description requesting playbook execution, **When** run through the full pipeline, **Then** the injection cannot trigger unauthorized playbook execution.

## Tasks / Subtasks

- [x] Task 1: Create ExecutorConstraints and PlaybookAllowlist (AC: 1)
  - [x] 1.1: Create `orchestrator/executor_constraints.py` with `ExecutorConstraints` frozen dataclass.
  - [x] 1.2: Add `DEFAULT_CONSTRAINTS` instance with sensible defaults.
  - [x] 1.3: Add `validate_playbook(playbook_id: str, constraints: ExecutorConstraints) -> bool` function that checks allowlist.
  - [x] 1.4: Add `validate_auto_close(confidence: float, fp_matched: bool, constraints: ExecutorConstraints) -> bool` function that checks BOTH confidence > threshold AND fp_match when `require_fp_match_for_auto_close` is True.
  - [x] 1.5: Add unit tests — `TestExecutorConstraints` class (11 tests)
- [x] Task 2: Create RolePermissionEnforcer (AC: 3)
  - [x] 2.1: Add `RolePermissionEnforcer` class with `ROLE_PERMISSIONS` matrix.
  - [x] 2.2: Add `check_permission(agent_role: str, action: str) -> bool` method that checks the matrix.
  - [x] 2.3: Add `enforce_permission(agent_role: str, action: str) -> None` method that raises `PermissionDeniedError` if not allowed.
  - [x] 2.4: Add `PermissionDeniedError(Exception)` to the module.
  - [x] 2.5: Add unit tests — `TestRolePermissions` class (10 tests)
- [x] Task 3: Integrate constraints into ResponseAgent (AC: 1, 2)
  - [x] 3.1: Add `constraints: ExecutorConstraints` parameter to `ResponseAgent.__init__()` (default: `DEFAULT_CONSTRAINTS`). Backward compat preserved.
  - [x] 3.2: In `ResponseAgent._execute_action()`, validate playbook allowlist, auto-close criteria, routing policy modification. Log blocked actions with `constraint_blocked_type`.
  - [x] 3.3: Add unit tests — `TestExecutorConstraintIntegration` class (6 tests)
- [x] Task 4: Add injection-through-pipeline integration test (AC: 4)
  - [x] 4.1: Add `TestInjectionCannotTriggerPlaybook` — injection playbook blocked, audit event published, investigation completes.
  - [x] 4.2: Add routing policy change silently blocked test. (3 tests total)
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite (`pytest tests/`) — 1399 tests pass (zero regressions, 30 new)
  - [x] 5.2: Verify existing `ResponseAgent` tests still pass (17/17 backward compat via default constraints)

## Dev Notes

### Critical Architecture Constraints

- **This is Part D of REM-C03.** The executor constraints are the last line of defense — even if all injection detection fails, constraints prevent unauthorized actions.
- **Constraints are enforced by CODE, not LLM compliance.** The LLM may request any action. The orchestrator code validates every action against constraints before execution.
- **DO NOT modify existing `ResponseAgent.execute()` flow** beyond adding constraint checks. The stage ordering (classify → execute auto → publish gated) remains unchanged.
- **Backward compat is mandatory.** `ResponseAgent()` with no `constraints` parameter must work identically to before (uses `DEFAULT_CONSTRAINTS`).
- **`ROLE_PERMISSIONS` is defined in orchestrator code**, not in LLM prompts. Agents are identified by their code path, not by what the LLM says they are.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `ResponseAgent` | `orchestrator/agents/response_agent.py:25-131` | Action execution. **Extend with constraint checks.** |
| `ApprovalGate` | `orchestrator/agents/response_agent.py:133-175` | Approval workflow. **Not modified.** |
| `TIER_AUTO`, `TIER_REQUIRES_APPROVAL` | `orchestrator/agents/response_agent.py:20-22` | Action tier constants. **Reference for tier-based constraint logic.** |
| `AgentRole` | `shared/schemas/investigation.py` | Agent role enum. **Use values for permission matrix keys.** |
| `InvestigationGraph` | `orchestrator/graph.py:25-225` | Pipeline executor. **Not modified; constraints are at agent level.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Response agent | `orchestrator/agents/response_agent.py` |
| Investigation graph | `orchestrator/graph.py` |
| Reasoning agent | `orchestrator/agents/reasoning_agent.py` |
| Investigation schemas | `shared/schemas/investigation.py` |
| Executor constraints (NEW) | `orchestrator/executor_constraints.py` |
| Constraint tests (NEW) | `tests/test_orchestrator/test_executor_constraints.py` |
| Response agent tests | `tests/test_orchestrator/test_response_agent.py` |
| Integration tests | `tests/test_orchestrator/test_integration.py` |

### Constraint Enforcement Points

```
LLM Output (untrusted)
    │
    ▼
┌─────────────────────────────────────┐
│ ResponseAgent._execute_action()     │
│                                     │
│ ┌─ validate_playbook()             │ ◄── Is playbook in allowlist?
│ │  ✗ → log "unauthorized_playbook"  │
│ │  ✓ → continue                     │
│ └───────────────────────────────────│
│ ┌─ validate_auto_close()           │ ◄── confidence > 0.85 AND fp_match?
│ │  ✗ → log "insufficient_criteria"  │
│ │  ✓ → continue                     │
│ └───────────────────────────────────│
│ ┌─ RolePermissionEnforcer          │ ◄── Agent role allows this action?
│ │  ✗ → PermissionDeniedError        │
│ │  ✓ → execute                      │
│ └───────────────────────────────────│
└─────────────────────────────────────┘
```

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_response_agent.py (17 tests):**
- `TestResponseAgent` — 5 tests
- `TestActionClassification` — 4 tests
- `TestApprovalGate` — 8 tests

**test_integration.py (6 tests):**
- `TestHappyPathIntegration` — 1 test
- `TestEscalationIntegration` — 1 test
- `TestDestructiveActionIntegration` — 1 test
- `TestFPShortCircuitIntegration` — 1 test
- `TestErrorResilienceIntegration` — 1 test
- `TestAuditTrailIntegration` — 1 test

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Constraint tests: pure synchronous unit tests (no async needed for validation)
- Response agent tests: async tests with mocked postgres_client and kafka_producer
- Integration tests: construct full GraphState with injection payloads

### References

- [Source: docs/remediation-backlog.md#REM-C03 Part D] — Executor hard constraints requirements
- [Source: docs/ai-system-design.md Section 10.1-10.2] — Permission matrix and accumulation guards
- [Source: docs/prd.md#NFR-SEC-005] — Role-based permission enforcement
- [Source: docs/prd.md#FR-RSP-005] — Playbook execution controls

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

### Completion Notes List

- `ExecutorConstraints` frozen dataclass with allowlisted_playbooks, min_confidence_for_auto_close, require_fp_match_for_auto_close, can_modify_routing_policy, can_disable_guardrails
- `DEFAULT_CONSTRAINTS` instance blocks all playbooks, requires confidence > 0.85 AND fp_match for auto-close, blocks routing policy/guardrail changes
- `validate_playbook()` checks allowlist membership; `validate_auto_close()` requires BOTH confidence AND fp_match
- `ROLE_PERMISSIONS` matrix: ioc_extractor, context_enricher, reasoning_agent, response_agent with specific action sets
- `RolePermissionEnforcer.check_permission()` returns bool; `.enforce_permission()` raises `PermissionDeniedError`
- `ResponseAgent.__init__()` accepts optional `constraints` param with backward compat (defaults to `DEFAULT_CONSTRAINTS`)
- `_execute_action()` validates playbook allowlist, auto-close criteria, routing policy before executing
- `_publish_action()` extended with optional `constraint_blocked_type` field for audit events
- All 17 existing ResponseAgent tests pass unchanged — backward compat confirmed
- All 6 existing integration tests pass unchanged
- 30 new tests, 1399 total passing

### File List

**Created:**
- `orchestrator/executor_constraints.py` — ExecutorConstraints, DEFAULT_CONSTRAINTS, validate_playbook, validate_auto_close, ROLE_PERMISSIONS, RolePermissionEnforcer, PermissionDeniedError
- `tests/test_orchestrator/test_executor_constraints.py` — 21 constraint unit tests (2 test classes)

**Modified:**
- `orchestrator/agents/response_agent.py` — added constraints parameter, constraint validation in _execute_action(), constraint_blocked_type in _publish_action()
- `tests/test_orchestrator/test_response_agent.py` — added TestExecutorConstraintIntegration (6 tests)
- `tests/test_orchestrator/test_integration.py` — added TestInjectionCannotTriggerPlaybook (3 tests)

### Change Log

- 2026-02-21: Story 12.9 implemented — ExecutorConstraints, RolePermissionEnforcer, ResponseAgent constraint integration. 30 new tests, 1399 total passing.
