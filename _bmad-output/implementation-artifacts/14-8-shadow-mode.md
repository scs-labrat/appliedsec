# Story 14.8: Shadow Mode

Status: review

## Story

As a platform validating autonomous decisions before production,
I want a `SHADOW_MODE` flag (per-tenant, per-rule-family) where the full pipeline runs but decisions are logged without execution, with agreement rate tracking against analyst decisions,
so that every new tenant starts in shadow mode and must meet go-live criteria before autonomy is enabled.

## Acceptance Criteria

1. **Given** shadow mode is active for a tenant, **When** the pipeline processes an alert, **Then** the full pipeline runs but decisions are NOT executed; the analyst makes the actual decision.
2. **Given** shadow mode, **When** decisions are compared to analyst actions, **Then** `aluskort_shadow_agreement_rate{tenant, rule_family}` is tracked.
3. **Given** go-live criteria, **When** documented, **Then** they require: agreement >= 95% over 2 weeks, zero missed critical TPs, FP precision >= 98%, cost within projections.
4. **Given** shadow mode, **When** mandatory for every new tenant, **Then** there is no way to bypass shadow mode without explicit sign-off.

## Tasks / Subtasks

- [x] Task 1: Create tenant configuration model (AC: 1, 4)
  - [x] 1.1: Created `shared/config/tenant_config.py` with `TenantConfig` dataclass.
  - [x] 1.2: Added `TenantConfigStore` class (Redis-backed) with `get_config()` and `set_config()`.
  - [x] 1.3: New tenants default to `shadow_mode=True`. `disable_shadow()` and `set_config()` enforce `go_live_signed_off=True`.
  - [x] 1.4: Added unit tests — `TestTenantConfig` (4 tests) + `TestTenantConfigStore` (3 tests).
- [x] Task 2: Create ShadowModeManager (AC: 1, 2)
  - [x] 2.1: Created `orchestrator/shadow_mode.py` with `ShadowModeManager` class — full API.
  - [x] 2.2: Shadow decision logging emits `shadow.decision_logged` event to audit trail.
  - [x] 2.3: Added `TestShadowModeManager` — 8 tests.
- [x] Task 3: Integrate shadow mode into orchestrator graph (AC: 1)
  - [x] 3.1: Added `shadow_mode_manager` parameter to `InvestigationGraph.__init__()`.
  - [x] 3.2: Shadow check at RESPONDING stage: records decision, skips ResponseAgent.execute(), sets AWAITING_HUMAN.
  - [x] 3.3: Backward compat: `shadow_mode_manager=None` works identically to before.
  - [x] 3.4: Added `TestShadowModeIntegration` — 5 tests.
- [x] Task 4: Add go-live criteria and Prometheus metrics (AC: 2, 3)
  - [x] 4.1: Added `GoLiveCriteria` dataclass with `check()` method.
  - [x] 4.2: Added `SHADOW_MODE_METRICS` (2 metrics) to `ops/metrics.py`.
  - [x] 4.3: Added `TestGoLiveCriteria` — 5 tests.
- [x] Task 5: Run full regression (AC: 1-4)
  - [x] 5.1: Run full project test suite — all 1889 tests pass (zero regressions)

## Dev Notes

### Critical Architecture Constraints

- **REM-H05 Part A** — shadow mode is the prerequisite for safe autonomy. No tenant gets autonomous actions without proving agreement with analysts.
- **Full pipeline runs** — shadow mode is NOT a bypass. The full investigation pipeline runs (enrichment, LLM calls, classification). Only the final action execution is skipped.
- **Per-tenant + per-rule-family** — shadow mode can be enabled globally for a tenant or for specific rule families (e.g., new rule types start in shadow).
- **Default shadow for new tenants** — there is NO code path that allows bypassing shadow mode without explicit `go_live_signed_off=True`. This is enforced at the config level.
- **Backward compat** — `InvestigationGraph()` with no `shadow_mode_manager` works identically to before.

### Existing Code You MUST Reuse (DO NOT Reinvent)

| Component | File | What It Does |
|---|---|---|
| `InvestigationGraph` | `orchestrator/graph.py:25-225` | Pipeline executor. **Add shadow check at RESPONDING.** |
| `ResponseAgent` | `orchestrator/agents/response_agent.py` | Action execution. **Skip in shadow mode.** |
| `InvestigationState` | `shared/schemas/investigation.py` | State enum. **Use AWAITING_HUMAN for shadow.** |
| `TENANT_QUOTAS` | `llm_router/concurrency.py` | Per-tenant config pattern. **Follow for tenant config.** |

### Exact File Paths (Verified Against Codebase)

| Target | Correct Path |
|---|---|
| Tenant config (NEW) | `shared/config/tenant_config.py` |
| Shadow mode manager (NEW) | `orchestrator/shadow_mode.py` |
| Shadow mode tests (NEW) | `tests/test_orchestrator/test_shadow_mode.py` |
| Tenant config tests (NEW) | `tests/test_config/test_tenant_config.py` |
| Orchestrator graph | `orchestrator/graph.py` |
| Response agent | `orchestrator/agents/response_agent.py` |
| Metrics | `ops/metrics.py` |

### Existing Test Classes That MUST Still Pass (Unchanged)

**test_orchestrator/ (all existing tests):**
- All 23 tests unchanged (backward compat via None default)

**Total existing: 1169 tests — ALL must pass unchanged.**

### Testing Patterns

- Test framework: **pytest**, **pytest-asyncio**
- Mock ShadowModeManager for graph integration tests
- Mock ResponseAgent.execute to verify it's NOT called in shadow mode
- Test agreement rate math with crafted decision histories
- Test go-live criteria with boundary values

### Dependencies on Other Stories

- **Epic 12 (12.2-12.10)**: shadow mode needs multi-provider + injection hardening before deploying autonomous features

### References

- [Source: docs/remediation-backlog.md#REM-H05 Part A] — Shadow mode requirements
- [Source: docs/ai-system-design.md Section 10] — Deployment safety

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6 (claude-opus-4-6)

### Debug Log References

- 2 failures in `test_tenant_config.py::TestTenantConfigStore` — AsyncMock responds True to `hasattr(_, '_client')`, causing `_get_client()` to return a sub-mock whose `.get()` returns an AsyncMock (not None/str). Fixed by using plain `_FakeRedis` classes without `_client` attribute.

### Completion Notes List

- **Task 1 (Tenant Config):** `TenantConfig` dataclass with `shadow_mode=True` default, `disable_shadow()` enforcing go-live sign-off. `TenantConfigStore` Redis-backed with `get_config()`/`set_config()`, enforcing shadow mode invariant at persistence level. 7 tests.
- **Task 2 (ShadowModeManager):** `is_shadow_active()` checks tenant config (per-tenant + per-rule-family). `record_shadow_decision()` and `record_analyst_decision()` log to Redis lists. `compute_agreement_rate()` pairs shadow/analyst decisions by investigation_id. Audit event emitted on shadow decisions. 8 tests.
- **Task 3 (Graph Integration):** Added `shadow_mode_manager` param (default None, backward compat). Shadow check before RESPONDING stage: if active, logs DecisionEntry, records shadow decision, sets AWAITING_HUMAN, skips ResponseAgent.execute(). 5 tests.
- **Task 4 (Go-Live + Metrics):** `GoLiveCriteria` with min_agreement_rate=0.95, min_window_days=14, max_missed_critical_tp=0, min_fp_precision=0.98, `check()` returning (bool, [unmet]). Added `SHADOW_MODE_METRICS` (2 metrics: agreement_rate gauge, decisions_total counter). 5 tests.
- **Task 5 (Regression):** 1889 tests passed, 0 failures. 1 existing test updated for metrics count (+2 shadow).

### File List

**Created:**
- `shared/config/tenant_config.py` — TenantConfig, TenantConfigStore
- `orchestrator/shadow_mode.py` — ShadowModeManager, GoLiveCriteria
- `tests/test_orchestrator/test_shadow_mode.py` — 18 tests (8 manager + 5 go-live + 5 integration)
- `tests/test_config/test_tenant_config.py` — 7 tests (4 config + 3 store)

**Modified:**
- `orchestrator/graph.py` — added shadow_mode_manager param, shadow check at RESPONDING stage
- `ops/metrics.py` — added SHADOW_MODE_METRICS (2 metrics), updated ALL_METRICS
- `tests/test_ops/test_metrics.py` — updated expected count (+2 shadow)

### Change Log

- 2026-02-24: Story 14.8 implemented — Shadow mode with tenant config, agreement tracking, graph integration, go-live criteria, and Prometheus metrics. 25 new tests, 1889 total tests passing.
