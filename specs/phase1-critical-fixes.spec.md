# STORM VX — Phase 1: Critical Fixes Requirements Specification

**Feature ID**: P1-CRITICAL
**Priority**: CRITICAL (all items)
**Phase**: 1 — Architecture Remediation
**Author**: spec-writer (Agent ID 2, Skill: feature-forge)
**Date**: 2025-03-05
**Status**: pending

---

## Overview

Phase 1 addresses 6 critical bugs in the STORM VX codebase that pose risks to runtime stability, security posture, and code hygiene. These items were identified during the full codebase audit (Session 2, worklog.md) and validated against source code. Each fix is scoped to the smallest possible change (Law 2) while satisfying the triad of secure (Law 5), extensible (Law 9), and standard (Law 10).

---

## Bug #1: TaskGroup Lifecycle Leak

### FR-P1-001: Use async-with pattern for TaskGroup lifecycle management

**Feature ID**: FR-P1-001
**Priority**: CRITICAL
**Category**: Runtime Stability

#### Description

`asyncio.TaskGroup()` is instantiated directly and `__aenter__` / `__aexit__` are called manually in two locations. If `__aenter__` succeeds but code between entry and the managed body fails (exception, cancellation), the TaskGroup is never properly cleaned up, creating orphan tasks that consume resources and can cause silent failures.

**Current Code (WRONG)**:
```python
# engine/task_supervisor.py:571-573
self._task_group = asyncio.TaskGroup()
await self._task_group.__aenter__()

# engine/scheduler.py:688-690
self._task_group = asyncio.TaskGroup()
await self._task_group.__aenter__()
```

The `stop()` methods also call `__aexit__` manually:
```python
# engine/task_supervisor.py:598
await self._task_group.__aexit__(None, None, None)

# engine/scheduler.py:714
await self._task_group.__aexit__(None, None, None)
```

**Fix Required**: Refactor both `TaskSupervisor` and `StormScheduler` to use `async with asyncio.TaskGroup() as tg:` pattern. The start/stop lifecycle must be restructured so the TaskGroup context manager is entered and exited properly.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `engine/task_supervisor.py` | 571-573, 596-601 | Replace manual `__aenter__/__aexit__` with `async with` |
| `engine/scheduler.py` | 688-690, 712-717 | Replace manual `__aenter__/__aexit__` with `async with` |

#### Functional Requirements (EARS)

**FR-P1-001.1**: When `TaskSupervisor.start()` is called, the system shall enter an `async with asyncio.TaskGroup()` context manager to manage the lifecycle of all plugin scope tasks.

**FR-P1-001.2**: When `TaskSupervisor.stop()` is called, the system shall exit the TaskGroup context manager, which automatically cancels remaining child tasks.

**FR-P1-001.3**: When `StormScheduler.start()` is called, the system shall enter an `async with asyncio.TaskGroup()` context manager for the tick driver task.

**FR-P1-001.4**: When `StormScheduler.stop()` is called, the system shall exit the TaskGroup context manager.

**FR-P1-001.5**: When an exception occurs between TaskGroup entry and the managed body, the system shall ensure the TaskGroup is properly cleaned up via the context manager's exception handling.

#### Acceptance Criteria

```
AC-P1-001.1:
  Given TaskSupervisor is not running,
  When start() is called,
  Then the TaskGroup is managed via async with pattern
  And no manual __aenter__/__aexit__ calls exist in the file.

AC-P1-001.2:
  Given TaskSupervisor is running with active plugin tasks,
  When stop() is called,
  Then all child tasks are cancelled via the TaskGroup context manager exit
  And no orphan tasks remain.

AC-P1-001.3:
  Given StormScheduler is not running,
  When start() is called,
  Then the TaskGroup is managed via async with pattern.

AC-P1-001.4:
  Given an exception occurs during TaskGroup-managed code,
  When the exception propagates,
  Then the TaskGroup context manager properly cleans up all child tasks.

AC-P1-001.5:
  Given the refactored code,
  When grepping for "__aenter__" or "__aexit__",
  Then zero matches exist in engine/task_supervisor.py and engine/scheduler.py.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents resource leaks from orphan tasks | PASS |
| Law 9 (Extensible) | Standard async with pattern is idiomatic and extensible | PASS |
| Law 10 (Standard) | Uses Python's canonical TaskGroup API | PASS |

---

## Bug #2: Crash Double-Count

### FR-P1-002: Eliminate duplicate crash recording

**Feature ID**: FR-P1-002
**Priority**: CRITICAL
**Category**: Data Integrity / Metrics Accuracy

#### Description

When a plugin crashes, the crash is recorded twice:
1. **In `PluginScope.start()`** (line 292): `self._crash_count += 1` — increments the scope-local crash counter.
2. **In `TaskSupervisor.restart_crashed()`** (line 671): `self._recovery.record_crash(name)` — appends a timestamped entry to `CrashRecovery._crash_history`.

The second recording is incorrect because the crash was already captured by `PluginScope._crash_count` when it occurred. This causes:
- `CrashRecovery.should_restart()` computes exponential backoff based on `_crash_history` length, which is inflated by the duplicate, leading to faster backoff escalation than intended.
- Crash metrics and reporting show double the actual crash count.
- The backoff window grows exponentially faster (2^n where n includes phantom entries).

**Current Code (WRONG)**:
```python
# engine/task_supervisor.py:671 (in restart_crashed method)
self._recovery.record_crash(name)  # DUPLICATE — crash was already recorded
```

**Fix Required**: Remove the `self._recovery.record_crash(name)` call from `restart_crashed()`. The crash is already recorded when it happens in `PluginScope.start()`. Instead, ensure `PluginScope.start()` calls `self._recovery.record_crash()` at the point of crash, or the supervisor records it once at crash-detection time (not at restart time).

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `engine/task_supervisor.py` | 292, 671 | Remove duplicate `record_crash()` in `restart_crashed()`, ensure crash is recorded once at crash time |

#### Functional Requirements (EARS)

**FR-P1-002.1**: When a plugin crashes in `PluginScope.start()`, the system shall record the crash exactly once in `CrashRecovery._crash_history`.

**FR-P1-002.2**: When `TaskSupervisor.restart_crashed()` is called for a crashed plugin, the system shall NOT call `record_crash()` again, as the crash was already recorded at crash time.

**FR-P1-002.3**: The system shall ensure `CrashRecovery._crash_history` length accurately reflects the number of actual crash events, not restart attempts.

#### Acceptance Criteria

```
AC-P1-002.1:
  Given a plugin crashes once,
  When the crash is processed,
  Then CrashRecovery._crash_history contains exactly one entry for that plugin.

AC-P1-002.2:
  Given a plugin has crashed and restart_crashed() is called,
  When the restart is attempted,
  Then record_crash() is NOT called again for this restart cycle.

AC-P1-002.3:
  Given a plugin crashes 3 times,
  When checking _crash_history length,
  Then it contains exactly 3 entries (not 6).

AC-P1-002.4:
  Given the refactored code,
  When grepping for "record_crash" in engine/task_supervisor.py,
  Then it appears exactly once per crash path (not in restart_crashed).
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Accurate crash counts prevent misconfigured backoff | PASS |
| Law 9 (Extensible) | Single-source crash recording is cleaner for future extensions | PASS |
| Law 10 (Standard) | Eliminates data inconsistency anti-pattern | PASS |

---

## Bug #3: Path Traversal — Unbounded URL Decode Loop (input_validation.py)

### FR-P1-003: Add iteration limit to URL decode loop in path preprocessing

**Feature ID**: FR-P1-003
**Priority**: CRITICAL
**Category**: Security (DoS / CWE-400)

#### Description

The `_preprocess_path()` fallback in `security/input_validation.py` contains an unbounded `while prev != decoded` loop that iteratively URL-decodes a path. An attacker can craft a URL with deeply nested encoding (e.g., `%252525252e%252525252e%252525252f` = `../` after 5 decode passes) that causes the loop to execute many times, consuming excessive CPU.

This is a **CWE-400 (Uncontrolled Resource Consumption)** vulnerability. The deeper the encoding, the more iterations required, and each iteration involves a full string `unquote()` operation.

**Current Code (VULNERABLE)**:
```python
# security/input_validation.py:538-542
prev = None
decoded = path
while prev != decoded:       # UNBOUNDED — attacker controls iteration count
    prev = decoded
    decoded = unquote(decoded)
```

**Fix Required**: Add a maximum iteration limit (5 iterations). Legitimate double-encoding rarely exceeds 2-3 levels. Five iterations handles all reasonable cases while preventing abuse.

**Proposed Code**:
```python
MAX_DECODE_ITERATIONS = 5
prev = None
decoded = path
for _ in range(MAX_DECODE_ITERATIONS):
    prev = decoded
    decoded = unquote(decoded)
    if prev == decoded:
        break
```

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `security/input_validation.py` | 538-542 | Replace unbounded `while` with bounded `for` loop (max 5 iterations) |

#### Functional Requirements (EARS)

**FR-P1-003.1**: The system shall limit URL decode iterations in `_preprocess_path()` to a maximum of 5 passes.

**FR-P1-003.2**: When the decode loop reaches the maximum iteration limit, the system shall stop decoding and return the current result.

**FR-P1-003.3**: When a path contains deeply nested encoding exceeding 5 levels, the system shall log a warning indicating potential encoding abuse.

**FR-P1-003.4**: Where legitimate double-encoding (2-3 levels) is present, the system shall fully decode it within the iteration limit.

#### Acceptance Criteria

```
AC-P1-003.1:
  Given a path with 10 levels of URL encoding,
  When _preprocess_path() is called,
  Then the loop executes at most 5 iterations
  And does not hang or consume excessive CPU.

AC-P1-003.2:
  Given a path with standard double-encoding (%252e),
  When _preprocess_path() is called,
  Then it is fully decoded to the original characters within the iteration limit.

AC-P1-003.3:
  Given a path that triggers the iteration limit,
  When the loop terminates early,
  Then a warning is logged about potential encoding abuse.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents DoS via unbounded decode loop (CWE-400) | PASS |
| Law 9 (Extensible) | MAX_DECODE_ITERATIONS constant is configurable | PASS |
| Law 10 (Standard) | Industry-standard approach to bounded decode loops | PASS |

---

## Bug #4: Path Traversal — Unbounded Loops in vf_validator.py

### FR-P1-004: Add iteration limits to all unbounded while loops in vf_validator.py

**Feature ID**: FR-P1-004
**Priority**: CRITICAL
**Category**: Security (DoS / CWE-400)

#### Description

The `vf_validator.py` file contains multiple unbounded `while` loops that can be exploited for DoS:

1. **URL decode loop** (lines 183-186): Same pattern as Bug #3 — `while prev != path: path = unquote(path)`
2. **Semicolon traversal loop** (lines 198-199): `while '..;/' in path or '..;\\' in path:` — can be exploited with `..;..;..;/..;/..;/` patterns
3. **Semicolon conversion loop** (line 201-202): `while '..;' in path:` — similarly exploitable
4. **Path traversal loop** (lines 205-206): `while '../' in path or '..\\' in path:` — can be exploited with `..//..//..//` (replace creates new matches)
5. **Double-slash loop #1** (lines 209-210): `while '//' in path:` — exploitable with `//////`
6. **Double-slash loop #2** (lines 216-217): `while '//' in path:` — same pattern, second instance

Each of these loops replaces a pattern and checks again. An attacker can craft inputs where replacement creates new instances of the same pattern (e.g., `/.//./` -> after `//` removal becomes `/./`, which after `../` removal could create new `//`).

**Current Code (VULNERABLE)**:
```python
# vf_validator.py:183-186
prev = None
while prev != path:
    prev = path
    path = unquote(path)

# vf_validator.py:198-199
while '..;/' in path or '..;\\' in path:
    path = path.replace('..;/', '').replace('..;\\', '')

# vf_validator.py:201-202
while '..;' in path:
    path = path.replace('..;', '..')

# vf_validator.py:205-206
while '../' in path or '..\\' in path:
    path = path.replace('../', '').replace('..\\', '')

# vf_validator.py:209-210
while '//' in path:
    path = path.replace('//', '/')

# vf_validator.py:216-217
while '//' in path:
    path = path.replace('//', '/')
```

**Fix Required**: Add iteration limits to all 6 loops. Maximum iterations:
- URL decode: 5 (same as Bug #3)
- Semicolon traversal: 10
- Semicolon conversion: 10
- Path traversal: 20 (legitimate paths may have many `../`)
- Double-slash: 10

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `vf_validator.py` | 183-186, 198-199, 201-202, 205-206, 209-210, 216-217 | Add bounded iteration to all 6 while loops |

#### Functional Requirements (EARS)

**FR-P1-004.1**: The system shall limit the URL decode loop to 5 iterations.

**FR-P1-004.2**: The system shall limit each path traversal removal loop (`..;`, `../`, `..\\`) to a maximum of 20 iterations.

**FR-P1-004.3**: The system shall limit each double-slash removal loop to 10 iterations.

**FR-P1-004.4**: When any loop reaches its iteration limit, the system shall break out of the loop and log a warning.

**FR-P1-004.5**: The system shall reject paths that still contain traversal patterns after all sanitization loops complete with a bounded iteration limit exceeded.

#### Acceptance Criteria

```
AC-P1-004.1:
  Given a path with deeply nested URL encoding,
  When validate_path() processes it,
  Then the decode loop runs at most 5 iterations.

AC-P1-004.2:
  Given a path with 100 instances of "../",
  When validate_path() processes it,
  Then the traversal loop runs at most 20 iterations
  And the remaining "../" patterns are rejected.

AC-P1-004.3:
  Given a path with 50 consecutive slashes "//////...////",
  When validate_path() processes it,
  Then the double-slash loop runs at most 10 iterations.

AC-P1-004.4:
  Given a path that triggers any iteration limit,
  When the limit is hit,
  Then a warning is logged identifying which loop was bounded.

AC-P1-004.5:
  Given legitimate paths with up to 5 levels of "../",
  When validate_path() processes them,
  Then they are correctly sanitized within iteration limits.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents DoS via all unbounded loops (CWE-400) | PASS |
| Law 9 (Extensible) | Iteration limits defined as module constants | PASS |
| Law 10 (Standard) | Bounded sanitization loops are security best practice | PASS |

---

## Bug #5: Health Server Without Authentication

### FR-P1-005: Add bearer token authentication to health server

**Feature ID**: FR-P1-005
**Priority**: CRITICAL
**Category**: Security (Information Disclosure / CWE-200)

#### Description

The health server in `observability/health.py` binds to `0.0.0.0:9090` by default with **zero authentication**. The following endpoints expose sensitive information to any network-reachable attacker:

- **`/diag`** — Exposes PID, CWD, UID, platform info, event loop task count, and last health report
- **`/metrics`** — Exposes internal Prometheus metrics (request counts, error rates, plugin states)
- **`/health`** — Exposes system health status (useful for reconnaissance)
- **`/ready`** — Exposes readiness state

An attacker on the same network can enumerate system details, infer internal architecture, and use the information for further attacks.

**Current Code (VULNERABLE)**:
```python
# observability/health.py:425-486
async def start_health_server(
    host: str = "0.0.0.0",    # Binds to ALL interfaces
    port: int = 9090,
    ...
):
    # NO authentication middleware
    app = web.Application()
    app.router.add_get("/health", handle_health)
    app.router.add_get("/ready", handle_ready)
    app.router.add_get("/metrics", handle_metrics)
    app.router.add_get("/diag", handle_diag)
```

**Fix Required**: Add optional bearer token authentication via `STORM_VX_HEALTH_TOKEN` environment variable:
- If `STORM_VX_HEALTH_TOKEN` is set: ALL endpoints require `Authorization: Bearer <token>` header. Return 401 if missing/invalid.
- If `STORM_VX_HEALTH_TOKEN` is NOT set: Log a warning at startup, but allow unauthenticated access (backward compatibility).

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `observability/health.py` | 425-486 | Add bearer token middleware and env var check |

#### Functional Requirements (EARS)

**FR-P1-005.1**: Where `STORM_VX_HEALTH_TOKEN` environment variable is set, the system shall require `Authorization: Bearer <token>` header on ALL health server endpoints.

**FR-P1-005.2**: When a request is made without a valid bearer token and authentication is enabled, the system shall return HTTP 401 Unauthorized.

**FR-P1-005.3**: Where `STORM_VX_HEALTH_TOKEN` is NOT set, the system shall log a WARNING at startup and allow unauthenticated access for backward compatibility.

**FR-P1-005.4**: When the health server starts, the system shall log whether authentication is enabled or disabled.

**FR-P1-005.5**: The system shall use constant-time comparison for the bearer token to prevent timing attacks.

#### Acceptance Criteria

```
AC-P1-005.1:
  Given STORM_VX_HEALTH_TOKEN is set to "secret123",
  When a request is made to /health without Authorization header,
  Then the server returns HTTP 401 Unauthorized.

AC-P1-005.2:
  Given STORM_VX_HEALTH_TOKEN is set to "secret123",
  When a request is made with "Authorization: Bearer secret123",
  Then the server returns the normal response (HTTP 200/503).

AC-P1-005.3:
  Given STORM_VX_HEALTH_TOKEN is set to "secret123",
  When a request is made with "Authorization: Bearer wrongtoken",
  Then the server returns HTTP 401 Unauthorized.

AC-P1-005.4:
  Given STORM_VX_HEALTH_TOKEN is NOT set,
  When the health server starts,
  Then a WARNING is logged about running without authentication
  And all endpoints are accessible without authentication.

AC-P1-005.5:
  Given authentication is enabled,
  When token comparison is performed,
  Then hmac.compare_digest() or secrets.compare_digest() is used
  (not == operator).

AC-P1-005.6:
  Given authentication is enabled,
  When requests are made to /health, /ready, /metrics, /diag,
  Then ALL four endpoints require the bearer token.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents unauthenticated information disclosure (CWE-200) | PASS |
| Law 9 (Extensible) | Env-var based config, backward compatible | PASS |
| Law 10 (Standard) | Bearer token auth is RFC 6750 compliant | PASS |

---

## Bug #6: Dead Code — vf_api_flood.py

### FR-P1-006: Remove dead code file vf_api_flood.py

**Feature ID**: FR-P1-006
**Priority**: CRITICAL
**Category**: Code Hygiene / Law 14 Compliance

#### Description

`tester/vf_api_flood.py` is a 711-line file that is never imported or used in the runtime codebase. It is a legacy module that completely bypasses the plugin system — it has its own session management, worker spawning, and stats tracking. It violates Law 14 (>500 lines) and adds maintenance burden.

References found are limited to:
- **Test files** that test the module in isolation (not part of runtime)
- **Documentation** files that describe its bugs
- **Logging config** that defines a logger name for it (not a runtime import)

No `import vf_api_flood` or `from vf_api_flood import` exists in any runtime code.

**Fix Required**: Delete `tester/vf_api_flood.py` entirely. Also remove or update any test files and logging config entries that reference it.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `tester/vf_api_flood.py` | 711 lines | DELETE entire file |
| `observability/logging_ext.py` | 223 | Remove `vf_api_flood` logger entry |
| `tests/test_task_3_2_resource_controls.py` | 412-423 | Remove/update vf_api_flood test cases |
| `tests/test_task_5_7_security_hardening.py` | 834-838 | Remove/update vf_api_flood test cases |
| `tests/test_task_2_4_config_activation.py` | 338, 376 | Remove/update vf_api_flood references |

#### Functional Requirements (EARS)

**FR-P1-006.1**: The system shall not contain the file `tester/vf_api_flood.py`.

**FR-P1-006.2**: When the codebase is scanned for imports of `vf_api_flood`, zero runtime imports shall exist.

**FR-P1-006.3**: The logging configuration shall not include a logger entry for `vf_api_flood`.

#### Acceptance Criteria

```
AC-P1-006.1:
  Given the file tester/vf_api_flood.py,
  When the Phase 1 fix is applied,
  Then the file does not exist on disk.

AC-P1-006.2:
  Given the codebase after fix,
  When searching for "vf_api_flood" in all .py files,
  Then zero references exist in runtime code
  (test files may be removed or updated).

AC-P1-006.3:
  Given the codebase after fix,
  When observability/logging_ext.py is checked,
  Then no "vf_api_flood" logger entry exists.

AC-P1-006.4:
  Given the codebase after fix,
  When the project is imported,
  Then no ImportError or ModuleNotFoundError occurs.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Removes unmaintained attack surface (711 lines of untested legacy code) | PASS |
| Law 9 (Extensible) | Removing dead code reduces confusion for future extension | PASS |
| Law 10 (Standard) | Dead code removal is standard practice | PASS |
| Law 14 (500 lines) | Eliminates a 711-line file violation | PASS |

---

## Non-Functional Requirements

### Performance
- Bug #3 and #4 fixes shall not add measurable latency to normal (non-adversarial) path validation (< 1ms per call).
- Bug #1 fix shall not change the startup time of TaskSupervisor or StormScheduler.

### Security
- Bug #3 and #4 eliminate CWE-400 (Uncontrolled Resource Consumption) vectors.
- Bug #5 eliminates CWE-200 (Information Exposure) vector.
- All fixes shall be reviewed by security-auditor agent before merge (Law 12).

### Compatibility
- Bug #5 shall maintain backward compatibility when `STORM_VX_HEALTH_TOKEN` is not set.
- Bug #1 shall maintain the same external API for `TaskSupervisor` and `StormScheduler`.
- Bug #2 shall not change the exponential backoff formula, only the accuracy of its input.

### Testing
- Each fix shall have at least one test case covering the vulnerability scenario.
- Bug #3 and #4 test cases shall use adversarial inputs (deeply encoded paths).
- Bug #5 test cases shall cover both authenticated and unauthenticated modes.

---

## Error Handling

| Error Condition | Behavior | Code/Message |
|-----------------|----------|--------------|
| TaskGroup exception during managed code | Context manager handles cleanup automatically | asyncio.TaskGroup propagates first exception |
| Crash not yet recorded when restart_crashed() is called | Should not happen; defensive: log warning if _crash_history is empty for plugin | Warning log: "No crash record for {name}" |
| URL decode loop hits iteration limit | Break loop, log warning | Warning: "Path decode iteration limit ({MAX}) reached" |
| Path sanitization loop hits iteration limit | Break loop, reject path | Warning + return empty/rejected path |
| Health request with invalid token | Return 401 | HTTP 401, body: `{"error": "Unauthorized"}` |
| Health request with missing token when auth enabled | Return 401 | HTTP 401, body: `{"error": "Authorization required"}` |

---

## Implementation TODO Checklist

### Bug #1: TaskGroup Lifecycle Leak
- [ ] Refactor `TaskSupervisor.start()` to use `async with asyncio.TaskGroup()` pattern
- [ ] Refactor `TaskSupervisor.stop()` to work with new context-manager-based lifecycle
- [ ] Refactor `StormScheduler.start()` to use `async with asyncio.TaskGroup()` pattern
- [ ] Refactor `StormScheduler.stop()` to work with new context-manager-based lifecycle
- [ ] Ensure `create_task()` calls work within the managed context
- [ ] Write test: TaskGroup cleanup on exception
- [ ] Write test: no `__aenter__` / `__aexit__` in codebase

### Bug #2: Crash Double-Count
- [ ] Remove `self._recovery.record_crash(name)` from `restart_crashed()`
- [ ] Ensure crash is recorded exactly once (in `PluginScope.start()` exception handler)
- [ ] Add `self._recovery.record_crash(self.plugin_name)` to PluginScope crash handler if not present
- [ ] Write test: single crash → single entry in `_crash_history`
- [ ] Write test: backoff calculation uses accurate crash count

### Bug #3: Path Traversal — input_validation.py
- [ ] Define `MAX_DECODE_ITERATIONS = 5` constant
- [ ] Replace `while prev != decoded` with `for _ in range(MAX_DECODE_ITERATIONS)` + break
- [ ] Add warning log when iteration limit is reached
- [ ] Write test: deeply encoded path (10+ levels) completes within iteration limit
- [ ] Write test: standard double-encoding decodes correctly

### Bug #4: Path Traversal — vf_validator.py
- [ ] Define iteration limit constants for each loop type
- [ ] Bound URL decode loop (5 iterations)
- [ ] Bound `..;/` and `..;\\` removal loop (10 iterations)
- [ ] Bound `..;` conversion loop (10 iterations)
- [ ] Bound `../` and `..\\` removal loop (20 iterations)
- [ ] Bound `//` removal loops (10 iterations each)
- [ ] Add warning log when any iteration limit is reached
- [ ] Write test: adversarial path inputs with excessive patterns
- [ ] Write test: legitimate paths with up to 5 levels of `../` work correctly

### Bug #5: Health Server Authentication
- [ ] Read `STORM_VX_HEALTH_TOKEN` from environment in `start_health_server()`
- [ ] Create aiohttp middleware that validates `Authorization: Bearer <token>` header
- [ ] Use `secrets.compare_digest()` for constant-time token comparison
- [ ] Return HTTP 401 for invalid/missing tokens when auth is enabled
- [ ] Log WARNING at startup when token is not set
- [ ] Log INFO at startup when token is set (auth enabled)
- [ ] Write test: authenticated request succeeds
- [ ] Write test: unauthenticated request returns 401
- [ ] Write test: wrong token returns 401
- [ ] Write test: no token set → unauthenticated access allowed + warning logged

### Bug #6: Dead Code Removal
- [ ] Delete `tester/vf_api_flood.py`
- [ ] Remove `vf_api_flood` entry from `observability/logging_ext.py`
- [ ] Update or remove `vf_api_flood` test cases in test files
- [ ] Verify no runtime import breaks after deletion
- [ ] Run full test suite to confirm no regressions

---

## Out of Scope

- Migration of `vf_api_flood.py` functionality to a proper AttackPlugin (future phase)
- TLS/mTLS for the health server (future enhancement)
- Rate limiting on health server endpoints (future enhancement)
- Refactoring `TaskSupervisor` and `StormScheduler` to share a common base class (future phase)
- Adding HMAC or JWT-based auth to the health server (bearer token is sufficient for Phase 1)

---

## Open Questions

- [ ] Should `TaskSupervisor` need to support dynamic addition/removal of scopes after start? The current architecture implies yes, but `async with TaskGroup()` requires the body to contain all tasks. A background task wrapper may be needed.
- [ ] Should the health server support binding to `127.0.0.1` as an alternative to bearer token auth? (Defense in depth)
- [ ] Should paths that hit iteration limits in Bug #3/#4 be rejected entirely or returned partially sanitized?

---

## Dependency Graph

```
P1-001 (TaskGroup)  ──→ Independent (can be done in parallel)
P1-002 (Crash Count) ──→ Independent
P1-003 (input_validation) ──→ Independent
P1-004 (vf_validator)  ──→ Independent (but same pattern as P1-003)
P1-005 (Health Auth)  ──→ Independent
P1-006 (Dead Code)    ──→ Independent
```

All 6 fixes are independent and can be implemented in parallel by separate coder agents.

---

## Summary Table

| ID | Bug | Severity | Category | Files | Law Compliance |
|----|-----|----------|----------|-------|----------------|
| FR-P1-001 | TaskGroup Lifecycle Leak | CRITICAL | Runtime Stability | task_supervisor.py, scheduler.py | L5✓ L9✓ L10✓ |
| FR-P1-002 | Crash Double-Count | CRITICAL | Data Integrity | task_supervisor.py | L5✓ L9✓ L10✓ |
| FR-P1-003 | Unbounded Decode (input_validation.py) | CRITICAL | Security (CWE-400) | input_validation.py | L5✓ L9✓ L10✓ |
| FR-P1-004 | Unbounded Loops (vf_validator.py) | CRITICAL | Security (CWE-400) | vf_validator.py | L5✓ L9✓ L10✓ |
| FR-P1-005 | Health Server No Auth | CRITICAL | Security (CWE-200) | health.py | L5✓ L9✓ L10✓ |
| FR-P1-006 | Dead Code vf_api_flood.py | CRITICAL | Code Hygiene (L14) | vf_api_flood.py + refs | L5✓ L9✓ L10✓ L14✓ |
