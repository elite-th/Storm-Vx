# STORM VX — Phase 2: Security & Reliability Hardening
# Technical Roadmap + TO-DO List

**Version:** 1.0  
**Date:** 2025-03-05  
**Author:** Architect Agent (architecture-designer)  
**Status:** PENDING REVIEW  
**Prerequisite:** Phase 1 COMPLETE ✅ (6 bugs fixed)

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Source Verification Audit](#source-verification-audit)
3. [Dependency Graph](#dependency-graph)
4. [Parallel Execution Plan](#parallel-execution-plan)
5. [Detailed Fix Specifications](#detailed-fix-specifications)
6. [Integration Points](#integration-points)
7. [Rollback Strategy](#rollback-strategy)
8. [Effort Estimation](#effort-estimation)

---

## Executive Summary

Phase 2 covers 14 HIGH-priority security and reliability fixes. Upon **source code verification**, **12 of 14 items are ALREADY FIXED** — resolved during Phase 1 or in prior codebase evolution. Only **2 items require active implementation**:

| Status | Count | Items |
|--------|-------|-------|
| ✅ VERIFIED COMPLETE | 12 | BUG-001, BUG-002, BUG-003, BUG-005, BUG-006, BUG-007, BUG-009, BUG-010, BUG-012, B3, B4, B16 |
| ❌ NEEDS WORK | 2 | BUG-008 (OperationTimeoutError callers), BUG-011 (shared mutable state) |

**Total estimated effort for remaining work: ~3 hours**

---

## Source Verification Audit

Every item was verified against the current source code at `/home/z/my-project/STORM/`. Below is the evidence for each determination.

### Group A — Security Fixes

#### BUG-001: aiohttp NameError guard — ✅ VERIFIED COMPLETE

- **File:** `tester/vf_graphql_introspection.py`
- **Evidence:** Lines 28-33 contain the `try/except ImportError` guard with `_HAS_AIOHTTP` flag. Line 133 has `if not _HAS_AIOHTTP: return`. Lines 167 and 184 check `_HAS_AIOHTTP and isinstance(exc, aiohttp.ClientError)`.
- **Action:** None required. Mark as COMPLETE.

#### BUG-002: verify_ssl contradictory defaults — ✅ VERIFIED COMPLETE

- **Files:** `config/settings.py`, `config/defaults.py`, `plugin_system.py`
- **Evidence:**
  - `config/defaults.py:34` — `VERIFY_SSL: bool = True` ✅
  - `config/settings.py:56` — `verify_ssl: bool = VERIFY_SSL` (references constant) ✅
  - `plugin_system.py:230` — `verify_ssl: bool = True` (SEC-07 comment) ✅
  - All three locations now agree on `True`.
- **Action:** None required. Mark as COMPLETE.

#### BUG-003: Cloudflare IP ranges — ✅ VERIFIED COMPLETE

- **File:** `finder/vf_origin_discovery.py`
- **Evidence:** Lines 54-77 use `ipaddress.ip_network()` with proper CIDR notation:
  ```python
  CDN_IPV4_RANGES: dict[str, list[ipaddress.IPv4Network]] = {
      "cloudflare": [
          ipaddress.ip_network("173.245.48.0/20"),
          ipaddress.ip_network("103.21.244.0/22"),
          ...
      ],
  }
  ```
  The broken hex ranges from the original `dns_scanner.py` have been replaced. The `is_cdn_ip()` function (line 106-122) uses `ipaddress.ip_address()` containment checks.
- **Action:** None required. Mark as COMPLETE.

#### BUG-005: sys.path.insert(0,...) module shadowing — ✅ VERIFIED COMPLETE

- **File:** `plugin_system.py`
- **Evidence:** Lines 313-318 now use `sys.path.append(search_dir)` instead of `sys.path.insert(0, search_dir)`. Comment explains: "Append (not insert) to avoid plugin files shadowing stdlib modules."
- **Action:** None required. Mark as COMPLETE.

#### BUG-006: Path traversal in vf_updater.py — ✅ VERIFIED COMPLETE

- **File:** `infra/vf_updater.py`
- **Evidence:** Lines 525-529 contain path traversal validation:
  ```python
  resolved = (self.project_root / file_path).resolve()
  if not str(resolved).startswith(str(self.project_root.resolve())):
      logger.warning(f"Path traversal detected, skipping: {file_path}")
      continue
  ```
- **Action:** None required. Mark as COMPLETE.

#### BUG-007: Remove auto pip install — ✅ VERIFIED COMPLETE

- **File:** `run.py`
- **Evidence:** `check_and_install_deps()` (lines 189-213) now prints missing packages and exits with `sys.exit(1)`. No `subprocess.run(["pip", "install", ...])` call exists.
- **Action:** None required. Mark as COMPLETE.

#### BUG-008: Rename TimeoutError → OperationTimeoutError — ❌ NEEDS WORK

- **File:** `exceptions.py`
- **Current State:** `OperationTimeoutError` class exists at `exceptions.py:33-42`. The class has been renamed from `TimeoutError`.
- **Remaining Work:** No callers import `OperationTimeoutError`. Need to:
  1. Audit all 40+ files that reference `TimeoutError` to distinguish builtin `asyncio.TimeoutError` (correct usage) from any custom imports
  2. Add `OperationTimeoutError` to `exceptions.py`'s `__all__` export list
  3. Identify any code that should use `OperationTimeoutError` for project-specific timeout semantics
  4. Update `vf_network.py` and `engine/task_supervisor.py` to raise `OperationTimeoutError` where appropriate
- **Risk:** LOW — renaming is purely additive; `asyncio.TimeoutError` references are correct and should not change.

### Group B — Reliability Fixes

#### BUG-009: Implement keyboard handler — ✅ VERIFIED COMPLETE

- **File:** `tester/vf_keyboard.py`
- **Evidence:** Lines 42-55 contain proper platform-specific implementation:
  - Windows: `msvcrt.kbhit()` + `msvcrt.getch()`
  - Unix: `select.select([sys.stdin], [], [], 0)`
  - `_KEY_MAP` class attribute for key mapping
- **Action:** None required. Mark as COMPLETE.

#### BUG-010: Fix blocking socket — ✅ VERIFIED COMPLETE

- **File:** `evasion/vf_fp_cloner.py`
- **Evidence:** `_raw_tls_probe()` (lines 276-322) uses `asyncio.wait_for(asyncio.open_connection(...), timeout=EVASION_FPC_TIMEOUT)`. Comment at line 280-281 confirms: "BUG-010 fix: Replaced blocking socket.create_connection() with asyncio.open_connection()."
- **Action:** None required. Mark as COMPLETE.

#### BUG-011: Shared mutable state — ❌ NEEDS WORK

- **File:** `finder/engine.py`
- **Current State:** Lines 85-158 show three parallel pipelines (`_content_pipeline`, `_ssl_pipeline`, `_dns_pipeline`) that all mutate `self.profile` via `asyncio.gather()`. The `return_exceptions=True` flag is set (line 157), but there's no lock or sequential-apply pattern to protect concurrent mutations.
- **Remaining Work:**
  1. Add an `asyncio.Lock()` to serialize `self.profile` mutations
  2. Or refactor pipelines to return results and apply them sequentially after `gather()`
  3. The `return_exceptions=True` (line 157) prevents crashes but not data corruption
- **Risk:** MEDIUM — In CPython's asyncio, cooperative scheduling makes this *technically safe* for non-yielding mutations, but mid-yield list/dict modifications (e.g., `self.profile.api_endpoints.append()`) can cause issues if another coroutine yields between append calls.

#### BUG-012: HAS_AIOHTTP checks — ✅ VERIFIED COMPLETE

- **Files:** `evasion/vf_session_harvest.py`, `evasion/vf_fp_cloner.py`
- **Evidence:**
  - `vf_session_harvest.py:192-194` — `if not HAS_AIOHTTP: logger.error(...); return None` ✅
  - `vf_fp_cloner.py:207-209` — `if not HAS_AIOHTTP: logger.error(...); return None` ✅
- **Action:** None required. Mark as COMPLETE.

### Group C — Code Quality & Safety

#### B3: Remove sensitive paths — ✅ VERIFIED COMPLETE

- **File:** `tester/vf_page_flood.py`
- **Evidence:** `COMMON_DYNAMIC_PATHS` (lines 45-60) does NOT contain `/.env` or `/.git/config`. The list includes `/admin` and `/wp-login.php` which are legitimate attack targets for authorized load testing, but no data-exfiltration-risk paths.
- **Action:** None required. Mark as COMPLETE.

#### B4: Fix logging_config.py handler accumulation — ✅ VERIFIED COMPLETE

- **File:** `logging_config.py`
- **Evidence:** Line 94 — `if not logger.handlers:` guard prevents duplicate console handlers. Lines 105-109 — duplicate file handler check with `has_file_handler` variable.
- **Action:** None required. Mark as COMPLETE.

#### B16: Move ValidationError to exceptions.py — ✅ VERIFIED COMPLETE

- **Files:** `exceptions.py`, `vf_validator.py`
- **Evidence:**
  - `exceptions.py:13-15` — `class ValidationError(ValueError): pass` ✅
  - `vf_validator.py:15` — `from exceptions import ValidationError` ✅
- **Action:** None required. Mark as COMPLETE.

---

## Dependency Graph

```
BUG-008 (OperationTimeoutError callers)
  ├── vf_network.py          — uses asyncio.TimeoutError (CORRECT, no change)
  ├── engine/task_supervisor.py — may need OperationTimeoutError for custom timeouts
  └── exceptions.py           — class already defined (no dependency)

BUG-011 (Shared mutable state)
  └── finder/engine.py        — self-contained fix within scan() method
```

**Dependency analysis:** BUG-008 and BUG-011 are **completely independent** — they touch different files, different subsystems, and have no shared state. They can be implemented in parallel.

No fix depends on the output of another fix.

---

## Parallel Execution Plan

### Coder Group A: BUG-008 (OperationTimeoutError Integration)

**Scope:** Wire up the already-renamed `OperationTimeoutError` exception across the codebase.

| Step | Action | File(s) |
|------|--------|---------|
| A1 | Add `OperationTimeoutError` to `__all__` in exceptions.py | `exceptions.py` |
| A2 | Audit all `TimeoutError` references to classify: builtin vs custom | ~40 files |
| A3 | Add `from exceptions import OperationTimeoutError` where needed | `vf_network.py`, `engine/task_supervisor.py` |
| A4 | Replace any `raise TimeoutError(...)` with `raise OperationTimeoutError(...)` in project code | TBD after A2 |
| A5 | Verify `asyncio.TimeoutError` references are left unchanged (they're correct) | All files |
| A6 | Add type alias `TimeoutError = OperationTimeoutError` for backward compat (deprecated) | `exceptions.py` |
| A7 | Run `py_compile` on all modified files | — |

### Coder Group B: BUG-011 (Shared Mutable State)

**Scope:** Add synchronization to `VFFinder.scan()` parallel pipelines.

| Step | Action | File(s) |
|------|--------|---------|
| B1 | Add `self._profile_lock = asyncio.Lock()` to `VFFinder.__init__` | `finder/engine.py` |
| B2 | Create `_update_profile(self, fn)` helper that acquires lock before mutating | `finder/engine.py` |
| B3 | Wrap `_content_pipeline` profile mutations in lock | `finder/engine.py:85-111` |
| B4 | Wrap `_ssl_pipeline` profile mutations in lock | `finder/engine.py:113-138` |
| B5 | Wrap `_dns_pipeline` profile mutations in lock | `finder/engine.py:140-150` |
| B6 | Run `py_compile` on modified file | — |
| B7 | Verify file stays under 500 lines (currently 252 lines) | `finder/engine.py` |

### Coder Group C: Verification & Documentation

**Scope:** Verify all 12 already-complete fixes and document the Phase 2 status.

| Step | Action |
|------|--------|
| C1 | Run `py_compile` on all 14 affected files |
| C2 | Verify BUG-001: `_HAS_AIOHTTP` guard present in vf_graphql_introspection.py |
| C3 | Verify BUG-002: `verify_ssl` defaults agree across 3 files |
| C4 | Verify BUG-003: Cloudflare ranges use ipaddress.ip_network() |
| C5 | Verify BUG-005: `sys.path.append` (not insert) in plugin_system.py |
| C6 | Verify BUG-006: Path traversal check in vf_updater.py |
| C7 | Verify BUG-007: No auto pip install in run.py |
| C8 | Verify BUG-009: Keyboard handler uses select/msvcrt |
| C9 | Verify BUG-010: _raw_tls_probe uses asyncio.open_connection |
| C10 | Verify BUG-012: HAS_AIOHTTP checks in both files |
| C11 | Verify B3: No /.env or /.git in COMMON_DYNAMIC_PATHS |
| C12 | Verify B4: Handler accumulation guard in logging_config.py |
| C13 | Verify B16: ValidationError in exceptions.py, imported by vf_validator.py |
| C14 | Update memory.md with Phase 2 status |

---

## Detailed Fix Specifications

### BUG-008: OperationTimeoutError — Wire Up Callers

#### Affected Files

| File | Current State | Change Required |
|------|--------------|-----------------|
| `exceptions.py` | Class defined at line 33 but not in `__all__` | Add to `__all__` list |
| `vf_network.py` | Uses `asyncio.TimeoutError` in except clauses | CORRECT — no change needed |
| `engine/task_supervisor.py` | Uses `asyncio.TimeoutError` in except clauses | CORRECT — no change needed |
| `engine/scheduler.py` | Uses `asyncio.TimeoutError` | CORRECT — no change needed |
| ~37 other files | Reference `asyncio.TimeoutError` or builtin `TimeoutError` | Audit for any custom usage |

#### Implementation Approach

**Step 1: Add to `__all__` in exceptions.py**

```python
# exceptions.py — add OperationTimeoutError to exports
__all__ = [
    "ConfigurationError",
    "ValidationError", 
    "ProfileError",
    "PluginError",
    "NetworkError",
    "OperationTimeoutError",
    "SessionError",
    "TargetUnreachableError",
]
```

**Step 2: Audit all `TimeoutError` references**

Run a classification scan. Expected results:
- `asyncio.TimeoutError` → CORRECT usage (builtin, OSError-derived) → NO CHANGE
- `except TimeoutError` → CORRECT if catching builtin → NO CHANGE  
- `raise TimeoutError(...)` → Should be `raise OperationTimeoutError(...)` if it's project-specific
- `from exceptions import TimeoutError` → Should be `from exceptions import OperationTimeoutError`

**Step 3: Add backward-compat alias (optional)**

```python
# exceptions.py — deprecated alias for migration period
import warnings

def __getattr__(name):
    if name == "TimeoutError":
        warnings.warn(
            "TimeoutError is deprecated; use OperationTimeoutError",
            DeprecationWarning,
            stacklevel=2,
        )
        return OperationTimeoutError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
```

**Step 4: Identify raise sites**

Scan for any `raise TimeoutError(` or `raise exceptions.TimeoutError(` patterns that should use the custom exception instead of the builtin. In the current codebase, timeouts are typically caught (not raised by project code), so this step is likely a no-op.

#### Risk Assessment

- **Risk Level:** LOW
- **Blast Radius:** Only `exceptions.py` and any explicit `from exceptions import TimeoutError` callers
- **Breaking Change:** No — `asyncio.TimeoutError` catches remain correct; `OperationTimeoutError` is a new import
- **Rollback:** Remove `__all__` entry and backward-compat alias; no behavioral change

#### Law Compliance

- **Law 14 (500 lines):** `exceptions.py` = 61 lines → well under limit ✅
- **Law 15 (Interface-only deps):** `OperationTimeoutError` is imported from `exceptions.py` interface ✅

---

### BUG-011: Shared Mutable State in VFFinder.scan()

#### Affected Files

| File | Current Lines | Change Required |
|------|-------------|-----------------|
| `finder/engine.py` | 252 lines | Add lock + helper method |

#### Current State Analysis

```python
# finder/engine.py:153-158 — CURRENT (unsafe)
pipeline_results = await asyncio.gather(
    _content_pipeline(),   # mutates self.profile
    _ssl_pipeline(),       # mutates self.profile
    _dns_pipeline(),       # mutates self.profile
    return_exceptions=True
)
```

The three pipelines mutate `self.profile` concurrently:
- `_content_pipeline()` calls `self.profile = analyze_content(...)` (line 89) — full replacement
- `_ssl_pipeline()` sets `self.profile.ssl_enabled` and `self.profile.ssl_info` (lines 124-133) — attribute mutation
- `_dns_pipeline()` calls `self.profile = await dns_enumerate(...)` (line 144) — full replacement

**The risk:** If `_content_pipeline` replaces `self.profile` while `_ssl_pipeline` is reading it, the SSL data could be written to a stale profile object that's then discarded.

#### Target State

```python
# finder/engine.py — AFTER (safe)

class VFFinder:
    def __init__(self, url, ...):
        ...
        self._profile_lock = asyncio.Lock()
    
    def _update_profile(self, new_profile: SiteProfile) -> None:
        """Thread-safe profile update (acquires lock)."""
        # Note: In asyncio, this is technically safe without a lock due to
        # cooperative scheduling, but the lock documents the intent and
        # protects against future yield-point issues.
        self.profile = new_profile
    
    async def scan(self) -> SiteProfile:
        ...
        async def _content_pipeline():
            try:
                result = analyze_content(self._html or '', self.url, self.profile)
                async with self._profile_lock:
                    self.profile = result
                
                result = detect_technologies(self._html or '', self.url, self.profile)
                async with self._profile_lock:
                    self.profile = result
                ...
        
        async def _ssl_pipeline():
            try:
                if self.profile.scheme == 'https':
                    ssl_result = await analyze_ssl(...)
                    async with self._profile_lock:
                        self.profile.ssl_enabled = ssl_result.get("ssl_enabled")
                        self.profile.ssl_info = { ... }
        
        async def _dns_pipeline():
            try:
                if self.dns_scan:
                    result = await dns_enumerate(self.profile, ...)
                    async with self._profile_lock:
                        self.profile = result
```

#### Implementation Approach

1. Add `self._profile_lock = asyncio.Lock()` to `VFFinder.__init__` (around line 42)
2. In `_content_pipeline()`: Wrap each `self.profile = ...` assignment in `async with self._profile_lock:`
3. In `_ssl_pipeline()`: Wrap the `self.profile.ssl_enabled` and `self.profile.ssl_info` assignments in `async with self._profile_lock:`
4. In `_dns_pipeline()`: Wrap `self.profile = await dns_enumerate(...)` in `async with self._profile_lock:`
5. Add a docstring comment explaining the lock's purpose
6. Count: ~8 `async with self._profile_lock:` blocks added

**Alternative approach (preferred if simpler):** Have each pipeline return results instead of mutating profile, then apply sequentially:

```python
async def _content_pipeline():
    # Return results instead of mutating self.profile
    profile = self.profile
    profile = analyze_content(html, url, profile)
    profile = detect_technologies(html, url, profile)
    ...
    return profile

results = await asyncio.gather(_content_pipeline(), _ssl_pipeline(), _dns_pipeline())
# Apply sequentially
for result in results:
    if isinstance(result, SiteProfile):
        self.profile = result
    elif isinstance(result, dict):
        # SSL pipeline returns partial updates
        self.profile.ssl_enabled = result.get("ssl_enabled")
        ...
```

**Recommendation:** Use the lock approach — it's simpler, requires less refactoring, and the lock overhead is negligible in this context (pipeline execution takes seconds, lock acquisition takes microseconds).

#### Risk Assessment

- **Risk Level:** MEDIUM
- **Blast Radius:** Only `finder/engine.py` — `VFFinder.scan()` method
- **Breaking Change:** No — internal implementation change only; public API unchanged
- **Performance Impact:** Negligible — lock acquisition is microseconds vs. seconds for pipeline execution
- **Potential Issue:** Lock could cause deadlock if a pipeline method calls another method that also acquires the lock. Mitigation: Only acquire lock for `self.profile = ...` assignments, not for function calls.

#### Law Compliance

- **Law 14 (500 lines):** `finder/engine.py` = 252 lines → adding ~20 lines → ~272 lines ✅
- **Law 15 (Interface-only deps):** `asyncio.Lock` is stdlib ✅; no new cross-module deps ✅

---

## Integration Points

### Where Fixes Touch Shared Code

| Fix | Shared Module | Impact |
|-----|--------------|--------|
| BUG-008 | `exceptions.py` | Adds `OperationTimeoutError` to `__all__` — no behavioral change |
| BUG-011 | `finder/engine.py` | Adds `asyncio.Lock` to `VFFinder.__init__` — no API change |

**Cross-fix interaction:** None. BUG-008 and BUG-011 touch completely different subsystems (exceptions vs. finder).

**Phase 1 integration:** Both fixes are additive — they don't modify any code touched in Phase 1 (task_supervisor.py, scheduler.py, input_validation.py, vf_validator.py, health.py, health_server.py).

### External Consumers

| Consumer | What They Import | Impact of Phase 2 |
|----------|-----------------|-------------------|
| VF_TESTER.py | `from exceptions import ConfigurationError` | None — new `OperationTimeoutError` export doesn't affect existing imports |
| vf_network.py | `from exceptions import NetworkError` | None |
| plugin_system.py | `AttackContext` from `plugin_system` | None — `verify_ssl` default was already fixed |

---

## Rollback Strategy

### BUG-008 Rollback

1. Remove `OperationTimeoutError` from `__all__` in `exceptions.py`
2. Remove the `__getattr__` backward-compat alias (if added)
3. No behavioral changes to revert — all `asyncio.TimeoutError` references were left unchanged
4. **Revert time:** < 1 minute

### BUG-011 Rollback

1. Remove `self._profile_lock = asyncio.Lock()` from `VFFinder.__init__`
2. Remove all `async with self._profile_lock:` blocks in `scan()` method
3. Restore direct `self.profile = ...` assignments
4. **Revert time:** < 5 minutes

### Full Phase 2 Rollback

Since 12/14 items are already verified complete (no code changes), a full rollback only needs to revert the 2 active fixes. Git-based:

```bash
git diff HEAD -- exceptions.py finder/engine.py  # Review changes
git checkout HEAD -- exceptions.py finder/engine.py  # Revert
```

---

## Effort Estimation

| Fix | Analysis | Implementation | Testing | Total |
|-----|----------|---------------|---------|-------|
| BUG-008 (OperationTimeoutError) | 30 min (audit 40+ files) | 30 min (__all__, alias) | 30 min (verify) | **1.5 hr** |
| BUG-011 (Shared mutable state) | 15 min (read engine.py) | 30 min (add locks) | 30 min (verify) | **1.25 hr** |
| Verification (12 items) | — | — | 30 min | **0.5 hr** |
| **TOTAL** | | | | **~3.25 hr** |

### By Coder Group

| Group | Tasks | Estimated Time |
|-------|-------|---------------|
| Group A (BUG-008) | Audit + implement OperationTimeoutError | 1.5 hr |
| Group B (BUG-011) | Add asyncio.Lock to VFFinder | 1.25 hr |
| Group C (Verification) | Verify all 12 complete fixes | 0.5 hr |
| **Total (parallel)** | | **1.5 hr** (wall clock) |

---

## ADR: Phase 2 Architecture Decisions

### ADR-P2-001: Use asyncio.Lock for Profile Mutation Safety

**Status:** Proposed

**Context:** Three parallel pipelines in `VFFinder.scan()` mutate `self.profile` concurrently via `asyncio.gather()`. While CPython's cooperative scheduling makes this technically safe for non-yielding mutations, the pattern is fragile and could break if any mutation function adds an internal yield point.

**Decision:** Add `asyncio.Lock()` to serialize `self.profile` mutations. This documents the concurrency intent and protects against future yield-point issues.

**Alternatives Considered:**
- **Return-and-apply sequential pattern:** Have each pipeline return results and apply after gather. More refactoring, higher risk of breaking existing behavior.
- **Copy-on-write profile:** Each pipeline gets its own copy, merged afterward. High complexity, may lose cross-pipeline data dependencies.
- **No change (status quo):** Technically safe in current CPython, but fragile and undocumented.

**Consequences:**
- Positive: Explicit concurrency contract, future-proof, minimal code change
- Negative: Negligible lock contention overhead; requires careful lock scoping to avoid deadlock

**Trade-off:** Code clarity and safety prioritized over theoretical zero-overhead.

---

### ADR-P2-002: Backward-Compatible Exception Rename

**Status:** Proposed

**Context:** `TimeoutError` in `exceptions.py` was renamed to `OperationTimeoutError` to avoid shadowing the Python builtin. However, no callers currently import either name — all code uses `asyncio.TimeoutError` (which is correct).

**Decision:** Add `OperationTimeoutError` to `__all__` and provide a `__getattr__` deprecation alias for `TimeoutError`. Do NOT change any existing `asyncio.TimeoutError` references.

**Alternatives Considered:**
- **Mass-rename all TimeoutError references:** Dangerous — many are correct `asyncio.TimeoutError` catches
- **No action:** Class is renamed but unused — poor API surface
- **Add to __all__ only:** Simpler but provides no migration path

**Consequences:**
- Positive: Clean exception hierarchy, backward-compat for future importers, deprecation path
- Negative: Slightly more complex exceptions.py module

**Trade-off:** API completeness and forward-compatibility prioritized over minimalism.

---

## TO-DO Checklist

- [ ] **BUG-008:** Add `OperationTimeoutError` to `exceptions.__all__`
- [ ] **BUG-008:** Audit all 40+ `TimeoutError` references and classify (builtin vs custom)
- [ ] **BUG-008:** Add `__getattr__` deprecation alias for `TimeoutError` → `OperationTimeoutError`
- [ ] **BUG-008:** Identify any `raise TimeoutError(...)` sites that should use `OperationTimeoutError`
- [ ] **BUG-008:** Verify `asyncio.TimeoutError` references are unchanged
- [ ] **BUG-008:** Run `py_compile` on `exceptions.py`
- [ ] **BUG-011:** Add `self._profile_lock = asyncio.Lock()` to `VFFinder.__init__`
- [ ] **BUG-011:** Wrap `_content_pipeline()` profile mutations with lock
- [ ] **BUG-011:** Wrap `_ssl_pipeline()` profile mutations with lock
- [ ] **BUG-011:** Wrap `_dns_pipeline()` profile mutations with lock
- [ ] **BUG-011:** Verify `finder/engine.py` stays under 500 lines
- [ ] **BUG-011:** Run `py_compile` on `finder/engine.py`
- [ ] **VERIFY:** BUG-001 — `_HAS_AIOHTTP` guard in `vf_graphql_introspection.py`
- [ ] **VERIFY:** BUG-002 — `verify_ssl` defaults agree across 3 files
- [ ] **VERIFY:** BUG-003 — Cloudflare ranges use `ipaddress.ip_network()`
- [ ] **VERIFY:** BUG-005 — `sys.path.append` in `plugin_system.py`
- [ ] **VERIFY:** BUG-006 — Path traversal check in `vf_updater.py`
- [ ] **VERIFY:** BUG-007 — No auto pip install in `run.py`
- [ ] **VERIFY:** BUG-009 — Keyboard handler uses `select`/`msvcrt`
- [ ] **VERIFY:** BUG-010 — `_raw_tls_probe` uses `asyncio.open_connection`
- [ ] **VERIFY:** BUG-012 — `HAS_AIOHTTP` checks in both files
- [ ] **VERIFY:** B3 — No `/.env` or `/.git` in `COMMON_DYNAMIC_PATHS`
- [ ] **VERIFY:** B4 — Handler accumulation guard in `logging_config.py`
- [ ] **VERIFY:** B16 — `ValidationError` in `exceptions.py`, imported by `vf_validator.py`
- [ ] **DOC:** Update `memory.md` with Phase 2 status
