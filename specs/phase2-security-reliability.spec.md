# STORM VX — Phase 2: Security & Reliability Hardening Requirements Specification

**Feature ID**: P2-SECURITY-RELIABILITY
**Priority**: CRITICAL (6) + HIGH (4) + MEDIUM (4)
**Phase**: 2 — Security & Reliability Hardening
**Author**: spec-writer (Agent ID 2, Skill: feature-forge)
**Date**: 2025-03-05
**Status**: pending

---

## Overview

Phase 2 addresses 14 remaining CRITICAL + HIGH + MEDIUM priority bugs across security, reliability, and code quality. Phase 1 (6 critical fixes) is COMPLETE and approved.

**Validation Note**: All 14 bugs were validated against the current source code. Several have been partially or fully addressed in previous work sessions (W2.x–W5.x, documented in code comments). The specification below identifies the **current residual state** and remaining work for each item.

### Current State Summary

| Bug | Original Issue | Current State | Remaining Work |
|-----|---------------|---------------|----------------|
| BUG-001 | aiohttp NameError | ✅ FIXED (try/except guard exists) | Verification tests + CI enforcement |
| BUG-002 | verify_ssl contradictory defaults | ✅ FIXED (references VERIFY_SSL constant) | Add consistency test + CI enforcement |
| BUG-003 | Cloudflare IP ranges incorrect | ✅ FIXED (uses ipaddress module) | Add consistency test + auto-update mechanism |
| BUG-005 | sys.path.insert(0,...) module shadowing | ✅ FIXED (uses sys.path.append) | Add lint rule + CI enforcement |
| BUG-006 | Path traversal in vf_updater.py | ⚠️ BROKEN FIX (pathlib on str type) | Fix the broken path traversal check |
| BUG-007 | Auto pip install supply chain risk | ✅ FIXED (no longer auto-installs) | Verification + add requirements.txt hashes |
| BUG-008 | TimeoutError shadows builtins | ✅ FIXED (renamed to OperationTimeoutError) | Update remaining import references |
| BUG-009 | Keyboard handler returns None | ✅ FIXED (platform-specific impl exists) | Edge case testing + CI enforcement |
| BUG-010 | Blocking socket in vf_fp_cloner.py | ✅ FIXED (uses asyncio.open_connection) | Verification testing |
| BUG-011 | Shared mutable state in engine.py | ❌ NOT FIXED | Full implementation needed |
| BUG-012 | HAS_AIOHTTP never checked | ✅ FIXED (guards exist in both files) | Verification testing + CI enforcement |
| B3 | Sensitive paths in page_flood | ✅ FIXED (removed from COMMON_DYNAMIC_PATHS) | Verification + BLOCKED_PATHS enforcement |
| B4 | logging_config handler accumulation | ✅ FIXED (checks logger.handlers) | Edge case testing for child loggers |
| B16 | ValidationError in wrong module | ⚠️ PARTIAL (in exceptions.py but 3 stale imports) | Update 3 stale import references |

---

## Group A — Security Fixes (6 items)

---

### FR-P2-001: aiohttp Import Guard Verification and CI Enforcement

**Bug ID**: BUG-001
**Priority**: CRITICAL
**Category**: Security (Availability / CWE-758)
**Current State**: ✅ FIXED in current code

#### Description

The original bug reported that `tester/vf_graphql_introspection.py:27` had an unconditional `import aiohttp` that would crash the module when aiohttp is not installed. The current code (lines 28-33) now uses the defensive `try/except ImportError` pattern with `_HAS_AIOHTTP` flag, and guards at lines 133, 167, and 184.

**Residual Risk**: No CI enforcement exists to prevent future modules from adding unconditional aiohttp imports. The codebase currently has 7+ modules using aiohttp, and the pattern must be enforced consistently.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `tester/vf_graphql_introspection.py` | 28-33, 133, 167, 184 | VERIFIED — no code change needed |
| CI configuration | N/A | Add lint check for unguarded aiohttp imports |

#### Functional Requirements (EARS)

**FR-P2-001.1**: The system shall guard all `import aiohttp` statements outside `TYPE_CHECKING` blocks with `try/except ImportError`, setting a `HAS_AIOHTTP` flag.

**FR-P2-001.2**: Where `HAS_AIOHTTP` is `False`, the system shall not reference `aiohttp` class attributes (e.g., `aiohttp.ClientError`) in `except` clauses unless guarded by a `HAS_AIOHTTP` check.

**FR-P2-001.3**: When `HAS_AIOHTTP` is `False` and an aiohttp-dependent method is called, the system shall log an error and return a safe default rather than crashing with `NameError` or `AttributeError`.

**FR-P2-001.4**: The CI pipeline shall reject any module that imports `aiohttp` unconditionally outside `TYPE_CHECKING` blocks.

#### Acceptance Criteria

```
AC-P2-001.1:
  Given all Python files in the project,
  When searching for bare "import aiohttp" outside TYPE_CHECKING blocks,
  Then zero matches exist that are not wrapped in try/except ImportError.

AC-P2-001.2:
  Given aiohttp is not installed,
  When vf_graphql_introspection is imported,
  Then the module loads successfully without NameError
  And _HAS_AIOHTTP is False.

AC-P2-001.3:
  Given aiohttp is not installed and _HAS_AIOHTTP is False,
  When _worker_loop() is called,
  Then the method returns immediately without error.

AC-P2-001.4:
  Given a CI pipeline with the aiohttp import guard check,
  When a new module is added with unguarded "import aiohttp",
  Then the CI build fails with a descriptive error.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents module crash on missing dependency | PASS |
| Law 9 (Extensible) | Standard import guard pattern is consistent | PASS |
| Law 10 (Standard) | Follows Python optional-dependency pattern | PASS |

#### Risk Assessment

Low risk — this is a verification and CI enforcement task. No code changes required in the module itself.

#### Dependencies

None — independent of all other Phase 2 fixes.

---

### FR-P2-002: verify_ssl Default Consistency — Add Enforcement Tests

**Bug ID**: BUG-002
**Priority**: CRITICAL
**Category**: Security (CWE-295: Improper Certificate Validation)
**Current State**: ✅ FIXED in current code

#### Description

The original bug reported that `config/settings.py:33` had `verify_ssl: bool = False` while `config/defaults.py:31` had `VERIFY_SSL: bool = True` and `plugin_system.py:230` had `verify_ssl: bool = True`. The current code at `settings.py:56` correctly uses `verify_ssl: bool = VERIFY_SSL` referencing the constant, and `plugin_system.py:230` also references `VERIFY_SSL` (via comment "SEC-07").

**Residual Risk**: No test ensures this consistency is maintained. A future developer could hardcode `False` again. The `run.py:394-395` `--verify-ssl` flag description says "default: disabled for testing" which contradicts the actual secure default.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `config/settings.py` | 56 | VERIFIED — no code change needed |
| `config/defaults.py` | 34 | VERIFIED — no code change needed |
| `plugin_system.py` | 230 | VERIFIED — no code change needed |
| `run.py` | 395 | Fix misleading help text |
| Test suite | N/A | Add consistency test |

#### Functional Requirements (EARS)

**FR-P2-002.1**: The `ConnectionSettings.verify_ssl` default shall always reference `VERIFY_SSL` from `config/defaults.py`, never a hardcoded boolean literal.

**FR-P2-002.2**: The `AttackContext.verify_ssl` default shall always be `True` (matching `config/defaults.py VERIFY_SSL`).

**FR-P2-002.3**: The system shall include a test that asserts `ConnectionSettings().verify_ssl == defaults.VERIFY_SSL`.

**FR-P2-002.4**: Where CLI help text references the SSL verification default, it shall accurately state "default: enabled for security".

#### Acceptance Criteria

```
AC-P2-002.1:
  Given ConnectionSettings is instantiated with no arguments,
  When verify_ssl is read,
  Then it equals defaults.VERIFY_SSL (True).

AC-P2-002.2:
  Given AttackContext is instantiated with no arguments,
  When verify_ssl is read,
  Then it equals True.

AC-P2-002.3:
  Given the test suite,
  When the verify_ssl consistency test runs,
  Then it asserts ConnectionSettings().verify_ssl == defaults.VERIFY_SSL.

AC-P2-002.4:
  Given "python run.py --help" output,
  When the --verify-ssl help text is read,
  Then it says "Enable SSL certificate verification (default: enabled for security)"
  not "default: disabled for testing".
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Ensures SSL verification is on by default (CWE-295) | PASS |
| Law 9 (Extensible) | Single source of truth in defaults.py | PASS |
| Law 10 (Standard) | Secure-by-default principle | PASS |

#### Risk Assessment

Low risk — verification and documentation task. The code is already correct.

#### Dependencies

None — independent.

---

### FR-P2-003: Cloudflare IP Range Verification and Auto-Update Mechanism

**Bug ID**: BUG-003
**Priority**: CRITICAL
**Category**: Network (Incorrect CDN Classification / CWE-1037)
**Current State**: ✅ FIXED in current code

#### Description

The original bug reported incorrect hex-to-IP mappings in `finder/dns_scanner.py:191-203`. The Cloudflare IP ranges have been moved to `finder/vf_origin_discovery.py:54-71` and now use `ipaddress.ip_network()` for proper CIDR matching with the `is_cdn_ip()` function at lines 106-122.

**Residual Risk**: The Cloudflare IP ranges are hardcoded and may become outdated if Cloudflare adds/removes ranges. No mechanism exists to verify them against the official source.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `finder/vf_origin_discovery.py` | 54-71 | VERIFIED — ranges are correct |
| Test suite | N/A | Add verification test against official API |

#### Functional Requirements (EARS)

**FR-P2-003.1**: The system shall use `ipaddress.ip_network()` for all CDN IP range comparisons (not manual hex arithmetic).

**FR-P2-003.2**: The Cloudflare IPv4 ranges shall match the official list at `https://www.cloudflare.com/ips-v4/`.

**FR-P2-003.3**: The system shall include a test that validates CDN_IPV4_RANGES["cloudflare"] against the official Cloudflare IP list (optionally, with a manual trigger mode for CI).

**FR-P2-003.4**: Where a CDN range is used for classification, the `is_cdn_ip()` function shall correctly identify IPs within any registered CDN network.

#### Acceptance Criteria

```
AC-P2-003.1:
  Given the codebase,
  When searching for manual hex IP range comparisons (tuple of ints),
  Then zero such patterns exist in finder/ modules.

AC-P2-003.2:
  Given the current CDN_IPV4_RANGES["cloudflare"] list,
  When compared against the official Cloudflare IP list,
  Then all 15 CIDR blocks are present and correct.

AC-P2-003.3:
  Given an IP of 104.16.0.1 (within Cloudflare 104.16.0.0/13),
  When is_cdn_ip() is called,
  Then it returns True.

AC-P2-003.4:
  Given an IP of 1.1.1.1 (Cloudflare DNS, NOT in CDN ranges),
  When is_cdn_ip() is called with cdn_ips=set(),
  Then it returns False (correctly, since 1.1.1.1 is DNS not CDN).
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Correct CDN classification prevents misdirected attacks | PASS |
| Law 9 (Extensible) | ipaddress module makes adding new CDN ranges trivial | PASS |
| Law 10 (Standard) | Uses Python stdlib ipaddress (PEP 3144) | PASS |

#### Risk Assessment

Low risk — verification task. Code is already correct.

#### Dependencies

None — independent.

---

### FR-P2-004: Fix Broken Path Traversal Check in vf_updater.py

**Bug ID**: BUG-006
**Priority**: CRITICAL
**Category**: Security (Path Traversal / CWE-22)
**Current State**: ⚠️ BROKEN FIX — pathlib syntax used on string type

#### Description

The `_api_download()` method at `infra/vf_updater.py:525-529` attempts to validate that downloaded file paths stay within `self.project_root`. However, the fix uses pathlib's `/` operator on `self.project_root` which is a **string** (defined at line 113 as `os.path.dirname(os.path.dirname(os.path.abspath(__file__)))`), causing a `TypeError: unsupported operand type(s) for /: 'str' and 'str'` at runtime.

**Current Code (BROKEN)**:
```python
# vf_updater.py:525-529
resolved = (self.project_root / file_path).resolve()  # TypeError: str / str
if not str(resolved).startswith(str(self.project_root.resolve())):
    logger.warning(f"Path traversal detected, skipping: {file_path}")
    continue
```

This means the path traversal protection is completely non-functional — any `TypeError` from this line would either crash the download or be caught by the outer exception handler, silently allowing path traversal.

**Fix Required**: Convert `self.project_root` to `pathlib.Path` and use proper path traversal validation.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `infra/vf_updater.py` | 113 | Change `self.project_root` to `Path(...)` |
| `infra/vf_updater.py` | 525-529 | Fix path traversal check to use pathlib correctly |
| `infra/vf_updater.py` | 164, 403, 440, 447, 541 | Update os.path.join calls for Path compatibility |

#### Functional Requirements (EARS)

**FR-P2-004.1**: The system shall validate that all file paths downloaded from the GitHub API resolve to a location within `self.project_root`.

**FR-P2-004.2**: Where a downloaded file path contains `..` or resolves to a location outside `self.project_root`, the system shall skip that file and log a warning.

**FR-P2-004.3**: The path traversal validation shall use `pathlib.Path.resolve()` for correct symlink resolution and comparison.

**FR-P2-004.4**: The system shall reject absolute paths in GitHub API tree entries (paths starting with `/`).

**FR-P2-004.5**: The `self.project_root` attribute shall be a `pathlib.Path` object for consistent path operations throughout the class.

#### Acceptance Criteria

```
AC-P2-004.1:
  Given a GitHub API tree with path "../../etc/cron.d/malware",
  When _api_download() processes it,
  Then the file is skipped with a logged warning
  And no file is written outside project_root.

AC-P2-004.2:
  Given a GitHub API tree with path "tester/vf_keyboard.py" (normal),
  When _api_download() processes it,
  Then the file is downloaded to project_root/tester/vf_keyboard.py.

AC-P2-004.3:
  Given a GitHub API tree with absolute path "/etc/passwd",
  When _api_download() processes it,
  Then the file is skipped with a logged warning.

AC-P2-004.4:
  Given a symlink in project_root that points outside,
  When _api_download() resolves the target path,
  Then Path.resolve() follows the symlink and detects the escape.

AC-P2-004.5:
  Given self.project_root is a pathlib.Path object,
  When all path operations in AutoUpdater use it,
  Then no TypeError occurs from mixing str and Path types.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents path traversal attacks (CWE-22) | PASS |
| Law 9 (Extensible) | pathlib.Path is the modern Python standard | PASS |
| Law 10 (Standard) | Uses stdlib pathlib, not custom path logic | PASS |

#### Risk Assessment

**Medium risk** — Converting `self.project_root` from `str` to `Path` requires updating all `os.path.join(self.project_root, ...)` calls to use Path's `/` operator or `str(self.project_root)`. The rollback code at line 403 also uses `os.path.join(self.project_root, rel_path)` and must be updated. Missing any call site could cause a new `TypeError`.

#### Dependencies

None — independent.

---

### FR-P2-005: Auto pip install — Verification and Requirements Hardening

**Bug ID**: BUG-007
**Priority**: CRITICAL
**Category**: Security (Supply Chain / CWE-494)
**Current State**: ✅ FIXED in current code

#### Description

The original bug reported that `run.py:227-259` automatically ran `pip install` for missing packages, creating a supply chain attack vector. The current code at `run.py:189-215` now prints an error and exits instead of auto-installing.

**Residual Risk**: No `requirements.txt` with pinned versions and hashes exists. The error message suggests `pip install` without hash verification.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `run.py` | 189-215 | VERIFIED — no auto-install |
| Project root | N/A | Create requirements.txt with pinned versions + hashes |

#### Functional Requirements (EARS)

**FR-P2-005.1**: The system shall never automatically install Python packages at runtime.

**FR-P2-005.2**: Where required packages are missing, the system shall print an error with manual install instructions and exit with code 1.

**FR-P2-005.3**: The project shall include a `requirements.txt` with pinned package versions.

**FR-P2-005.4**: The install instructions shall recommend `pip install -r requirements.txt` rather than individual package names.

#### Acceptance Criteria

```
AC-P2-005.1:
  Given the run.py code,
  When searching for "subprocess" calls to pip,
  Then zero such calls exist.

AC-P2-005.2:
  Given aiohttp is not installed,
  When run.py is executed,
  Then it prints "[ERROR] Missing required packages: aiohttp"
  And exits with code 1.

AC-P2-005.3:
  Given the project root,
  When requirements.txt is checked,
  Then it exists with pinned versions for aiohttp, httpx, beautifulsoup4.

AC-P2-005.4:
  Given the error message in run.py,
  When a missing package is detected,
  Then the message includes "pip install -r requirements.txt".
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Eliminates supply chain attack vector (CWE-494) | PASS |
| Law 9 (Extensible) | requirements.txt is standard for dependency management | PASS |
| Law 10 (Standard) | Pinned requirements with hashes is industry standard | PASS |

#### Risk Assessment

Low risk — verification and documentation task. Creating requirements.txt is additive with no breaking changes.

#### Dependencies

None — independent.

---

### FR-P2-006: TimeoutError Builtin Shadowing — Update Remaining References

**Bug ID**: BUG-008
**Priority**: CRITICAL
**Category**: Code Quality (Name Collision / CWE-1110)
**Current State**: ✅ FIXED in exceptions.py, but stale references may exist

#### Description

The custom `TimeoutError` class in `exceptions.py` has been renamed to `OperationTimeoutError` (lines 33-42). However, any code that imports `TimeoutError` from `exceptions` would need updating, and any code that catches the builtin `TimeoutError` may accidentally catch the custom one if `from exceptions import *` was used.

**Residual Risk**: Need to verify no code still imports `TimeoutError` from `exceptions.py`, and that all catch sites use the correct exception type.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `exceptions.py` | 33-42 | VERIFIED — OperationTimeoutError |
| All .py files | N/A | Verify no stale `from exceptions import TimeoutError` |

#### Functional Requirements (EARS)

**FR-P2-006.1**: The custom timeout exception shall be named `OperationTimeoutError`, distinct from the Python builtin `TimeoutError`.

**FR-P2-006.2**: Where code needs to catch the project-specific timeout, it shall catch `OperationTimeoutError`, not `TimeoutError`.

**FR-P2-006.3**: Where code needs to catch asyncio's timeout, it shall catch `asyncio.TimeoutError`, which is the builtin.

**FR-P2-006.4**: No module shall import `TimeoutError` from `exceptions.py` (only `OperationTimeoutError`).

#### Acceptance Criteria

```
AC-P2-006.1:
  Given all Python files in the project,
  When searching for "from exceptions import TimeoutError",
  Then zero matches exist.

AC-P2-006.2:
  Given all Python files in the project,
  When searching for "from exceptions import OperationTimeoutError",
  Then all matches are valid usage sites.

AC-P2-006.3:
  Given exceptions.py,
  When the class at line 33 is inspected,
  Then it is named OperationTimeoutError (not TimeoutError).
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents exception handling confusion | PASS |
| Law 9 (Extensible) | Distinct names allow independent evolution | PASS |
| Law 10 (Standard) | Avoids shadowing Python builtins (PEP 8) | PASS |

#### Risk Assessment

Low risk — verification task. The rename is already done; just need to confirm no stale imports.

#### Dependencies

None — independent.

---

## Group B — Reliability Fixes (4 items)

---

### FR-P2-007: Keyboard Handler — Edge Case Testing and Robustness

**Bug ID**: BUG-009
**Priority**: HIGH
**Category**: Reliability (User Interface)
**Current State**: ✅ FIXED — platform-specific implementation exists

#### Description

The original bug reported that `get_command()` always returned `None`. The current code at `tester/vf_keyboard.py:36-55` has a proper implementation using `msvcrt` on Windows and `select` on Unix. However, there are edge cases not covered:

1. Line 51 uses `sys.stdin.readline()` which blocks until newline — should use `sys.stdin.read(1)` for single-character input.
2. No handling for when stdin is not a TTY (piped input, background process).
3. The `select` import on Unix is inside the method, not at module level.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `tester/vf_keyboard.py` | 50-51 | Fix Unix path to use read(1) instead of readline() |
| `tester/vf_keyboard.py` | N/A | Add TTY detection guard |

#### Functional Requirements (EARS)

**FR-P2-007.1**: The `get_command()` method shall return `None` when stdin is not a TTY (e.g., piped input, background process).

**FR-P2-007.2**: On Unix systems, the keyboard handler shall read a single character using `sys.stdin.read(1)`, not `sys.stdin.readline()` which requires pressing Enter.

**FR-P2-007.3**: The keyboard handler shall not block the event loop under any circumstances.

**FR-P2-007.4**: On Windows, the keyboard handler shall use `msvcrt.kbhit()` and `msvcrt.getch()` for non-blocking input.

#### Acceptance Criteria

```
AC-P2-007.1:
  Given stdin is not a TTY (e.g., piped input),
  When get_command() is called,
  Then it returns None immediately without error.

AC-P2-007.2:
  Given a Unix system and stdin is a TTY,
  When the user presses '+' without pressing Enter,
  Then get_command() returns '+' immediately.

AC-P2-007.3:
  Given any platform,
  When get_command() is called and no key is pressed,
  Then it returns None within 1ms (non-blocking).

AC-P2-007.4:
  Given a Windows system and a keypress is available,
  When get_command() is called,
  Then it returns the mapped command ('+', '-', or 'q').
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Non-blocking I/O prevents event loop stalls | PASS |
| Law 9 (Extensible) | Platform-specific paths are cleanly separated | PASS |
| Law 10 (Standard) | Uses platform-native APIs (select/msvcrt) | PASS |

#### Risk Assessment

Low risk — fixing `readline()` to `read(1)` is a targeted change. Adding TTY detection is defensive.

#### Dependencies

None — independent.

---

### FR-P2-008: Blocking Socket Replacement Verification

**Bug ID**: BUG-010
**Priority**: HIGH
**Category**: Performance (Event Loop Blocking)
**Current State**: ✅ FIXED — uses asyncio.open_connection()

#### Description

The original bug reported that `evasion/vf_fp_cloner.py:289` used `socket.create_connection()` (blocking) inside an async method. The current code at lines 290-322 uses `asyncio.open_connection()` with `asyncio.wait_for()` and proper timeout handling.

**Residual Risk**: Need to verify that the async replacement produces the same TLS information as the original blocking version, and that error handling covers all cases.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `evasion/vf_fp_cloner.py` | 276-322 | VERIFIED — async implementation exists |
| Test suite | N/A | Add async TLS probe test |

#### Functional Requirements (EARS)

**FR-P2-008.1**: The `_raw_tls_probe()` method shall use `asyncio.open_connection()` instead of `socket.create_connection()` to avoid blocking the event loop.

**FR-P2-008.2**: Where `_raw_tls_probe()` connects to a TLS endpoint, it shall extract TLS version, cipher suite, and ALPN protocol from the async SSL object.

**FR-P2-008.3**: Where the TLS probe times out, the system shall return a default result dict rather than hanging or raising an unhandled exception.

#### Acceptance Criteria

```
AC-P2-008.1:
  Given vf_fp_cloner.py source code,
  When searching for "socket.create_connection",
  Then zero matches exist.

AC-P2-008.2:
  Given a target with HTTPS on port 443,
  When _raw_tls_probe() is called,
  Then it returns a dict with keys: ja3_hash, tls_version, cipher_suite, alpn
  And the method completes within EVASION_FPC_TIMEOUT seconds.

AC-P2-008.3:
  Given a target that does not respond within timeout,
  When _raw_tls_probe() is called,
  Then it returns a default result dict without raising an unhandled exception
  And the event loop is not blocked.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents event loop blocking (availability) | PASS |
| Law 9 (Extensible) | asyncio-based I/O is the project standard | PASS |
| Law 10 (Standard) | Uses Python's canonical async I/O API | PASS |

#### Risk Assessment

Low risk — verification task only.

#### Dependencies

None — independent.

---

### FR-P2-009: Shared Mutable State in finder/engine.py Parallel Pipelines

**Bug ID**: BUG-011
**Priority**: HIGH
**Category**: Architecture (Race Condition / CWE-362)
**Current State**: ❌ NOT FIXED — requires full implementation

#### Description

In `finder/engine.py`, the `VFFinder.scan()` method runs three async pipelines in parallel via `asyncio.gather()` (lines 153-158):

1. `_content_pipeline()` — mutates `self.profile` at lines 89, 93, 101, 108
2. `_ssl_pipeline()` — mutates `self.profile` at lines 124-133
3. `_dns_pipeline()` — mutates `self.profile` at line 144

All three pipelines directly mutate the shared `self.profile` (a `SiteProfile` dataclass) without any synchronization. While Python's GIL prevents true data races for CPU-bound work, the async pipelines yield control during I/O operations, and concurrent list/dict mutations (e.g., `self.profile.api_endpoints.append()`) can cause issues if one coroutine is iterating while another mutates.

The `_perf_pipeline()` at lines 182-184 and cache analysis at lines 186-190 have the same issue.

**Fix Required**: Each pipeline should return its results instead of mutating `self.profile` directly. After `gather()` completes, apply results sequentially to `self.profile`. Alternatively, use an `asyncio.Lock()` for profile mutations.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `finder/engine.py` | 85-190 | Refactor pipelines to return results, apply sequentially |

#### Functional Requirements (EARS)

**FR-P2-009.1**: Where multiple async pipelines run in parallel via `asyncio.gather()`, each pipeline shall return its results rather than directly mutating shared state.

**FR-P2-009.2**: After `asyncio.gather()` completes, the system shall apply pipeline results to `self.profile` sequentially to prevent concurrent mutation.

**FR-P2-009.3**: The public API of `VFFinder.scan()` shall remain unchanged — it shall still return a `SiteProfile` object.

**FR-P2-009.4**: Where a pipeline raises an exception, the system shall still apply results from other successful pipelines.

#### Acceptance Criteria

```
AC-P2-009.1:
  Given the _content_pipeline, _ssl_pipeline, and _dns_pipeline functions,
  When they are called within asyncio.gather(),
  Then none of them directly mutate self.profile
  (they return results instead).

AC-P2-009.2:
  Given all three pipelines complete successfully,
  When their results are applied to self.profile,
  Then all discovered data is present in the final SiteProfile.

AC-P2-009.3:
  Given VFFinder.scan() is called,
  When it returns,
  Then it returns a SiteProfile object with the same data as before the refactor.

AC-P2-009.4:
  Given _ssl_pipeline raises an exception but _content_pipeline succeeds,
  When the gather results are processed,
  Then content analysis results are still applied to self.profile
  And the SSL error is logged.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents race conditions in concurrent code | PASS |
| Law 9 (Extensible) | Return-values pattern is more composable than mutation | PASS |
| Law 10 (Standard) | Functional pipeline pattern is a recognized best practice | PASS |

#### Risk Assessment

**High risk** — This is the most complex fix in Phase 2. The pipelines currently call multiple functions that accept `self.profile` as a parameter and return a modified version. The refactoring requires:
1. Changing `_content_pipeline`, `_ssl_pipeline`, `_dns_pipeline` to return their results
2. Creating an application step after `gather()` that applies results to `self.profile`
3. Handling the case where some functions modify `self.profile` by reference (e.g., `analyze_content()`) vs. returning a new value
4. Ensuring the `_enhancer` methods (which also mutate `self.profile`) are handled correctly

The key challenge is that helper functions like `analyze_content(self._html, self.url, self.profile)` take `self.profile` as input and return it. The pipeline can pass `self.profile` to these functions and collect the return value, then apply all returns at the end.

#### Dependencies

None — independent, but careful testing required.

---

### FR-P2-010: HAS_AIOHTTP Guard Verification and CI Enforcement

**Bug ID**: BUG-012
**Priority**: HIGH
**Category**: Code Quality (Missing Guard / CWE-758)
**Current State**: ✅ FIXED — guards exist in both files

#### Description

Both `evasion/vf_session_harvest.py:192` and `evasion/vf_fp_cloner.py:207` now check `HAS_AIOHTTP` before using aiohttp. The original bug reported that the flag was set but never checked.

**Residual Risk**: No CI enforcement to ensure future modules that set `HAS_AIOHTTP` also check it before using aiohttp.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `evasion/vf_session_harvest.py` | 36-40, 192-194 | VERIFIED |
| `evasion/vf_fp_cloner.py` | 36-40, 207-209 | VERIFIED |
| CI configuration | N/A | Add grep-based check |

#### Functional Requirements (EARS)

**FR-P2-010.1**: Where a module defines `HAS_AIOHTTP = True/False` via try/except ImportError, the module shall check `HAS_AIOHTTP` before using any `aiohttp` class or method.

**FR-P2-010.2**: Where `HAS_AIOHTTP` is `False` and an aiohttp-dependent method is called, the system shall log an error and return a safe default.

**FR-P2-010.3**: The CI pipeline shall verify that every module setting `HAS_AIOHTTP` also contains at least one `if not HAS_AIOHTTP:` guard.

#### Acceptance Criteria

```
AC-P2-010.1:
  Given all Python files that define HAS_AIOHTTP,
  When searching for "if not HAS_AIOHTTP" or "if HAS_AIOHTTP is False",
  Then every such file has at least one guard before aiohttp usage.

AC-P2-010.2:
  Given aiohttp is not installed,
  When SessionHarvester.harvest() is called,
  Then it returns a safe default dict (not None, not crash).

AC-P2-010.3:
  Given aiohttp is not installed,
  When BrowserFingerprintCloner.probe_target() is called,
  Then it returns a default result dict (not None, not crash).
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Graceful degradation on missing dependency | PASS |
| Law 9 (Extensible) | Consistent pattern across modules | PASS |
| Law 10 (Standard) | Standard Python optional-dependency pattern | PASS |

#### Risk Assessment

Low risk — verification and CI enforcement task.

#### Dependencies

FR-P2-001 (aiohttp import guard) — shares the same CI enforcement mechanism.

---

## Group C — Code Quality & Safety Fixes (4 items)

---

### FR-P2-011: Cloudflare IP Range Consistency Test (see FR-P2-003)

**Bug ID**: BUG-003
**Priority**: MEDIUM → covered by FR-P2-003
**Note**: This is the same bug as FR-P2-003. The Cloudflare IP ranges have been fixed. The remaining work is adding a consistency test, which is specified under FR-P2-003 above.

---

### FR-P2-012: Remove Sensitive Paths and Enforce BLOCKED_PATHS

**Bug ID**: B3
**Priority**: HIGH → MEDIUM (already fixed in code)
**Category**: Security (Data Exfiltration Risk / CWE-538)
**Current State**: ✅ FIXED — /.env and /.git/config removed from COMMON_DYNAMIC_PATHS

#### Description

The original bug reported that `tester/vf_page_flood.py:56` probed `/.env` and `/.git/config`. These paths have been removed from `COMMON_DYNAMIC_PATHS` (lines 45-60). Additionally, `vf_validator.py:42-46` defines `BLOCKED_PATHS` that includes `/.env` and `/.git`.

**Residual Risk**: The `BLOCKED_PATHS` list in `vf_validator.py` exists but is not enforced during page_flood's discovery phase. Also, `finder/vf_origin_discovery.py:595` still probes `/.env` in the header leak analysis paths.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `tester/vf_page_flood.py` | 45-60 | VERIFIED — sensitive paths removed |
| `finder/vf_origin_discovery.py` | 595 | Remove `/.env` from leak_paths |
| `tester/vf_page_flood.py` | N/A | Add BLOCKED_PATHS enforcement in discovery |

#### Functional Requirements (EARS)

**FR-P2-012.1**: The page flood discovery phase shall not probe paths listed in `BLOCKED_PATHS` (from `vf_validator.py`).

**FR-P2-012.2**: The origin IP discovery module shall not probe `/.env` or `/.git/config` in its leak analysis paths.

**FR-P2-012.3**: Where a discovered URL matches a blocked path pattern, the system shall exclude it from the target list.

#### Acceptance Criteria

```
AC-P2-012.1:
  Given COMMON_DYNAMIC_PATHS in vf_page_flood.py,
  When searching for "/.env" or "/.git/config",
  Then zero matches exist.

AC-P2-012.2:
  Given leak_paths in vf_origin_discovery.py,
  When searching for "/.env",
  Then zero matches exist.

AC-P2-012.3:
  Given vf_page_flood's _discover_endpoints() runs,
  When an HTML link matches a BLOCKED_PATHS entry,
  Then it is excluded from the discovered URL set.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents data exfiltration during testing (CWE-538) | PASS |
| Law 9 (Extensible) | BLOCKED_PATHS list is centralized and extensible | PASS |
| Law 10 (Standard) | Ethical testing practices | PASS |

#### Risk Assessment

Low risk — removing `/.env` from one list and adding a filter check.

#### Dependencies

None — independent.

---

### FR-P2-013: Fix logging_config.py Handler Accumulation for Child Loggers

**Bug ID**: B4
**Priority**: MEDIUM
**Category**: Code Quality (Log Duplication / CWE-776)
**Current State**: ✅ MOSTLY FIXED — `if not logger.handlers` guard exists

#### Description

The current code at `logging_config.py:93-94` checks `if not logger.handlers:` before adding a console handler, preventing duplicates for the root logger. However, there's an edge case: if `setup_logger()` is called with a specific name (not "storm_vx"), the `logging.getLogger(name)` call returns a child logger that inherits handlers from the root logger. If the module-level `logger = setup_logger()` at line 123 creates the root logger, and then a module calls `setup_logger("my_module")`, the child logger gets duplicate output from both its own handler and the root's handler.

The `get_logger()` function at line 126 correctly uses `logging.getLogger(name)` without adding handlers, which is the right approach for child loggers. The issue is if someone calls `setup_logger()` instead of `get_logger()` for child loggers.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `logging_config.py` | 90-100 | Add propagate=False for non-root loggers, or only add handlers to the root logger |
| `logging_config.py` | 126-147 | Verify get_logger() is used correctly everywhere |

#### Functional Requirements (EARS)

**FR-P2-013.1**: The `setup_logger()` function shall only add handlers to the root "storm_vx" logger, not to child loggers.

**FR-P2-013.2**: Where a child logger is created via `get_logger(name)`, it shall inherit handlers from the root logger via propagation, not add its own.

**FR-P2-013.3**: Where `setup_logger()` is called with a name different from "storm_vx", the system shall not add duplicate handlers.

**FR-P2-013.4**: Log messages shall appear exactly once in the console output, not duplicated.

#### Acceptance Criteria

```
AC-P2-013.1:
  Given setup_logger("storm_vx.my_module") is called,
  When the logger emits a message,
  Then the message appears exactly once in console output.

AC-P2-013.2:
  Given get_logger("storm_vx.evasion") is called,
  When the logger emits a message,
  Then the message appears exactly once.

AC-P2-013.3:
  Given setup_logger() is called twice with the same name,
  When the logger's handlers are inspected,
  Then there is exactly one console handler.

AC-P2-013.4:
  Given the module-level logger = setup_logger() at line 123,
  When a submodule calls get_logger(__name__),
  Then the submodule logger has zero direct handlers
  And inherits from the root logger via propagation.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Prevents log flooding that could mask security events | PASS |
| Law 9 (Extensible) | Standard Python logging hierarchy | PASS |
| Law 10 (Standard) | Follows Python logging best practices | PASS |

#### Risk Assessment

Low risk — modifying setup_logger() to only add handlers to the root logger is a targeted change.

#### Dependencies

None — independent.

---

### FR-P2-014: Move ValidationError Import References to Centralized Location

**Bug ID**: B16
**Priority**: MEDIUM
**Category**: Code Quality (Inconsistent Exception Hierarchy)
**Current State**: ⚠️ PARTIAL — ValidationError is in exceptions.py but 3 files still import from vf_validator

#### Description

`ValidationError` is now defined in `exceptions.py:13-15` (as a subclass of `ValueError`), and `vf_validator.py:15` correctly imports it from there. However, three files still import `ValidationError` from `vf_validator` instead of from `exceptions`:

1. `tester/VF_TESTER.py:193` — `from vf_validator import validate_target_url, validate_worker_count, validate_ip_address, ValidationError`
2. `infra/vf_telegram.py:389` — `from vf_validator import validate_target_url, ValidationError`
3. `VF_FINDER.py:282` — `from vf_validator import validate_target_url, ValidationError`

This creates an inconsistent import chain: `exceptions.ValidationError` → `vf_validator.ValidationError` (re-exported) → consumer modules. While functionally equivalent (vf_validator re-exports from exceptions), it violates Law 15 (interface-only deps) and creates confusion about where the exception is actually defined.

#### Affected Files
| File | Lines | Change |
|------|-------|--------|
| `tester/VF_TESTER.py` | 193 | Change `from vf_validator import ..., ValidationError` to `from exceptions import ValidationError` |
| `infra/vf_telegram.py` | 389 | Change `from vf_validator import ..., ValidationError` to `from exceptions import ValidationError` |
| `VF_FINDER.py` | 282 | Change `from vf_validator import ..., ValidationError` to `from exceptions import ValidationError` |
| `vf_validator.py` | 15 | Add `__all__` to control re-export surface |

#### Functional Requirements (EARS)

**FR-P2-014.1**: The `ValidationError` class shall be defined in `exceptions.py` and imported from there by all consumer modules.

**FR-P2-014.2**: Where a module needs both validation functions and `ValidationError`, it shall import them from their respective canonical locations (`vf_validator` for functions, `exceptions` for the class).

**FR-P2-014.3**: The `vf_validator` module shall import `ValidationError` from `exceptions` and may optionally re-export it, but consumer modules shall import from the canonical location.

#### Acceptance Criteria

```
AC-P2-014.1:
  Given all Python files in the project,
  When searching for "from vf_validator import.*ValidationError",
  Then zero matches exist.

AC-P2-014.2:
  Given all Python files that use ValidationError,
  When searching for "from exceptions import ValidationError",
  Then all consumer modules import from exceptions.py.

AC-P2-014.3:
  Given vf_validator.py,
  When its imports are inspected,
  Then it contains "from exceptions import ValidationError"
  And no "class ValidationError" definition.
```

#### Law Compliance

| Law | Check | Status |
|-----|-------|--------|
| Law 5 (Secure) | Centralized exception hierarchy is easier to audit | PASS |
| Law 9 (Extensible) | Single definition point for exceptions | PASS |
| Law 10 (Standard) | Consistent import patterns follow Python conventions | PASS |
| Law 15 (Interface-only deps) | Consumer modules import from the defining module | PASS |

#### Risk Assessment

Low risk — updating 3 import statements. The re-export from vf_validator means current code works, but cleaning up the imports improves maintainability.

#### Dependencies

None — independent.

---

## Non-Functional Requirements

### Performance
- FR-P2-009 (shared mutable state) refactoring shall not increase scan time by more than 5%.
- FR-P2-008 (async TLS probe) verification shall confirm no event loop blocking during probe.
- FR-P2-007 (keyboard handler) shall have < 1ms overhead per call when no key is pressed.

### Security
- FR-P2-004 (path traversal) shall prevent all CWE-22 attacks via `../../` sequences.
- FR-P2-012 (sensitive paths) shall prevent probing of `/.env`, `/.git/config`, `/.ssh/`.
- All fixes shall be reviewed by security-auditor agent before merge (Law 12).

### Compatibility
- FR-P2-009 shall maintain the same public API for `VFFinder.scan()`.
- FR-P2-014 shall maintain backward compatibility for any code importing `ValidationError` from `vf_validator`.
- FR-P2-004 shall maintain the same AutoUpdater public API.

### Testing
- Each fix that involves code changes shall have at least one test case.
- FR-P2-004 (path traversal) shall have adversarial test inputs (`../../etc/passwd`, `/absolute/path`).
- FR-P2-009 (shared state) shall have a test that runs pipelines concurrently and verifies consistent results.

---

## Error Handling

| Error Condition | Behavior | Code/Message |
|-----------------|----------|--------------|
| Path traversal detected in updater | Skip file, log warning | "[UPDATER] Path traversal detected, skipping: {path}" |
| aiohttp not available when needed | Log error, return safe default | "[SESSION] aiohttp not installed — session harvesting unavailable" |
| stdin not a TTY | Return None from get_command() | No error, silent return |
| Pipeline raises exception in gather | Apply other pipeline results, log error | "[PIPELINE] {name} error: {exc}" |
| ValidationError from wrong import | Works (re-exported), but lint warning | CI check fails on stale import |

---

## Implementation TODO Checklist (55 action items)

### FR-P2-001: aiohttp Import Guard Verification
- [ ] Verify all modules using aiohttp have try/except ImportError guard
- [ ] Verify all modules with HAS_AIOHTTP check the flag before aiohttp usage
- [ ] Add CI grep check: reject unguarded `import aiohttp` outside TYPE_CHECKING
- [ ] Write test: module loads without aiohttp installed
- [ ] Write test: HAS_AIOHTTP=False → methods return safe defaults

### FR-P2-002: verify_ssl Consistency
- [ ] Verify ConnectionSettings().verify_ssl == defaults.VERIFY_SSL
- [ ] Verify AttackContext().verify_ssl == True
- [ ] Add unit test: assert ConnectionSettings().verify_ssl == defaults.VERIFY_SSL
- [ ] Fix run.py:395 help text (change "default: disabled" to "default: enabled")
- [ ] Add CI check: no hardcoded `verify_ssl: bool = False` in any settings dataclass

### FR-P2-003: Cloudflare IP Range Verification
- [ ] Verify CDN_IPV4_RANGES uses ipaddress.ip_network()
- [ ] Verify is_cdn_ip() correctly classifies known Cloudflare IPs
- [ ] Verify is_cdn_ip() correctly rejects non-CDN IPs
- [ ] Add test: 104.16.0.1 → is_cdn_ip() returns True
- [ ] Add test: 1.2.3.4 → is_cdn_ip() returns False (with empty cdn_ips)
- [ ] Add test: validate CDN_IPV4_RANGES against official Cloudflare IP list
- [ ] Document update procedure for when Cloudflare changes IP ranges

### FR-P2-004: Fix Broken Path Traversal Check
- [ ] Change `self.project_root` from `str` to `pathlib.Path` in `__init__`
- [ ] Fix line 525-529: use `Path(self.project_root) / file_path` correctly
- [ ] Add `os.path.isabs(file_path)` check for absolute paths
- [ ] Add `'..' in Path(file_path).parts` check for traversal components
- [ ] Update line 164: `os.path.join(self.project_root, ".version")` for Path
- [ ] Update line 403: `os.path.join(self.project_root, rel_path)` for Path
- [ ] Update line 440: `os.walk(self.project_root)` for Path
- [ ] Update line 541: `os.path.join(self.project_root, file_path)` for Path
- [ ] Add test: `../../etc/passwd` path is rejected
- [ ] Add test: normal path `tester/vf_keyboard.py` is accepted
- [ ] Add test: absolute path `/etc/cron.d/malware` is rejected
- [ ] Add test: symlink escape is detected by resolve()
- [ ] Verify all AutoUpdater methods work with Path-based project_root

### FR-P2-005: Auto pip install Verification
- [ ] Verify run.py does not call subprocess with pip
- [ ] Create requirements.txt with pinned versions (aiohttp, httpx, beautifulsoup4)
- [ ] Update run.py error message to suggest `pip install -r requirements.txt`
- [ ] Add test: missing package → exit code 1 (no auto-install)
- [ ] Consider adding hash-checking support in requirements.txt

### FR-P2-006: TimeoutError Builtin Shadowing
- [ ] Verify exceptions.py has `OperationTimeoutError` (not `TimeoutError`)
- [ ] Grep for `from exceptions import TimeoutError` → zero matches
- [ ] Grep for `from exceptions import OperationTimeoutError` → verify all valid
- [ ] Verify `asyncio.TimeoutError` is used correctly (not `exceptions.TimeoutError`)
- [ ] Add CI check: reject custom `TimeoutError` class in exceptions.py

### FR-P2-007: Keyboard Handler Robustness
- [ ] Fix Unix path: change `sys.stdin.readline()` to `sys.stdin.read(1)`
- [ ] Add TTY detection: `if not sys.stdin.isatty(): return None`
- [ ] Add test: non-TTY stdin → get_command() returns None
- [ ] Add test: keypress '+' → returns '+'
- [ ] Add test: keypress 'q' → returns 'q'
- [ ] Add test: no keypress → returns None within 1ms
- [ ] Verify Windows path (msvcrt) still works

### FR-P2-008: Blocking Socket Verification
- [ ] Verify vf_fp_cloner.py uses asyncio.open_connection() (not socket.create_connection)
- [ ] Verify _raw_tls_probe() extracts TLS version, cipher, ALPN correctly
- [ ] Verify timeout handling uses EVASION_FPC_TIMEOUT constant
- [ ] Add test: _raw_tls_probe() completes within timeout
- [ ] Add test: _raw_tls_probe() returns default on connection failure
- [ ] Verify event loop is not blocked during probe

### FR-P2-009: Shared Mutable State Fix
- [ ] Refactor _content_pipeline() to return results instead of mutating self.profile
- [ ] Refactor _ssl_pipeline() to return results instead of mutating self.profile
- [ ] Refactor _dns_pipeline() to return results instead of mutating self.profile
- [ ] Refactor _perf_pipeline() to return results instead of mutating self.profile
- [ ] Add sequential application step after asyncio.gather()
- [ ] Handle partial pipeline failures (apply successful results, log failed ones)
- [ ] Ensure _enhancer methods (WAF, JS, subdomain, dir_fuzz, rate, cache) are handled
- [ ] Write test: concurrent pipelines produce same results as sequential
- [ ] Write test: partial failure (SSL fails) still applies content + DNS results
- [ ] Verify VFFinder.scan() public API unchanged
- [ ] Profile performance: ensure < 5% scan time increase

### FR-P2-010: HAS_AIOHTTP Guard Verification
- [ ] Verify vf_session_harvest.py:192-194 checks HAS_AIOHTTP
- [ ] Verify vf_fp_cloner.py:207-209 checks HAS_AIOHTTP
- [ ] Add CI grep check: every `HAS_AIOHTTP = True/False` must have `if not HAS_AIOHTTP` guard
- [ ] Write test: harvest() returns safe default when aiohttp unavailable
- [ ] Write test: probe_target() returns default dict when aiohttp unavailable

### FR-P2-012: Sensitive Path Enforcement
- [ ] Verify /.env and /.git/config removed from COMMON_DYNAMIC_PATHS
- [ ] Remove /.env from vf_origin_discovery.py:595 leak_paths list
- [ ] Add BLOCKED_PATHS filtering in vf_page_flood _discover_endpoints()
- [ ] Write test: BLOCKED_PATHS entries are never probed
- [ ] Write test: discovered URLs matching blocked paths are excluded

### FR-P2-013: logging_config Handler Fix
- [ ] Modify setup_logger() to only add handlers to root "storm_vx" logger
- [ ] Ensure child loggers created via get_logger() have no direct handlers
- [ ] Set propagate=True for child loggers (default, but verify)
- [ ] Write test: setup_logger("child") does not add duplicate handlers
- [ ] Write test: log message appears exactly once in console output
- [ ] Verify structured logging path (W5.1) still works correctly

### FR-P2-014: ValidationError Import Cleanup
- [ ] Update tester/VF_TESTER.py:193 — import ValidationError from exceptions
- [ ] Update infra/vf_telegram.py:389 — import ValidationError from exceptions
- [ ] Update VF_FINDER.py:282 — import ValidationError from exceptions
- [ ] Add __all__ to vf_validator.py to document the re-export
- [ ] Grep verify: zero `from vf_validator import.*ValidationError` remain
- [ ] Write test: ValidationError is isinstance of ValueError
- [ ] Write test: importing from exceptions works correctly

---

## Dependency Graph

```
Group A (Security):
  FR-P2-001 ──→ Independent (verification + CI)
  FR-P2-002 ──→ Independent (verification + test)
  FR-P2-003 ──→ Independent (verification + test)
  FR-P2-004 ──→ Independent (CODE CHANGE REQUIRED — broken fix)
  FR-P2-005 ──→ Independent (verification + requirements.txt)
  FR-P2-006 ──→ Independent (verification)

Group B (Reliability):
  FR-P2-007 ──→ Independent (minor code fix)
  FR-P2-008 ──→ Independent (verification)
  FR-P2-009 ──→ Independent (MAJOR CODE CHANGE — shared state)
  FR-P2-010 ──→ FR-P2-001 (shares CI enforcement mechanism)

Group C (Code Quality):
  FR-P2-012 ──→ Independent (minor code change)
  FR-P2-013 ──→ Independent (minor code change)
  FR-P2-014 ──→ Independent (3 import updates)
```

**Parallelization**: 11 of 14 fixes can be done in parallel. FR-P2-010 depends on FR-P2-001 for shared CI mechanism. FR-P2-004 and FR-P2-009 are the only fixes requiring significant code changes.

---

## Summary Table

| ID | Bug | Severity | Current State | Work Needed | Files | Law Compliance |
|----|-----|----------|---------------|-------------|-------|----------------|
| FR-P2-001 | BUG-001 aiohttp guard | CRITICAL | ✅ Fixed | Verify + CI | vf_graphql_introspection.py | L5✓ L9✓ L10✓ |
| FR-P2-002 | BUG-002 verify_ssl | CRITICAL | ✅ Fixed | Verify + Test + Help text | config/settings.py, run.py | L5✓ L9✓ L10✓ |
| FR-P2-003 | BUG-003 Cloudflare IPs | CRITICAL | ✅ Fixed | Verify + Consistency test | vf_origin_discovery.py | L5✓ L9✓ L10✓ |
| FR-P2-004 | BUG-006 Path traversal | CRITICAL | ⚠️ Broken | **Fix broken pathlib code** | vf_updater.py | L5✓ L9✓ L10✓ |
| FR-P2-005 | BUG-007 Auto pip install | CRITICAL | ✅ Fixed | Verify + requirements.txt | run.py | L5✓ L9✓ L10✓ |
| FR-P2-006 | BUG-008 TimeoutError | CRITICAL | ✅ Fixed | Verify stale refs | exceptions.py + refs | L5✓ L9✓ L10✓ |
| FR-P2-007 | BUG-009 Keyboard handler | HIGH | ✅ Fixed | Fix readline→read(1) + TTY | vf_keyboard.py | L5✓ L9✓ L10✓ |
| FR-P2-008 | BUG-010 Blocking socket | HIGH | ✅ Fixed | Verification testing | vf_fp_cloner.py | L5✓ L9✓ L10✓ |
| FR-P2-009 | BUG-011 Shared state | HIGH | ❌ Not Fixed | **Full refactoring** | finder/engine.py | L5✓ L9✓ L10✓ |
| FR-P2-010 | BUG-012 HAS_AIOHTTP | HIGH | ✅ Fixed | Verify + CI | vf_session_harvest.py, vf_fp_cloner.py | L5✓ L9✓ L10✓ |
| FR-P2-012 | B3 Sensitive paths | MEDIUM | ⚠️ Partial | Remove /.env from discovery | vf_origin_discovery.py, vf_page_flood.py | L5✓ L9✓ L10✓ |
| FR-P2-013 | B4 Handler accumulation | MEDIUM | ⚠️ Partial | Fix child logger handling | logging_config.py | L5✓ L9✓ L10✓ |
| FR-P2-014 | B16 ValidationError | MEDIUM | ⚠️ Partial | Update 3 stale imports | VF_TESTER.py, vf_telegram.py, VF_FINDER.py | L5✓ L9✓ L10✓ L15✓ |

---

## Risk Matrix

| Fix | Code Change? | Risk Level | Key Risk |
|-----|-------------|------------|----------|
| FR-P2-004 | YES (significant) | **HIGH** | Converting project_root to Path touches 8+ call sites |
| FR-P2-009 | YES (significant) | **HIGH** | Refactoring 4 pipelines to return values instead of mutating |
| FR-P2-007 | YES (minor) | LOW | readline→read(1) is one-line fix |
| FR-P2-013 | YES (minor) | LOW | setup_logger logic change |
| FR-P2-014 | YES (minor) | LOW | 3 import statement updates |
| FR-P2-012 | YES (minor) | LOW | Remove 1 path from list, add filter |
| All others | NO | LOW | Verification + CI enforcement only |

---

## Out of Scope

- Adding IPv6 Cloudflare ranges (future enhancement)
- Adding curl_cffi for real JA3 fingerprinting (BUG-026, future phase)
- Refactoring VFFinder to be under 500 lines (BUG-015, future phase)
- Adding mTLS to the health server (future enhancement)
- Comprehensive test suite for all evasion modules (future phase)
- Refactoring AutoUpdater to use pathlib throughout (partially in scope via FR-P2-004)

---

## Open Questions

- [ ] Should FR-P2-004 convert ALL `os.path.join(self.project_root, ...)` calls to use Path's `/` operator, or keep os.path.join with `str(self.project_root)`?
- [ ] Should FR-P2-009 use an `asyncio.Lock()` approach (simpler but adds contention) or the return-values approach (more refactoring but cleaner)?
- [ ] Should the requirements.txt in FR-P2-005 include hash verification (`--require-hashes`)?
- [ ] Should FR-P2-003 include an automated Cloudflare IP range update mechanism, or just a manual update procedure documented in comments?
