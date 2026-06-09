# Storm-Vx Technical Roadmap v3 — Fresh Deep Review

## Review Methodology
Complete source code audit of all core files:
- `tester/VF_TESTER.py` — Main orchestrator (~1200 lines)
- `tester/vf_attack_base.py` — AttackPlugin base class (~960 lines)
- `tester/vf_data.py` — Stats/HitResult dataclasses
- `vf_common.py` — Colors, themes, helpers
- `vf_validator.py` — Input validation
- `vf_network.py` — Network utilities
- `plugin_system.py` — Plugin registry
- `VF_FINDER.py` — Recon engine
- `config/defaults.py`, `config/settings.py` — Configuration
- `exceptions.py` — Custom exceptions
- `logging_config.py` — Logging
- `_bootstrap.py` — Path setup
- `tester/vf_slowloris.py`, `tester/vf_conn_exhaust.py`, `tester/vf_page_flood.py` — Plugins
- `evasion/vf_behavior.py` — Behavioral mimicry

---

## Defect Inventory — Fresh Review Findings

### CRITICAL (P0) — Bugs that cause incorrect behavior or crashes

| # | Defect | File | Line(s) | Impact |
|---|--------|------|---------|--------|
| B1 | `AttackPlugin._record()` method is called in slowloris/conn_exhaust but NOT DEFINED in AttackPlugin class | vf_attack_base.py, vf_slowloris.py:155, vf_conn_exhaust.py:124 | N/A | **RuntimeError**: `AttributeError: 'SlowlorisPlugin' object has no attribute '_record'` — slowloris and conn_exhaust plugins crash immediately |
| B2 | `sanitize_path()` removes `../` via string replacement but doesn't handle `..%2f` or `%2e%2e/` — the `unquote` happens BEFORE the traversal removal, but double-encoded strings like `%252e%252e%252f` decode to `%2e%2e%2f` after one pass, then `..../` after second pass — but the while loop re-runs unquote, so it DOES catch this. However, `..;/` (Tomcat semicolon bypass) is NOT handled | vf_validator.py:189 | MEDIUM | Path traversal bypass via semicolon technique |
| B3 | `page_flood` probes `/.env` and `/.git/config` paths — these are sensitive files that should never be probed even during authorized testing (data exfiltration risk) | vf_page_flood.py:56 | HIGH | Probing sensitive paths violates security testing ethics |
| B4 | `logging_config.py` `setup_logger()` adds a new handler EVERY TIME it's called — since `get_logger()` calls `logging.getLogger(name)` which returns the same logger, but `setup_logger()` creates a new handler each time, the module-level `logger = setup_logger()` call adds a handler, and if any other module calls `setup_logger()` again, duplicate handlers accumulate | logging_config.py:56-76 | MEDIUM | Log messages appear multiple times in console |
| B5 | `AdaptiveTimeout` uses mutable default `_ema: float = 0.0` and `_sample_count: int = 0` as dataclass field defaults — this is fine for `@dataclass` but the class is used via `@dataclass` decorator implicitly? No, it's explicitly a dataclass. Wait, actually `AdaptiveTimeout` is NOT decorated with `@dataclass` — it uses class-level attributes that are shared across ALL instances. `_ema` and `_sample_count` are class variables, not instance variables | vf_network.py:43-44 | CRITICAL | All `AdaptiveTimeout` instances share the same `_ema` and `_sample_count` — if VFTester creates one AND any plugin creates another, they share state |
| B6 | `ConnectionPoolStats` is NOT thread-safe — `record_connection()`, `record_timeout()`, etc. use `self.total_connections += 1` which is NOT atomic in asyncio context. While asyncio is single-threaded, if stats are read while being updated, you could get inconsistent reads | vf_network.py:134-140 | LOW | Inconsistent stat reads (cosmetic, not data-corrupting) |
| B7 | `_cache_lock` in `VF_FINDER.py` is created at module level as `asyncio.Lock()` — but this is created BEFORE any event loop exists. In Python 3.10+, `asyncio.Lock()` outside a running loop emits a DeprecationWarning and will fail in 3.12+ | VF_FINDER.py:91 | HIGH | Cache operations crash on Python 3.12+ |
| B8 | `BehavioralMimic._response_history` grows up to 1000 entries then truncates to 500 — the truncation creates a gap where 500 entries are lost, making recent history inaccurate | evasion/vf_behavior.py:543 | LOW | Minor inaccuracy in response history |
| B9 | `AttackPlugin.run()` initializes `_target_selector` with ONLY `page_targets` — `resource_targets` are never added to the selector, so resource-based plugins using `_select_target()` never hit resource URLs | vf_attack_base.py:669-670 | MEDIUM | Resource flood plugins can't discover resource URLs |
| B10 | `VFTester.__init__()` calls `self._base_headers` before `self._evasion` is defined — line 241 passes `self._base_headers` (a method reference) to `_ViewStateManagerStub`, but the method won't work until `_evasion` is initialized on line 292 | VF_TESTER.py:241 | MEDIUM | ViewStateManagerStub may get a broken header function if called before evasion init |
| B11 | `Stats.record()` is NOT thread-safe despite the class docstring saying "single-event-loop use only" — but `AttackPlugin._lock` exists (line 638) yet is NEVER used to protect Stats operations. Multiple workers write to Stats simultaneously via `_record_hit` callback | vf_data.py:72-117, VF_TESTER.py:589-600 | MEDIUM | Race condition: concurrent writes to `self.total`, `self.ok`, etc. may lose counts |
| B12 | `TargetSelector.__init__` iterates `urls` list 4 times to build `_weights`, `_hit_counts`, `_ok_counts`, `_fail_counts` — but if the input list contains duplicates, the same URL will appear multiple times in `_original_urls` but only once in the dicts (last-write-wins for weight=1.0, counts reset to 0) | vf_attack_base.py:314-318 | LOW | Minor: duplicate URLs waste memory in `_original_urls` |
| B13 | `_handle_classified_response` is called in `_process_response` (line 794) but its definition was cut off in the file read — need to verify it doesn't have bugs | vf_attack_base.py (past line 960) | UNKNOWN | Need to verify |
| B14 | `SlowlorisPlugin._worker_loop` line 155: `await self._record("TCP-RAW", True, 0, 0, hint="slowloris")` — but `_record` method doesn't exist on `AttackPlugin`. Should use `context.stats_callback` via `AttackContext.record()` | vf_slowloris.py:155 | CRITICAL | Plugin crashes on first successful connection |
| B15 | `ConnExhaustPlugin._worker_loop` line 124: `await self._record("CONN-HOLD", True, 0, 0, hint="hold")` — same bug as B14 | vf_conn_exhaust.py:124 | CRITICAL | Plugin crashes on first successful connection |
| B16 | `exceptions.py` only has `ConfigurationError` — `ValidationError` is defined in `vf_validator.py` instead of the central exceptions module, making the exception hierarchy incomplete and inconsistent | exceptions.py, vf_validator.py:40 | LOW | Inconsistent exception location |
| B17 | `AdaptivePacer._recent_classes` is pruned by list comprehension on every `record_response()` call — O(n) per call where n can be up to 1000. Should use `collections.deque` with maxlen for O(1) | vf_attack_base.py:541-545 | MEDIUM | Performance: O(n) prune on every response |
| B18 | `page_flood` hardcodes `ssl=False` on lines 104, 132, 186, 199, 207 — should use `context.extra.get('verify_ssl', False)` to determine SSL setting | vf_page_flood.py:104,132,186,199,207 | MEDIUM | SSL verification flag ignored by page_flood |

---

## Phase Plan

### Phase 1: Critical Bug Fixes (P0)

**Goal**: Fix bugs that cause crashes or incorrect behavior.

| Task | Bug ID | Fix Description | File(s) |
|------|--------|-----------------|---------|
| 1.1 | B1/B14/B15 | Add `_record()` helper method to `AttackPlugin` that routes through `context.stats_callback` and `context.live_log_callback` | vf_attack_base.py |
| 1.2 | B5 | Fix `AdaptiveTimeout` to use instance variables in `__init__` instead of class-level mutable defaults | vf_network.py |
| 1.3 | B7 | Fix `_cache_lock` creation — move inside `async` function or use lazy initialization | VF_FINDER.py |
| 1.4 | B9 | Add `resource_targets` to `TargetSelector` in `AttackPlugin.run()` | vf_attack_base.py |
| 1.5 | B10 | Move `_ViewStateManagerStub` creation after `_evasion` initialization | VF_TESTER.py |
| 1.6 | B11 | Add note/lock protection to `Stats.record()` — since it's single-event-loop, add explicit docstring warning and consider using `_lock` from AttackPlugin or a simple atomic counter pattern | vf_data.py |
| 1.7 | B17 | Replace `AdaptivePacer._recent_classes` list with `collections.deque(maxlen=1000)` | vf_attack_base.py |
| 1.8 | B18 | Fix `page_flood` to respect `verify_ssl` from context.extra | vf_page_flood.py |

### Phase 2: Security & Ethics Fixes (P1)

**Goal**: Fix security issues and ethical problems.

| Task | Bug ID | Fix Description | File(s) |
|------|--------|-----------------|---------|
| 2.1 | B3 | Remove `/.env` and `/.git/config` from `COMMON_DYNAMIC_PATHS` in `page_flood` — these are sensitive paths that should never be probed | vf_page_flood.py |
| 2.2 | B2 | Add semicolon-based path traversal handling to `sanitize_path()` — strip `..;/` patterns | vf_validator.py |
| 2.3 | B4 | Fix `setup_logger()` to check for existing handlers before adding new ones | logging_config.py |
| 2.4 | B16 | Move `ValidationError` from `vf_validator.py` to `exceptions.py` and import it back | exceptions.py, vf_validator.py |

### Phase 3: Reliability & Code Quality (P2)

**Goal**: Improve reliability without changing architecture.

| Task | Bug ID | Fix Description | File(s) |
|------|--------|-----------------|---------|
| 3.1 | B8 | Fix `_response_history` truncation to keep last 1000 consistently (use deque or proper slice) | vf_behavior.py |
| 3.2 | B12 | Deduplicate URLs in `TargetSelector.__init__` | vf_attack_base.py |
| 3.3 | B6 | Add note about single-event-loop usage to `ConnectionPoolStats` | vf_network.py |
| 3.4 | — | Verify `_handle_classified_response` implementation | vf_attack_base.py |

### Phase 4: Deep Post-Implementation Review

**Goal**: Re-review all changes and find any remaining bugs.

- Run syntax check on all modified files
- Verify all method signatures match their call sites
- Check for any new bugs introduced by fixes

---

## Total Timeline Estimate

- Phase 1: 3 hours (8 critical fixes)
- Phase 2: 1.5 hours (4 security/ethics fixes)
- Phase 3: 1 hour (3 reliability fixes)
- Phase 4: 2 hours (deep review)
- **Total: ~7.5 hours**
