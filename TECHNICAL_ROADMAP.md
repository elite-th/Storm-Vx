# Storm-Vx Technical Roadmap — Bug Fixes & Code Quality Improvements

## Executive Summary
This roadmap addresses **9 critical/medium weaknesses** identified in the Storm-Vx codebase (~25,000 lines across 70+ Python files). Fixes are prioritized by impact and organized into phases.

---

## 🔴 Phase 1: Critical Fixes (Must Fix)

### 1.1 Type System — Replace `Dict[str, Any]` with `SiteProfile`
**Impact**: HIGH — Eliminates ~70 untyped dict accesses, enables IDE autocomplete + mypy  
**Files**: `plugin_system.py`, `tester/vf_profile_loader.py`, `tester/vf_plugin_orchestrator.py`, `tester/vf_dashboard.py`, `finder/engine.py`  
**Plan**:
- Change `AttackContext.profile: Dict[str, Any]` → `AttackContext.profile: SiteProfile`
- Update `ProfileLoader` to return `SiteProfile` objects instead of raw dicts
- Add `to_dict()` / `from_dict()` methods for JSON serialization
- Update all `.get()` calls to proper attribute access
- Run mypy --strict to verify

### 1.2 Replace `print()` with `logging`
**Impact**: HIGH — ~800+ print() calls across 37 files  
**Files**: ALL files with print() calls  
**Plan**:
- Each module already has `from logging_config import get_logger; logger = get_logger(__name__)`
- Replace `print(f"  {C.G}[TAG] message{C.RS}")` → `logger.info("message", extra={"tag": "TAG"})`
- Keep ANSI color support via the existing `AnsiColorFormatter`
- For dashboard/UI: create `UILogger` that wraps print() but with proper log levels
- Keep `live_log`, `live_ok`, `live_warn` as logger-based wrappers

### 1.3 Break Up Long Methods
**Impact**: MEDIUM — Methods >50 lines are hard to test/debug  
**Files**: `tester/VF_TESTER.py`, `finder/engine.py`  
**Plan**:
- `_run_dashboard_loop()` (~200 lines) → extract:
  - `_check_keyboard_commands()` 
  - `_check_waf_runtime_detection()`
  - `_auto_disable_failing_plugins()`
  - `_auto_recover_disabled_plugins()`
  - `_compute_dynamic_step()`
  - `_auto_shrink_workers()`
  - `_escalation_phase()`
- `_generate_attack_profile()` (~120 lines) → already partially refactored, extract:
  - `_print_strategy_display()`
  - `_print_surgical_targets()`

### 1.4 Replace `ensure_paths()` with Proper Package Installation
**Impact**: HIGH — ~60 files use this hack  
**Files**: ALL files with `ensure_paths(__file__)`, `pyproject.toml`  
**Plan**:
- Create proper `pyproject.toml` with package configuration
- Add `__init__.py` to all subpackages (already done)
- Use relative imports: `from .vf_common import C` instead of `from vf_common import C`
- Remove all `ensure_paths(__file__)` calls
- Remove `_bootstrap.py` entirely
- Install with `pip install -e .` for development

---

## 🟡 Phase 2: Medium Fixes (Should Fix)

### 2.1 SSL Verification — Default to `True`
**Impact**: MEDIUM — Security risk even in testing  
**Files**: `config/defaults.py`, all modules with `ssl=False`  
**Plan**:
- Change `VERIFY_SSL: bool = False` → `VERIFY_SSL: bool = True` in defaults
- Add `--no-verify-ssl` CLI flag for testing (explicit opt-out)
- Replace all `ssl=False` with `ssl_param(verify_ssl)` from `vf_common`
- Log a warning when SSL verification is disabled

### 2.2 Pydantic Models for Profile Validation
**Impact**: MEDIUM — Runtime validation + JSON schema generation  
**Files**: `finder/site_profile.py`, `plugin_system.py`  
**Plan**:
- Convert `SiteProfile` to Pydantic `BaseModel`
- Add validators for URL, IP addresses, worker counts
- Keep `to_dict()` compatibility via `model_dump()`
- Add `model_json_schema()` for documentation
- Keep dataclass `AttackExtras` but add Pydantic `ConfigDict`

### 2.3 Replace `Optional[X]` with `X | None` (Python 3.10+)
**Impact**: LOW-MEDIUM — Modern Python convention  
**Files**: ~28 files with ~65 occurrences  
**Plan**:
- Global search-replace: `Optional[X]` → `X | None`
- Remove `from typing import Optional` imports
- Keep `from __future__ import annotations` for forward references
- Run mypy to verify

### 2.4 Add `.gitignore` and Remove `__pycache__`
**Impact**: LOW — Repository hygiene  
**Plan**:
- Create `.gitignore` with: `__pycache__/`, `*.pyc`, `.env`, `*.egg-info/`, `dist/`, `build/`
- Remove all `__pycache__` directories: `find . -type d -name __pycache__ -exec rm -rf {} +`
- Add to pre-commit hook

### 2.5 Narrow Broad Exception Handlers
**Impact**: MEDIUM — Prevents hiding real bugs  
**Files**: `finder/engine.py`, `_bootstrap.py`, multiple others  
**Plan**:
- Replace `(OSError, ValueError, RuntimeError, AttributeError, ImportError)` with specific exceptions
- For I/O: catch `(OSError, IOError)` only
- For parsing: catch `(ValueError, KeyError)` only
- Add `logger.debug()` for unexpected exceptions with `exc_info=True`
- Never catch `RuntimeError` or `AttributeError` broadly — these indicate bugs

---

## 📊 Estimated Effort

| Phase | Task | Files Changed | Estimated Lines |
|-------|------|---------------|-----------------|
| 1.1 | Type System | 5 | ~300 |
| 1.2 | print→logging | 37 | ~800 |
| 1.3 | Long Methods | 2 | ~200 (restructure) |
| 1.4 | ensure_paths removal | 60+ | ~120 (removals) |
| 2.1 | SSL default | 10 | ~30 |
| 2.2 | Pydantic | 2 | ~150 |
| 2.3 | Optional→X\|None | 28 | ~65 |
| 2.4 | .gitignore | 1 | ~20 |
| 2.5 | Narrow exceptions | 15 | ~50 |

**Total**: ~1,735 lines changed across 70+ files

---

## ⚠️ Risk Mitigation
- All changes are backwards-compatible (no API breaking)
- Each phase can be merged independently
- Type system changes validated with `mypy --strict`
- Logging changes preserve ANSI color output
- SSL change has opt-out flag
