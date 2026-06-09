# Storm-Vx Technical Roadmap v4

**Project**: Storm-Vx — Adaptive Reconnaissance and Load Testing Engine
**Date**: 2025-03-05
**Scope**: Full codebase audit — 48 bugs across 14+ files
**Priority Order**: CRITICAL (8) → HIGH (6) → MEDIUM (23) → LOW (11)

---

## Table of Contents

- [CRITICAL — Must Fix Before Next Release](#critical--must-fix-before-next-release)
- [HIGH — Fix Within One Sprint](#high--fix-within-one-sprint)
- [MEDIUM — Fix Within Two Sprints](#medium--fix-within-two-sprints)
- [LOW — Backlog / Tech Debt](#low--backlog--tech-debt)
- [Summary Statistics](#summary-statistics)

---

## CRITICAL — Must Fix Before Next Release

### BUG-001: aiohttp NameError in vf_graphql_introspection.py — except uses aiohttp.ClientError when aiohttp may be None
- **Severity**: CRITICAL
- **Category**: Code Quality
- **File**: `tester/vf_graphql_introspection.py:27,157,167`
- **Description**: The module imports `aiohttp` unconditionally at line 27 (`import aiohttp`), then references `aiohttp.ClientError` in `except` clauses at lines 157 and 167. If aiohttp is not installed, the import at line 27 will raise `ImportError` immediately, causing the entire module to fail to load. There is no `try/except ImportError` guard around the import, unlike other modules (e.g., `vf_api_flood.py:42-45`, `vf_fp_cloner.py:37-41`).
- **Root Cause**: The import was written without the defensive `try/except ImportError` pattern used elsewhere in the codebase. The plugin system will fail to discover this module entirely when aiohttp is missing, rather than gracefully skipping it.
- **Fix**: Wrap the import in a `try/except ImportError` block and set a `HAS_AIOHTTP` flag, then guard the `except` clauses:
  ```python
  try:
      import aiohttp
      HAS_AIOHTTP = True
  except ImportError:
      aiohttp = None
      HAS_AIOHTTP = False
  ```
  Then at lines 157 and 167, replace `aiohttp.ClientError` with a conditional:
  ```python
  except (aiohttp.ClientError, asyncio.TimeoutError, OSError) if HAS_AIOHTTP else (asyncio.TimeoutError, OSError) as exc:
  ```
  Or better, add an early guard at the top of `_worker_loop`:
  ```python
  if not HAS_AIOHTTP:
      raise ImportError("aiohttp is required for graphql_introspection")
  ```
- **Prevention**: Add a lint rule / CI check that all modules importing `aiohttp` outside `TYPE_CHECKING` must use the `try/except ImportError` pattern. The plugin system already checks `requirements=['aiohttp']` in `PluginMeta`, but the import guard is still needed for runtime safety.

---

### BUG-002: verify_ssl — 3 contradictory defaults across settings.py, defaults.py, and plugin_system.py
- **Severity**: CRITICAL
- **Category**: Security
- **File**: `config/settings.py:33`, `config/defaults.py:31`, `plugin_system.py:230`
- **Description**: The `verify_ssl` default is set to **three different values** across the codebase:
  1. `config/settings.py:33` — `verify_ssl: bool = False`
  2. `config/defaults.py:31` — `VERIFY_SSL: bool = True` (comment: "Default True for security")
  3. `plugin_system.py:230` — `verify_ssl: bool = True` (comment: "SEC-07: Default to True")

  The `ConnectionSettings` dataclass at `settings.py:33` hardcodes `verify_ssl: bool = False`, completely ignoring the `VERIFY_SSL` constant from `defaults.py:31`. This means production deployments default to **no SSL verification**, which is a security vulnerability (susceptible to MITM attacks).
- **Root Cause**: The `ConnectionSettings` dataclass was written with `False` for convenience during testing, but `defaults.py` and `plugin_system.py` were later updated to `True` for security. The dataclass was never updated to reference the constant.
- **Fix**: Change `settings.py:33` to use the defaults constant:
  ```python
  # Before:
  verify_ssl: bool = False
  # After:
  verify_ssl: bool = VERIFY_SSL  # Uses defaults.VERIFY_SSL = True
  ```
  Also add `VERIFY_SSL` to the imports from `config.defaults` at line 11-21.
- **Prevention**: Add a unit test that asserts `ConnectionSettings().verify_ssl == defaults.VERIFY_SSL`. Add a CI check that no boolean literal `False` is used for `verify_ssl` in any settings/defaults dataclass.

---

### BUG-003: Cloudflare IP ranges incorrect in dns_scanner.py — hex ranges do not match official CIDR blocks
- **Severity**: CRITICAL
- **Category**: Network
- **File**: `finder/dns_scanner.py:191-203`
- **Description**: The `cloudflare_ranges` list at lines 191-203 contains incorrect hex-to-IP mappings. Several entries are marked "(approximate)" and are factually wrong, causing legitimate origin IPs to be misclassified as Cloudflare CDN IPs (or vice versa). Examples:
  - Line 192: `(0x67153000, 0x67153FFF)` claims `103.21.244.0/22`. The actual range is `0x6715F400` to `0x6715F7FF` (103.21.244.0-103.21.247.255). The hex values are completely wrong.
  - Line 193: `(0xADF53000, 0xADF53FFF)` claims `173.245.48.0/20`. Actual: `0xADF53000`-`0xADF53FFF` covers only 173.245.48.0-173.245.63.255 which happens to be correct, but the end should be `0xADF53FFF` for /20 = `0xADF53FFF` — actually this one is right.
  - Line 194: `(0xC0A60000, 0xC0A60FFF)` claims `192.166.0.0/17`. `0xC0A60000` = 192.166.0.0 but `/17` end should be `0xC0A67FFF`, not `0xC0A60FFF`. The range is far too narrow.
  - Line 196: `(0x68100000, 0x68100FFF)` claims `104.16.0.0/12`. `0x68100000` = 104.16.0.0, but `/12` end should be `0x681FFFFF`, not `0x68100FFF`. The range covers only 4096 IPs instead of ~1 million.
  - Line 197: `(0x6C900000, 0x6C900FFF)` claims `108.144.0.0/12`. This is not a Cloudflare range at all. Cloudflare's actual range is `108.162.192.0/18`.
  - Lines 198-202: Multiple other ranges are incorrect or not actual Cloudflare ranges.
- **Root Cause**: The hex values were computed incorrectly — likely using `/24` or `/16` subnet masks instead of the actual CIDR prefix lengths, and some entries were for non-Cloudflare IP ranges entirely.
- **Fix**: Replace the entire `cloudflare_ranges` list with the correct hex ranges computed from the official Cloudflare IP list (https://www.cloudflare.com/ips-v4/):
  ```python
  cloudflare_ranges = [
      (0x6715F400, 0x6715F7FF),  # 103.21.244.0/22
      (0xADF53000, 0xADF53FFF),  # 173.245.48.0/20
      (0xC0A68000, 0xC0A6BFFF),  # 192.168.128.0/20 — actually 192.168.0.0/13 range is not CF
      # ... replace ALL with correct values from official source
  ]
  ```
  Better yet, use the `ipaddress` stdlib module for proper CIDR matching instead of manual hex arithmetic:
  ```python
  import ipaddress
  CLOUDFLARE_NETWORKS = [ipaddress.ip_network(cidr) for cidr in [
      "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
      "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
      "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
      "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
      "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  ]]
  def _is_cdn_ip(ip: str) -> bool:
      try:
          addr = ipaddress.ip_address(ip)
          return any(addr in net for net in CLOUDFLARE_NETWORKS)
      except ValueError:
          return False
  ```
- **Prevention**: Add a unit test that verifies each hex range maps to the expected CIDR block. Use `ipaddress.ip_network` for all future IP range comparisons instead of manual hex arithmetic.

---

### BUG-004: vf_api_flood.py stats_callback sends dict, VF_TESTER expects positional args
- **Severity**: CRITICAL
- **Category**: Architecture
- **File**: `tester/vf_api_flood.py:522-529,551-558,567-572,581-586`
- **Description**: The `APIFloodAttacker` calls `self.stats_callback` with a dict argument (`await self.stats_callback({...})`), but the `VF_TESTER._record_hit` method (which is the actual callback) expects positional arguments `(mode, ok, code, rt, err, url, hint)`. The `LegacyPluginAdapter._stats_cb` in `plugin_system.py:572-592` correctly unpacks a dict, but when `APIFloodAttacker` is used directly (not through the plugin system), the callback signature mismatch causes a `TypeError` at runtime.

  At line 522: `await self.stats_callback({"ok": ..., "code": ..., ...})` — this is `await`-ed but `_record_hit` is not async, and it expects `(mode, ok, code, rt, err, url, hint)` not a dict.
- **Root Cause**: `APIFloodAttacker` was written as a standalone module with its own callback convention (dict), but when integrated with VF_TESTER, the callback is `_record_hit` which has a different signature. The `LegacyPluginAdapter` bridges this gap, but direct usage bypasses the adapter.
- **Fix**: Two options:
  1. Change `vf_api_flood.py` to call the callback with positional args matching `_record_hit`:
     ```python
     if self.stats_callback:
         self.stats_callback("api_flood", resp.status < 500, resp.status, elapsed,
                            "", target_url[:60], f"API {method}")
     ```
  2. Or make `stats_callback` always accept a dict and update `_record_hit` to handle both. Option 1 is simpler and consistent.
  Also remove the `await` since `_record_hit` is synchronous.
- **Prevention**: Define a `StatsCallback = Callable[[str, bool, int, float, str, str, str], None]` type alias and enforce it across all modules. Add a type-checking CI step.

---

### BUG-005: sys.path.insert(0,...) in plugin_system.py causes module shadowing
- **Severity**: CRITICAL
- **Category**: Architecture
- **File**: `plugin_system.py:315`
- **Description**: At line 315, `sys.path.insert(0, search_dir)` prepends the plugin search directory to `sys.path`. This means any module in the search directory (e.g., `tester/`) will shadow stdlib or installed packages of the same name. For example, if a file named `json.py` or `ssl.py` exists in the tester directory, it will shadow the stdlib `json`/`ssl` modules for the entire process. This is particularly dangerous because the search directories include `tester/`, `evasion/`, `finder/` etc., which contain many `.py` files.
- **Root Cause**: `sys.path.insert(0, ...)` gives the search directory the **highest** priority, overriding even stdlib. The correct approach is `sys.path.append(search_dir)` or better yet, use `importlib.util.spec_from_file_location` (which the code already does as Strategy 1) and avoid modifying `sys.path` at all.
- **Fix**: Remove `sys.path.insert(0, search_dir)` entirely. The code already uses `importlib.util.spec_from_file_location` as Strategy 1 (lines 337-341), which doesn't require `sys.path` modification. The `sys.path.insert` was only needed for Strategy 2 (fallback bare import), but Strategy 2 should also use `spec_from_file_location`:
  ```python
  # Remove lines 314-315:
  # if search_dir not in sys.path:
  #     sys.path.insert(0, search_dir)
  ```
  If fallback is still needed, use `sys.path.append(search_dir)` instead of `insert(0, ...)` to avoid shadowing.
- **Prevention**: Add a lint rule forbidding `sys.path.insert(0, ...)`. Review all `sys.path` modifications in the codebase and replace with `importlib.util` or `sys.path.append`.

---

### BUG-006: Path traversal in vf_updater.py GitHub API tree path
- **Severity**: CRITICAL
- **Category**: Security
- **File**: `infra/vf_updater.py:504-522`
- **Description**: In the `_api_download` method, at line 511, the code takes `file_path = item["path"]` directly from the GitHub API response and uses it to construct a local filesystem path at line 522: `target = os.path.join(self.project_root, file_path)`. If a malicious GitHub repository (or a man-in-the-middle attack on the API response) contains a path like `../../.bashrc` or `../../../etc/cron.d/malware`, this would write files outside the project directory. The code at line 523 (`os.makedirs(os.path.dirname(target), exist_ok=True)`) would create any intermediate directories needed.
- **Root Cause**: The `item["path"]` from the GitHub API tree is trusted without validation. While the owner/repo names are validated (lines 93-95), the file paths within the tree response are not.
- **Fix**: Validate that the resolved path stays within `self.project_root`:
  ```python
  file_path = item["path"]
  target = os.path.join(self.project_root, file_path)
  # Path traversal check:
  real_target = os.path.realpath(target)
  real_root = os.path.realpath(self.project_root)
  if not real_target.startswith(real_root + os.sep) and real_target != real_root:
      logger.warning(f"[UPDATER] Skipping suspicious path: {file_path}")
      continue
  # Also skip absolute paths and paths with ..
  if os.path.isabs(file_path) or '..' in file_path.split(os.sep):
      logger.warning(f"[UPDATER] Skipping invalid path: {file_path}")
      continue
  ```
- **Prevention**: Add a `sanitize_download_path()` utility function and use it for all file downloads. Add a security test that verifies paths with `..` are rejected.

---

### BUG-007: Auto pip install in run.py — supply chain risk
- **Severity**: CRITICAL
- **Category**: Security
- **File**: `run.py:227-259`
- **Description**: The `check_and_install_deps()` function at line 251 automatically runs `pip install` for missing packages. This is a supply chain attack vector: if an attacker can manipulate the package index (e.g., DNS poisoning to redirect `pypi.org`), they could install malicious packages. The `--quiet` flag at line 252 suppresses output, making it harder to detect suspicious installations. This runs with whatever privileges the user has (often root/admin on Windows).
- **Root Cause**: Convenience-over-security design. Auto-installing packages was intended to reduce user friction but introduces a real attack vector, especially for a tool that may be run with elevated privileges.
- **Fix**: Replace auto-install with a clear warning and manual instructions:
  ```python
  if missing:
      print(f"  {C.R}[ERROR] Missing packages: {', '.join(missing)}{C.RS}")
      print(f"  {C.Y}[INFO] Install manually: pip install {' '.join(missing)}{C.RS}")
      print(f"  {C.Y}[INFO] Or use: pip install -r requirements.txt{C.RS}")
      sys.exit(1)
  ```
  If auto-install must be kept, add `--no-index --find-links` to use only a trusted local mirror, remove `--quiet`, and add hash verification.
- **Prevention**: Remove auto-install entirely in production builds. Add a `requirements.txt` with pinned versions and hashes. Document the manual install process.

---

### BUG-008: TimeoutError shadows builtins in exceptions.py
- **Severity**: CRITICAL
- **Category**: Code Quality
- **File**: `exceptions.py:33-41`
- **Description**: The custom `TimeoutError` class at line 33 shadows the built-in `TimeoutError` (which is a subclass of `OSError`). This means any code that does `from exceptions import TimeoutError` or `from exceptions import *` will replace the built-in `TimeoutError` with the custom one, which is not an `OSError` subclass. This breaks `except TimeoutError` clauses elsewhere that expect the builtin behavior. The docstring at line 36 acknowledges this but doesn't solve it.
- **Root Cause**: Naming conflict with Python's built-in `TimeoutError`. The custom class was named without checking for builtin conflicts.
- **Fix**: Rename the custom exception to avoid shadowing:
  ```python
  class OperationTimeoutError(Exception):
      """Raised when a network or operation timeout occurs.
      
      Distinct from the built-in TimeoutError (which is OSError-derived)
      to provide project-specific timeout semantics for attack operations
      and adaptive timeout tracking.
      """
      pass
  ```
  Update all imports and references across the codebase.
- **Prevention**: Add a CI check using a linter that warns about custom exception classes shadowing builtins. Use `pylint --disable=redefined-builtin` or similar.

---

## HIGH — Fix Within One Sprint

### BUG-009: Keyboard handler returns None always in vf_keyboard.py
- **Severity**: HIGH
- **Category**: Code Quality
- **File**: `tester/vf_keyboard.py:25-27`
- **Description**: The `get_command()` method at line 25 always returns `None`. The docstring says it returns `'+', '-', 'q', or None`, but the implementation is just `return None`. This means keyboard controls documented in `run.py:26-28` (and shown to the user at line 389) do not work. Users cannot adjust workers or quit gracefully via keyboard.
- **Root Cause**: The method is a stub that was never implemented. On Unix systems, non-blocking stdin reading requires `select` or `asyncio`; on Windows, it requires `msvcrt`.
- **Fix**: Implement platform-specific non-blocking input:
  ```python
  import sys
  import select

  def get_command(self) -> str | None:
      """Check for keyboard command. Returns '+', '-', 'q', or None."""
      if sys.platform == 'win32':
          import msvcrt
          if msvcrt.kbhit():
              ch = msvcrt.getch().decode('utf-8', errors='ignore')
              return self._map_key(ch)
      else:
          if select.select([sys.stdin], [], [], 0)[0]:
              ch = sys.stdin.read(1)
              return self._map_key(ch)
      return None

  @staticmethod
  def _map_key(ch: str) -> str | None:
      mapping = {'+': '+', '=': '+', '-': '-', 'q': 'q', 'Q': 'q'}
      return mapping.get(ch)
  ```
- **Prevention**: Add an integration test that verifies keyboard commands are processed. Mark stub methods with `# TODO:` or `raise NotImplementedError` so they're not silently broken.

---

### BUG-010: Blocking socket in vf_fp_cloner.py _raw_tls_probe()
- **Severity**: HIGH
- **Category**: Performance
- **File**: `evasion/vf_fp_cloner.py:289`
- **Description**: At line 289, `_raw_tls_probe` uses `socket.create_connection((hostname, port), timeout=10)` which is a **blocking** synchronous call inside an `async` method. This blocks the entire event loop for up to 10 seconds, preventing all other async tasks (including attack workers) from running. The method is called from `probe_target` (line 264) which is also async.
- **Root Cause**: The method was written using synchronous socket APIs instead of `asyncio.open_connection` for TLS probing. The sync API is simpler for raw socket operations but incompatible with asyncio.
- **Fix**: Replace with async connection:
  ```python
  async def _raw_tls_probe(self, hostname: str, port: int) -> Dict:
      ctx = ssl.create_default_context()
      ctx.check_hostname = False
      ctx.verify_mode = ssl.CERT_NONE
      ctx.set_alpn_protocols(['h2', 'http/1.1'])
      
      try:
          reader, writer = await asyncio.wait_for(
              asyncio.open_connection(hostname, port, ssl=ctx),
              timeout=10
          )
          ssock = writer.get_extra_info('ssl_object')
          # ... extract TLS info from ssock ...
          writer.close()
          await writer.wait_closed()
      except (OSError, ssl.SSLError, asyncio.TimeoutError) as e:
          logger.warning(f"[FP-CLONE] TLS probe error: {e}")
      return result
  ```
- **Prevention**: Add a lint rule that flags `socket.create_connection` inside `async` methods. Use `asyncio.open_connection` for all network I/O in async code.

---

### BUG-011: Shared mutable state in engine.py parallel pipelines
- **Severity**: HIGH
- **Category**: Architecture
- **File**: `finder/engine.py:86-175`
- **Description**: In the `VFFinder.scan()` method, three async pipelines (`_content_pipeline`, `_ssl_pipeline`, `_dns_pipeline`) run in parallel via `asyncio.gather` at line 138-143. All three pipelines mutate `self.profile` concurrently (e.g., lines 90, 94, 129). Since Python's GIL prevents true parallelism for CPU-bound work, this is technically safe from data races. However, the parallel pipelines also run async I/O operations, and the `self.profile` object is a shared mutable `SiteProfile` with list/dict attributes. If any pipeline's async operation yields control mid-mutation (e.g., appending to a list), another pipeline could see a partially-mutated state. The `_perf_pipeline` and cache analysis at lines 167-175 have the same issue.
- **Root Cause**: No synchronization mechanism protects `self.profile` mutations. The `asyncio.gather` pattern assumes cooperative concurrency is safe, but mid-iteration list mutations (e.g., `self.profile.api_endpoints.append()`) can cause issues if another coroutine is iterating the same list.
- **Fix**: Use a lock for profile mutations, or collect results from each pipeline and apply them sequentially:
  ```python
  self._profile_lock = asyncio.Lock()
  
  async def _update_profile(self, fn):
      async with self._profile_lock:
          fn(self.profile)
  ```
  Or simpler: have each pipeline return its results instead of mutating `self.profile` directly, then apply them sequentially after `gather`.
- **Prevention**: Document the concurrency model for `VFFinder.scan()`. Add a code review checklist item for shared mutable state in `asyncio.gather` calls.

---

### BUG-012: HAS_AIOHTTP never checked in vf_session_harvest.py and vf_fp_cloner.py
- **Severity**: HIGH
- **Category**: Code Quality
- **File**: `evasion/vf_session_harvest.py:33-37,151`, `evasion/vf_fp_cloner.py:37-41,231`
- **Description**: Both modules correctly set `HAS_AIOHTTP = True/False` at import time (session_harvest lines 33-37, fp_cloner lines 37-41), but neither module ever checks the flag before using `aiohttp`. In `vf_session_harvest.py`, the `harvest()` method at line 151 directly uses `aiohttp.ClientTimeout(...)` — if aiohttp is not installed, this crashes with `NameError` or `AttributeError: 'NoneType' has no attribute 'ClientTimeout'`. Similarly in `vf_fp_cloner.py`, `probe_target` at line 231 creates `aiohttp.ClientTimeout(...)` without checking `HAS_AIOHTTP`.
- **Root Cause**: The `HAS_AIOHTTP` flag was added as a best practice but the guard code was never implemented. Other modules (like `vf_updater.py:158`) correctly check the flag.
- **Fix**: Add early returns in both modules:
  ```python
  # vf_session_harvest.py — in harvest() method:
  if not HAS_AIOHTTP:
      logger.error("[SESSION] aiohttp is required for session harvesting")
      return {"cookies": {}, "token": "", "session_id": "", "user_agent": "", "success": False}

  # vf_fp_cloner.py — in probe_target() method:
  if not HAS_AIOHTTP:
      logger.error("[FP-CLONE] aiohttp is required for TLS probing")
      return result  # return the default result dict
  ```
- **Prevention**: Add a grep-based CI check that every module setting `HAS_AIOHTTP` also has at least one `if not HAS_AIOHTTP` guard before using aiohttp.

---

### BUG-013: VF_TESTER.py reference aliasing bug
- **Severity**: HIGH
- **Category**: Code Quality
- **File**: `tester/VF_TESTER.py` (referenced from plugin_system.py LegacyPluginAdapter)
- **Description**: In the `LegacyPluginAdapter.run()` method (`plugin_system.py:552-610`), the legacy instance is created at line 566, and its `attack()` method is called at line 598. The `stats_callback` passed to `attack()` is `_stats_cb` (line 600), which unpacks a dict into positional args. However, if `VF_TESTER.py` passes `self._record_hit` directly as the callback, and `APIFloodAttacker.attack()` stores `self.stats_callback = stats_callback` (line 618), then multiple references to the same callback can cause aliasing issues — especially if the callback is later replaced. This is an instance of the "callback reference aliasing" anti-pattern where the same function object is shared between multiple attack instances.
- **Root Cause**: The legacy adapter pattern creates an indirection layer (`_stats_cb`) but doesn't prevent the legacy module from overwriting or aliasing the callback reference.
- **Fix**: Ensure each attack instance gets its own callback wrapper:
  ```python
  # In LegacyPluginAdapter.run(), create a unique wrapper per instance:
  def _make_stats_cb(ctx):
      async def _stats_cb(stats_dict):
          if ctx.stats_callback:
              try:
                  mode = stats_dict.get('mode', 'LEGACY')
                  # ... unpacking logic ...
                  ctx.stats_callback(mode, ok, code, rt, err, url, hint)
              except (RuntimeError, TypeError) as exc:
                  logger.debug(f"Stats callback error: {exc}")
      return _stats_cb
  
  cb = _make_stats_cb(context)
  result = await self._legacy_instance.attack(stop_event=context.stop_event, stats_callback=cb)
  ```
- **Prevention**: Document the callback contract clearly. Add integration tests that verify stats are recorded correctly when multiple attack plugins run simultaneously.

---

### BUG-014: vf_api_flood.py double import aiohttp dead code
- **Severity**: HIGH
- **Category**: Code Quality
- **File**: `tester/vf_api_flood.py:40-45`
- **Description**: At line 40, `import aiohttp` is an unconditional import. Then at lines 42-45:
  ```python
  try:
      import aiohttp as _aiohttp_check
  except ImportError:
      aiohttp = None
  ```
  If aiohttp IS installed, line 40 succeeds and `aiohttp` is the module. Lines 42-45 then import it again as `_aiohttp_check` (which is never used). If aiohttp is NOT installed, line 40 raises `ImportError` before reaching line 42, so the try/except block never executes. The guard is dead code in both cases.
- **Root Cause**: The unconditional import at line 40 was added before the try/except guard, and the guard was never made the primary import. The two import patterns are contradictory.
- **Fix**: Remove the unconditional import at line 40 and keep only the guarded version:
  ```python
  try:
      import aiohttp
      HAS_AIOHTTP = True
  except ImportError:
      aiohttp = None
      HAS_AIOHTTP = False
  ```
  Update the guard at line 609 to use `HAS_AIOHTTP` instead of `if aiohttp is None`.
- **Prevention**: Add a lint rule that flags multiple imports of the same module in the same file. Use a single consistent import pattern across the codebase.

---

## MEDIUM — Fix Within Two Sprints

### BUG-015: God Object — VFFinder class exceeds 900 lines with 30+ methods
- **Severity**: MEDIUM
- **Category**: Architecture
- **File**: `finder/engine.py:35-940+`
- **Description**: The `VFFinder` class contains reconnaissance orchestration, WAF detection, strategy determination, attack profile generation, worker config calculation, login config, target selection, resource selection, timing config, evasion config, and display formatting — all in one class. This violates the Single Responsibility Principle and makes the class difficult to test and maintain.
- **Root Cause**: Incremental feature additions without refactoring.
- **Fix**: Extract into focused classes:
  - `StrategyEngine` — strategy determination and vector selection
  - `AttackProfileBuilder` — profile generation from scan results
  - `WorkerConfigCalculator` — worker/ramp/timing configs
  - `TargetSelector` — page/resource target selection
  Keep `VFFinder` as a thin orchestrator that delegates to these classes.
- **Prevention**: Enforce a max class size (e.g., 300 lines) in code review. Use pylint's `too-many-methods` and `too-many-lines` checks.

---

### BUG-016: _process_response method not migrated to plugin architecture
- **Severity**: MEDIUM
- **Category**: Architecture
- **File**: `tester/VF_TESTER.py` (referenced)
- **Description**: The `_process_response` method in VF_TESTER handles status code classification (success/fail/WAF block/timeout) and stats recording. New plugins (like `vf_graphql_introspection.py`) each implement their own version of this logic instead of using a shared method. This leads to inconsistent status code handling across plugins.
- **Root Cause**: The plugin architecture was designed for attack execution but didn't include a shared response processing utility.
- **Fix**: Create a `process_response(status, rt, mode, url)` utility in the `AttackPlugin` base class or as a standalone function in `vf_common.py`.
- **Prevention**: Document the shared response processing API in the plugin development guide.

---

### BUG-017: Dead code — _aiohttp_check in vf_api_flood.py
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `tester/vf_api_flood.py:43`
- **Description**: The variable `_aiohttp_check` at line 43 is assigned but never used. It exists only as a side effect of the try/except import pattern.
- **Root Cause**: See BUG-014 — the double import pattern creates an unused alias.
- **Fix**: Remove the `_aiohttp_check` alias; use only `import aiohttp` inside the try block.
- **Prevention**: Use `pyflakes` or `pylint` to detect unused variables in CI.

---

### BUG-018: CJK character width not handled in render_table
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `vf_common.py:632-687`
- **Description**: The `render_table` function at line 632 uses `len(_strip_ansi(cell))` at line 682 to calculate visible width, but this doesn't account for CJK (Chinese/Japanese/Korean) characters which occupy 2 terminal columns. The `box_line` function at line 420 has the same issue. This causes misaligned table borders when cell content contains CJK characters.
- **Root Cause**: The `len()` function counts Unicode code points, not terminal display width. CJK characters are double-width in most terminal fonts.
- **Fix**: Use `unicodedata.east_asian_width()` to calculate display width:
  ```python
  import unicodedata
  
  def _display_width(text: str) -> int:
      """Return the terminal display width of text, accounting for CJK characters."""
      width = 0
      for ch in _strip_ansi(text):
          eaw = unicodedata.east_asian_width(ch)
          width += 2 if eaw in ('W', 'F') else 1
      return width
  ```
  Replace `len(_strip_ansi(...))` with `_display_width(...)` in `render_table`, `box_line`, `box_line_centered`, and `box_line_right`.
- **Prevention**: Add test cases with CJK strings for all box/table rendering functions.

---

### BUG-019: ensure_utf8 duplication between run.py and vf_common
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `run.py:51-79`, `vf_common.py` (implicit)
- **Description**: The `ensure_utf8_console()` function at `run.py:51-79` is duplicated logic that should be in `vf_common.py` as a shared utility. Other entry points (VF_FINDER.py, VF_TESTER.py) also need UTF-8 console setup but would need to duplicate this code.
- **Root Cause**: The function was written in `run.py` for the launcher, but it's generally useful.
- **Fix**: Move `ensure_utf8_console()` to `vf_common.py` and import it from both `run.py` and other entry points.
- **Prevention**: Code review checklist: no utility functions in entry point scripts.

---

### BUG-020: pyproject.toml version mismatch (22.0.0 vs actual v3.0)
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `pyproject.toml:3`
- **Description**: The version in `pyproject.toml` at line 3 is `22.0.0`, but the banner in `run.py:130` shows `v3.0`. The version numbering is inconsistent and confusing. The `22.0.0` appears to be the UI theme version (v22) accidentally used as the project version.
- **Root Cause**: The UI theme version (v22) was confused with the project version (v3.0).
- **Fix**: Update `pyproject.toml:3` to match the actual project version:
  ```toml
  version = "3.0.0"
  ```
  Better yet, use a single version source (e.g., `__version__` in `vf_common.py`) and read it in `pyproject.toml` via `dynamic = ["version"]`.
- **Prevention**: Add a CI check that validates `pyproject.toml` version against the banner version.

---

### BUG-021: SSL context duplication — create_default_context called repeatedly
- **Severity**: MEDIUM
- **Category**: Performance
- **File**: `finder/dns_scanner.py:524-528,846-849`, `evasion/vf_fp_cloner.py:284-287,308-343`
- **Description**: Multiple locations create `ssl.create_default_context()` then modify it (disable hostname check, set verify_mode to CERT_NONE). This pattern is repeated in `dns_scanner.py` lines 524-528, 846-849 and `vf_fp_cloner.py` lines 284-287, 308-343. Each `create_default_context()` loads the system CA bundle, which is expensive.
- **Root Cause**: No shared SSL context factory for the common "verify disabled" pattern.
- **Fix**: Create a `create_no_verify_ssl_context()` utility in `vf_common.py`:
  ```python
  _no_verify_ctx: ssl.SSLContext | None = None
  
  def create_no_verify_ssl_context() -> ssl.SSLContext:
      """Return a cached SSL context with verification disabled."""
      global _no_verify_ctx
      if _no_verify_ctx is None:
          _no_verify_ctx = ssl.create_default_context()
          _no_verify_ctx.check_hostname = False
          _no_verify_ctx.verify_mode = ssl.CERT_NONE
      return _no_verify_ctx
  ```
  Note: SSLContext is thread-safe after creation, so caching is safe.
- **Prevention**: Code review: any new `ssl.create_default_context()` + `CERT_NONE` pattern should use the shared utility.

---

### BUG-022: Behavior reading phase in VF_TESTER not extensible
- **Severity**: MEDIUM
- **Category**: Architecture
- **File**: `tester/VF_TESTER.py` (referenced)
- **Description**: The behavior reading phase in VF_TESTER (which probes the target before the main attack) has hardcoded logic that isn't extensible via the plugin system. New evasion techniques or probing strategies require modifying VF_TESTER.py directly.
- **Root Cause**: The behavior reading phase predates the plugin system.
- **Fix**: Create a `BehaviorProber` plugin type that can be extended. Move the existing probing logic into a default plugin.
- **Prevention**: Document the plugin extension points. Ensure new features go through the plugin system first.

---

### BUG-023: Unbounded stats dict in vf_api_flood.py
- **Severity**: MEDIUM
- **Category**: Performance
- **File**: `tester/vf_api_flood.py:309-319`
- **Description**: The `self.stats` dict at lines 309-319 has a fixed set of keys, but the `_update_stats` method at line 363 allows any key: `self.stats[key] = self.stats.get(key, 0) + delta`. If a bug causes an unexpected key to be passed, the dict will grow unboundedly. More importantly, the `bytes_sent` counter at line 317 will grow without bound during a long attack, potentially consuming significant memory.
- **Root Cause**: No stats capping or periodic reset mechanism.
- **Fix**: Add a cap to `bytes_sent` or use a rolling window. Validate stats keys:
  ```python
  VALID_STATS_KEYS = {"total_requests", "successful_requests", "failed_requests", 
                      "waf_blocked", "origin_requests", "origin_success",
                      "endpoints_discovered", "bytes_sent", "errors"}
  
  async def _update_stats(self, key: str, delta: int = 1):
      if key not in VALID_STATS_KEYS:
          logger.warning(f"Unknown stats key: {key}")
          return
      async with self._ensure_lock():
          self.stats[key] = self.stats.get(key, 0) + delta
  ```
- **Prevention**: Add type annotations for stats keys. Use a `TypedDict` or dataclass instead of a plain dict.

---

### BUG-024: auto_balance timing race condition
- **Severity**: MEDIUM
- **Category**: Performance
- **File**: `tester/VF_TESTER.py` (referenced)
- **Description**: The auto-balance feature (which adjusts worker count based on server health) reads health metrics and decides whether to scale up or down. However, the health metrics can be stale by the time the scaling decision is applied, leading to over-scaling (too many workers added) or under-scaling (workers removed too aggressively). The timing window between metric collection and scaling action introduces a race condition.
- **Root Cause**: No snapshot-isolation of health metrics. The metrics are read from shared state that's being continuously updated by workers.
- **Fix**: Take a snapshot of health metrics before making scaling decisions:
  ```python
  health_snapshot = {
      'fail_rate': self.stats.fail_rate,
      's5xx_rate': self.stats.s5xx_rate,
      'timeout_rate': self.stats.timeout_rate,
      'health': self.stats.health,
  }
  # Make scaling decision based on snapshot, not live stats
  ```
- **Prevention**: Document the timing assumptions. Add a cooldown period between scaling decisions.

---

### BUG-025: Rate limiter lock missing in some code paths
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `tester/vf_api_flood.py:357-361`
- **Description**: The `_ensure_lock()` method at line 357 lazily creates an `asyncio.Lock`, but if `_update_stats` is called from two different coroutines before the lock is created, both may create their own lock instance, defeating the purpose. The `_lock` field is initialized as `None` at line 320, and there's a race in the `if self._lock is None` check at line 359.
- **Root Cause**: Lazy initialization without synchronization. In asyncio, this is actually safe because only one coroutine runs at a time (cooperative scheduling), so the `if self._lock is None` check is atomic. However, the lazy initialization is still unnecessary complexity.
- **Fix**: Initialize the lock eagerly in `__init__`:
  ```python
  # In __init__:
  self._lock = asyncio.Lock()
  ```
  Remove the `_ensure_lock` method and use `self._lock` directly. If there's a concern about creating the lock outside an event loop, create it in the `attack()` method instead (which is already done at line 614 — but then `_ensure_lock` at line 357 creates a duplicate).
- **Prevention**: Always initialize `asyncio.Lock` in the method that runs inside the event loop, not lazily.

---

### BUG-026: JA3 fingerprint limitation — Python ssl cannot produce real browser JA3
- **Severity**: MEDIUM
- **Category**: Architecture
- **File**: `evasion/vf_fp_cloner.py:306-345`
- **Description**: The `_build_ssl_context` method at line 306 attempts to mimic browser JA3 fingerprints by setting cipher suites, TLS version, and ALPN. However, Python's `ssl` module uses OpenSSL under the hood, which produces a fundamentally different TLS ClientHello than real browsers. The cipher suite ORDER, extensions list, and GREASE values differ significantly. No amount of `set_ciphers()` calls can make Python produce a Chrome-like JA3 hash.
- **Root Cause**: Python's `ssl` module wraps OpenSSL, which has a different TLS implementation than BoringSSL (Chrome) or NSS (Firefox). JA3 fingerprints the entire ClientHello, not just cipher suites.
- **Fix**: Document this limitation clearly. For real JA3 mimicking, consider using `curl_cffi` or `tls-client` libraries which use the actual browser TLS stacks. Add a fallback message when WAF detection identifies JA3-based blocking.
- **Prevention**: Add a comment/documentation explaining the JA3 limitation. Track `curl_cffi` integration as a future enhancement.

---

### BUG-027: SSL analyzer assumes HTTPS on port 443
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `finder/ssl_analyzer.py` (referenced from engine.py:118)
- **Description**: The `analyze_ssl` function is called only when `self.profile.scheme == 'https'` (engine.py line 116), but it doesn't account for HTTPS services on non-standard ports. The `dns_scanner._method_ssl_san()` at line 530 also hardcodes port 443.
- **Root Cause**: Port 443 is the default HTTPS port, but many services use custom ports.
- **Fix**: Extract the port from the URL and pass it to `analyze_ssl`:
  ```python
  port = self.profile.port or (443 if self.profile.scheme == 'https' else 80)
  await analyze_ssl(self.profile, port=port, verify_ssl=self.verify_ssl)
  ```
- **Prevention**: Add test cases for HTTPS on non-standard ports.

---

### BUG-028: Rate probe burst pattern detected as attack
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `finder/vf_rate_probe.py` (referenced from engine.py:169)
- **Description**: The rate limit probe sends a burst of 50 requests (from `defaults.py:73`: `DEFAULT_RATE_PROBE_REQUESTS: int = 50`) to detect rate limiting thresholds. However, this burst itself may trigger WAF/CDN blocking, causing the probe to report incorrect (lower) rate limits. The target may also temporarily block the scanner's IP, affecting subsequent scan phases.
- **Root Cause**: The probe uses a burst pattern instead of a gradual ramp-up.
- **Fix**: Use a gradual ramp-up pattern instead of a burst:
  ```python
  for i in range(DEFAULT_RATE_PROBE_REQUESTS):
      # Send request
      # If blocked, note the threshold and stop
      await asyncio.sleep(0.05)  # 50ms between requests = 20 RPS baseline
  ```
- **Prevention**: Add a configuration option for probe aggressiveness.

---

### BUG-029: CDN keyword duplication between dns_scanner.py and engine.py
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `finder/dns_scanner.py:173-175`, `finder/engine.py:476-481`
- **Description**: CDN detection keywords are defined in two places: `dns_scanner.py:173-175` (`cdn_keywords` list) and `engine.py:476-481` (`cdn_keywords` in `_is_origin_resource`). The two lists are not identical — `dns_scanner.py` includes `'leaseweb'` which `engine.py` doesn't, and `engine.py` includes `'s3', 'amazonaws', 'cdnstatic'` etc. which `dns_scanner.py` doesn't. This causes inconsistent CDN detection.
- **Root Cause**: No centralized CDN keyword list.
- **Fix**: Move the CDN keywords to `config/defaults.py`:
  ```python
  CDN_KEYWORDS: List[str] = [
      'arvan', 'cloudflare', 'akamai', 'incapsula', 'sucuri',
      'cloudfront', 'fastly', 'cdn', 'edge', 'leaseweb', 'stackpath',
      'sotoon', 's3', 'amazonaws', 'cdnstatic', 'azureedge', 'msecnd',
  ]
  ```
- **Prevention**: Add a test that validates all CDN keyword lists are the same.

---

### BUG-030: SiteProfile hand-written constructor vs dataclass
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `finder/site_profile.py` (referenced)
- **Description**: The `SiteProfile` class has a hand-written constructor with 30+ parameters instead of using Python's `dataclass` decorator. This makes it verbose, error-prone, and difficult to add new fields. Default values are scattered and there's no `__repr__` or `__eq__`.
- **Root Cause**: The class predates the dataclass refactor or was written without considering dataclass.
- **Fix**: Convert to a `@dataclass`:
  ```python
  @dataclass
  class SiteProfile:
      url: str
      domain: str = ""
      # ... all fields with defaults ...
  ```
- **Prevention**: Use `@dataclass` for all data container classes. Add pylint `too-many-instance-attributes` check.

---

### BUG-031: Cache analyzer sessions not shared
- **Severity**: MEDIUM
- **Category**: Performance
- **File**: `finder/vf_cache_analyzer.py` (referenced from engine.py:173)
- **Description**: The cache analyzer creates its own `aiohttp.ClientSession` instead of reusing the session from the finder engine. Each new session creates a new connection pool, DNS cache, and cookie jar, wasting resources and potentially triggering rate limiting from the additional connection overhead.
- **Root Cause**: The finder engine doesn't pass its session to sub-modules.
- **Fix**: Pass the shared session from `VFFinder` to all sub-modules:
  ```python
  analyzer = CacheAnalyzer(self.url, self.profile.scripts, self.profile.images,
                          verify_ssl=self.verify_ssl, session=self._session)
  ```
- **Prevention**: Refactor finder modules to accept an optional session parameter.

---

### BUG-032: WAF false positives — 500 status code treated as WAF block
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `evasion/vf_fp_cloner.py:243`, `tester/vf_api_flood.py:513,542`
- **Description**: Multiple modules treat HTTP 500 as a WAF block (e.g., `vf_fp_cloner.py:243` checks `status in (403, 429, 500, 503)` for WAF blocking). However, a 500 status is a generic server error that could be caused by many things (application bugs, overloaded server, database errors). Treating it as a WAF block causes false positives that reduce attack effectiveness and skew profile stats.
- **Root Cause**: ArvanCloud WAF uses 500 for blocking (not just 403/429), so the check was broadened too aggressively.
- **Fix**: Differentiate between WAF 500 and genuine 500 by checking response headers:
  ```python
  def _is_waf_block(status, headers) -> bool:
      if status in (403, 429, 503):
          return True
      if status == 500:
          # ArvanCloud sets specific headers on WAF blocks
          server = headers.get('Server', '').lower()
          return 'arvan' in server or headers.get('X-WAF-Event')
      return False
  ```
- **Prevention**: Document WAF-specific detection logic. Add response header analysis for 500 status codes.

---

### BUG-033: logger.error misuse for informational messages in vf_updater.py
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `infra/vf_updater.py:200,218,304,329,353,368,384,392,478,482,542,651-654`
- **Description**: The `vf_updater.py` uses `logger.error()` for non-error messages throughout the file. Examples:
  - Line 200: `logger.error(f"{latest_message[:80]}")` — informational changelog
  - Line 304: `logger.error(f"[UPDATER] Rolling back...")` — this is a warning
  - Line 329: `logger.error(f"Update error: {e}", exc_info=True)` — correct, but then line 329: `logger.error(f"[UPDATER] Update error: {e}")` duplicates the same message
  - Line 651: `logger.error(f"Update successful!")` — this is NOT an error

  This pollutes error logs and makes it harder to identify real errors.
- **Root Cause**: Developer used `logger.error` as a default logging level without considering severity.
- **Fix**: Replace with appropriate log levels:
  - `logger.error(f"Update successful!")` → `logger.info(f"Update successful!")`
  - `logger.error(f"[UPDATER] Rolling back...")` → `logger.warning(f"[UPDATER] Rolling back...")`
  - Remove duplicate logging at lines 218/219, 328/329, 481/482.
- **Prevention**: Add a lint rule that flags `logger.error` for messages containing "successful", "complete", or other positive terms.

---

### BUG-034: Duplicated logger.error calls in vf_updater.py
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `infra/vf_updater.py:218-219,328-329,481-482,541-542`
- **Description**: Multiple locations log the same error twice:
  - Lines 218-219: `logger.error(f"Error checking updates: {e}", exc_info=True)` then `logger.error(f"[UPDATER] Error checking updates: {e}")`
  - Lines 328-329: `logger.error(f"Update error: {e}", exc_info=True)` then `logger.error(f"[UPDATER] Update error: {e}")`
  - Lines 481-482: `logger.error(f"Git error: {e}", exc_info=True)` then `logger.error(f"[UPDATER] git error: {e}")`
  - Lines 541-542: `logger.error(f"API download error: {e}", exc_info=True)` then `logger.warning(f"[UPDATER] API download error: {e}")`
- **Root Cause**: Likely auto-generated or copy-pasted logging without removing the original.
- **Fix**: Remove the duplicate lines. Keep only one log call per error, using the appropriate level and format:
  ```python
  logger.error(f"[UPDATER] Error checking updates: {e}", exc_info=True)
  ```
- **Prevention**: Add a lint check for consecutive logger calls with similar messages.

---

### BUG-035: render_table doesn't handle empty rows gracefully
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `vf_common.py:676-686`
- **Description**: The `render_table` function at line 676 iterates over rows and cells, but doesn't handle cases where a row has fewer cells than the number of headers. This causes an `IndexError` at line 680 when `i < len(col_widths)` is true but `i >= len(row)`.
- **Root Cause**: No defensive programming for malformed row data.
- **Fix**: Pad short rows with empty strings:
  ```python
  for row in rows:
      row_parts = []
      for i in range(num_cols):
          cell = row[i] if i < len(row) else ""
          # ... format cell ...
  ```
- **Prevention**: Add unit tests for edge cases (empty rows, mismatched column counts).

---

### BUG-036: _visible_len doesn't account for CJK width
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `vf_common.py:383-385`
- **Description**: The `_visible_len` function at line 383 uses `len(_strip_ansi(text))` which counts Unicode code points, not terminal display width. CJK characters occupy 2 terminal columns but are counted as 1. This is a subset of BUG-018 but affects all box-drawing functions that use `_visible_len`.
- **Root Cause**: See BUG-018.
- **Fix**: Replace `len(_strip_ansi(text))` with `_display_width(text)` as described in BUG-018.
- **Prevention**: Same as BUG-018.

---

### BUG-037: box_line padding doesn't account for CJK width
- **Severity**: MEDIUM
- **Category**: Code Quality
- **File**: `vf_common.py:420-422`
- **Description**: The `box_line` function at line 420 calculates padding as `max(width - 4 - len(visible), 0)` where `visible = _strip_ansi(text)`. If `text` contains CJK characters, the padding will be wrong because CJK chars take 2 columns but `len()` counts 1. This causes box borders to be misaligned.
- **Root Cause**: See BUG-018.
- **Fix**: Use `_display_width(text)` instead of `len(_strip_ansi(text))` in all box functions.
- **Prevention**: Same as BUG-018.

---

## LOW — Backlog / Tech Debt

### BUG-038: AUTO_WIDTH computed at import time, never updated
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `vf_common.py:45`
- **Description**: `AUTO_WIDTH = detect_terminal_width()` at line 45 is computed once at module import time. If the terminal is resized after import, the width is stale. The `DASHBOARD_AUTO_WIDTH` default at `defaults.py:17` is `True`, suggesting auto-width should be dynamic.
- **Root Cause**: Module-level constant computed once instead of per-render.
- **Fix**: Call `detect_terminal_width()` in each render cycle instead of using the module-level constant, or add a refresh mechanism.
- **Prevention**: Document that `AUTO_WIDTH` is a one-time snapshot.

---

### BUG-039: Regex compilation in hot path
- **Severity**: LOW
- **Category**: Performance
- **File**: `plugin_system.py:438-439`
- **Description**: In `_try_load_legacy_module`, the regex `re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)` at line 438 is compiled on every call. This is a cold path (plugin loading), so the performance impact is negligible, but it's still a code smell.
- **Root Cause**: No pre-compiled regex constant.
- **Fix**: Move to a module-level compiled regex:
  ```python
  _CAMEL_TO_SNAKE_1 = re.compile('(.)([A-Z][a-z]+)')
  _CAMEL_TO_SNAKE_2 = re.compile('([a-z0-9])([A-Z])')
  ```
- **Prevention**: Use `re.compile()` for all regex patterns used more than once.

---

### BUG-040: render_table doesn't support theme-based colors
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `vf_common.py:672`
- **Description**: The header formatting at line 672 uses `T('accent')` which is theme-dependent, but cell formatting has no theme support. Tables rendered in different themes look inconsistent.
- **Root Cause**: Theme support was added for headers but not for cell content.
- **Fix**: Add optional `cell_color` parameter to `render_table`.
- **Prevention**: Document the theme API for all UI rendering functions.

---

### BUG-041: Dead code — C class redefinition in run.py
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `run.py:89-103`
- **Description**: The `C` class at `run.py:89-103` is a duplicate of `vf_common._Colors`. Since `run.py` already imports from `vf_common` (indirectly through other modules), it could use the shared `C` instance. The local `C` class is dead code that drifts from the canonical color definitions.
- **Root Cause**: `run.py` was written as a standalone launcher with its own color definitions to avoid import dependencies, but those dependencies exist now.
- **Fix**: Import `C` from `vf_common` instead of defining a local class.
- **Prevention**: Code review: no duplicate utility classes across modules.

---

### BUG-042: Unused imports across multiple files
- **Severity**: LOW
- **Category**: Code Quality
- **File**: Multiple files
- **Description**: Several files have unused imports:
  - `vf_api_flood.py:34` — `ssl` imported but never used
  - `vf_api_flood.py:43` — `_aiohttp_check` alias never used (see BUG-017)
  - `plugin_system.py:26` — `asyncio` imported but only used for type hints (could be `TYPE_CHECKING` only)
- **Root Cause**: Imports added during development but never cleaned up.
- **Fix**: Remove unused imports. Move type-hint-only imports into `TYPE_CHECKING` blocks.
- **Prevention**: Add `pyflakes` or `autoflake` to CI pipeline.

---

### BUG-043: Memory inefficiency — large lists held in SiteProfile
- **Severity**: LOW
- **Category**: Performance
- **File**: `finder/site_profile.py` (referenced)
- **Description**: `SiteProfile` stores full lists of `links`, `scripts`, `images`, `stylesheets`, `found_paths`, and `api_endpoints`. For large sites, these lists can contain thousands of entries that are rarely all used. The entire profile (including all lists) is serialized to JSON when saved.
- **Root Cause**: No size limits on discovered resources.
- **Fix**: Add configurable limits (e.g., max 200 links, 100 scripts) and truncate with a warning. Use generators where possible instead of storing full lists.
- **Prevention**: Add `MAX_DISCOVERED_LINKS`, `MAX_DISCOVERED_SCRIPTS` constants to `defaults.py`.

---

### BUG-044: md5 used for fingerprinting instead of sha256
- **Severity**: LOW
- **Category**: Security
- **File**: `evasion/vf_fp_cloner.py:27` (imported `hashlib`)
- **Description**: While `hashlib` is imported at line 27, if any future code uses `hashlib.md5` for fingerprint comparison with server-provided hashes, MD5 is cryptographically broken. The current code doesn't use md5 directly, but the import suggests it was considered.
- **Root Cause**: MD5 is faster but cryptographically weak.
- **Fix**: Use `hashlib.sha256` for any fingerprinting. Remove the `hashlib` import if unused.
- **Prevention**: Add a lint rule flagging `hashlib.md5` and `hashlib.sha1` usage.

---

### BUG-045: C class for colors duplicated between vf_common.py and run.py
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `run.py:89-103`, `vf_common.py:52-187`
- **Description**: The `C` class in `run.py:89-103` is a minimal subset of `vf_common._Colors` (lines 52-187). The two classes define the same ANSI codes but may drift over time. `run.py` also lacks many colors available in `vf_common._Colors`.
- **Root Cause**: See BUG-041.
- **Fix**: Import `C` from `vf_common` in `run.py`:
  ```python
  from vf_common import C
  ```
- **Prevention**: Single source of truth for all constants.

---

### BUG-046: input() blocking in get_target_url()
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `run.py:277`
- **Description**: The `get_target_url` function at line 277 uses `input()` which is a blocking call. While this is acceptable for a CLI launcher, it prevents programmatic usage of `run.py` (e.g., from tests or automation scripts). The `EOFError`/`KeyboardInterrupt` handling at line 278 is good but incomplete.
- **Root Cause**: `input()` is the standard way to get user input in Python CLI tools.
- **Fix**: Add a `--non-interactive` flag or accept URL via stdin pipe:
  ```python
  if not sys.stdin.isatty():
      url = sys.stdin.readline().strip()
  else:
      url = input("   URL: ").strip()
  ```
- **Prevention**: Consider using `click` or `typer` for CLI handling which supports non-interactive mode.

---

### BUG-047: Missing `asyncio` import in exceptions module for type hint
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `exceptions.py:33-41`
- **Description**: The `TimeoutError` docstring at line 36 mentions `asyncio.TimeoutError` but the module doesn't import `asyncio`. While this is only a docstring reference (not runtime code), it could confuse readers who expect `asyncio.TimeoutError` to be accessible from this module.
- **Root Cause**: Docstring references a module that isn't imported.
- **Fix**: Either add `import asyncio` for reference, or change the docstring to reference the fully qualified name without implying import:
  ```python
  """Raised when a network or operation timeout occurs.

  Distinct from :class:`builtins.TimeoutError` (OSError-derived)
  and :class:`asyncio.TimeoutError`. This is a project-specific
  timeout for attack operations and adaptive timeout tracking.
  """
  ```
- **Prevention**: Use Sphinx-style docstrings that link to external references without requiring imports.

---

### BUG-048: ensure_utf8_console() called at module level in run.py
- **Severity**: LOW
- **Category**: Code Quality
- **File**: `run.py:82`
- **Description**: The `ensure_utf8_console()` call at line 82 happens at module import time, before `main()` is called. This means importing `run.py` (even for testing or introspection) will modify `sys.stdout`/`sys.stderr` encoding as a side effect.
- **Root Cause**: The function was placed at module level to ensure UTF-8 works for the banner and all subsequent output.
- **Fix**: Move the call inside `main()`:
  ```python
  def main():
      ensure_utf8_console()
      args = parse_args()
      # ...
  ```
- **Prevention**: No side effects at module import time. Use `if __name__ == "__main__"` guard.

---

## Summary Statistics

| Severity | Count | Key Areas |
|----------|-------|-----------|
| CRITICAL | 8 | Security (SSL, path traversal, supply chain), Architecture (module shadowing, callback mismatch), Network (IP ranges) |
| HIGH | 6 | Blocking I/O in async code, shared mutable state, import guards, dead code |
| MEDIUM | 23 | God Object, CJK support, logging misuse, WAF false positives, session sharing |
| LOW | 11 | Import-time side effects, unused code, memory, minor UX issues |
| **Total** | **48** | |

### Files Most Affected

| File | Bug Count | Severity Range |
|------|-----------|----------------|
| `tester/vf_api_flood.py` | 4 | CRITICAL, HIGH, MEDIUM |
| `finder/dns_scanner.py` | 2 | CRITICAL, MEDIUM |
| `infra/vf_updater.py` | 2 | CRITICAL, MEDIUM |
| `plugin_system.py` | 2 | CRITICAL, HIGH |
| `evasion/vf_fp_cloner.py` | 2 | HIGH, MEDIUM |
| `evasion/vf_session_harvest.py` | 1 | HIGH |
| `vf_common.py` | 4 | MEDIUM |
| `config/settings.py` | 1 | CRITICAL |
| `exceptions.py` | 1 | CRITICAL |
| `run.py` | 3 | CRITICAL, LOW |

### Recommended Fix Order

1. **Sprint 1 (CRITICAL)**: BUG-002 (SSL default), BUG-006 (path traversal), BUG-007 (supply chain), BUG-008 (builtin shadowing), BUG-001 (aiohttp guard), BUG-005 (sys.path shadowing), BUG-003 (IP ranges), BUG-004 (callback mismatch)
2. **Sprint 2 (HIGH)**: BUG-009 (keyboard handler), BUG-010 (blocking socket), BUG-011 (shared state), BUG-012 (aiohttp guard), BUG-013 (callback aliasing), BUG-014 (double import)
3. **Sprint 3-4 (MEDIUM)**: BUG-015 through BUG-037 — prioritize BUG-018/036/037 (CJK), BUG-032 (WAF false positives), BUG-021 (SSL context), BUG-029 (CDN keywords)
4. **Backlog (LOW)**: BUG-038 through BUG-048

---

*End of Technical Roadmap v4*
