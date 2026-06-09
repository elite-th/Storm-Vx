#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║     plugin_system — Dynamic Plugin Architecture for Storm-Vx             ║
║                                                                           ║
║  Provides:                                                                ║
║  - PluginMeta: Metadata descriptor for each plugin                       ║
║  - PluginInterface: Abstract base class all plugins must implement       ║
║  - PluginRegistry: Auto-discovery and management of plugin modules       ║
║  - AttackContext: Shared context object passed to attack plugins         ║
║                                                                           ║
║  Adding a new attack module = creating one .py file.                     ║
║  No changes to VF_TESTER.py, vf_data.py, or __init__.py needed!         ║
║                                                                           ║
║  FOR AUTHORIZED TESTING ONLY!                                             ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import os
import sys
import importlib
import importlib.util
import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Callable, Any, TYPE_CHECKING

# ═══ Module Path Setup ═══

from logging_config import get_logger
logger = get_logger(__name__)

if TYPE_CHECKING:
    import aiohttp
    from finder.site_profile import SiteProfile


__all__ = [
    "PluginMeta",
    "PluginInterface",
    "AttackExtras",
    "AttackContext",
    "PluginRegistry",
    "LegacyPluginAdapter",
]


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Metadata
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PluginMeta:
    """Metadata descriptor for a plugin module.

    Every plugin must define a `meta` class attribute with these fields.
    The registry uses this metadata for discovery, filtering, and ordering.

    Attributes:
        name: Unique identifier (e.g. 'ws_flood', 'cookie_poison')
        version: Semantic version string (e.g. '1.0.0')
        plugin_type: One of 'attack', 'finder', 'evasion'
        description: Human-readable description of what this plugin does
        tags: List of tags for filtering (e.g. ['websocket', 'conference'])
        priority: Execution order — lower = runs first (default 50)
        compatible_profiles: Target types this plugin works with
                             (e.g. ['conference', 'student_portal'])
        requirements: Python packages required (e.g. ['aiohttp', 'httpx'])
    """
    name: str
    version: str = '1.0.0'
    plugin_type: str = 'attack'  # 'attack' | 'finder' | 'evasion'
    description: str = ''
    tags: List[str] = field(default_factory=list)
    priority: int = 50
    compatible_profiles: List[str] = field(default_factory=list)
    requirements: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Interface (Abstract Base Class)
# ═══════════════════════════════════════════════════════════════════════════════

class PluginInterface(ABC):
    """Abstract base class for all Storm-Vx plugins.

    Every plugin must:
    1. Define a `meta` class attribute (PluginMeta instance)
    2. Implement `run()` — the main async execution method
    3. Implement `get_stats()` — return current statistics as a dict
    4. Optionally override `stop()` for custom cleanup

    The `run()` method receives an AttackContext object that provides
    access to the shared session, URL, headers, stop event, and stats callback.
    """

    meta: PluginMeta = PluginMeta(name='unnamed')

    @abstractmethod
    async def run(self, context: AttackContext) -> Dict[str, Any]:
        """Execute the plugin's main logic.

        Args:
            context: Shared attack context with session, URL, headers, etc.

        Returns:
            Dict with final statistics after execution completes.
        """
        ...

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        """Return current plugin statistics.

        Must include at minimum:
        - 'total_requests': int
        - 'success_count': int
        - 'error_count': int
        """
        ...

    def stop(self) -> None:
        """Signal the plugin to stop gracefully. Override if needed."""
        if hasattr(self, '_stop_event') and self._stop_event is not None:
            self._stop_event.set()

    def scale(self, delta: int) -> int:
        """Scale the number of workers by delta.

        Positive delta adds workers, negative removes them.
        Returns the actual change applied (may be less than requested).

        Override in subclasses that support dynamic worker scaling.
        The default implementation does nothing and returns 0.
        """
        return 0

    @property
    def worker_count(self) -> int:
        """Return the current number of active workers.

        Override in subclasses that track workers.
        """
        return 0

    def __repr__(self) -> str:
        return f"<Plugin:{self.meta.name} v{self.meta.version}>"


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Extras — Typed Configuration for Plugins
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackExtras:
    """Typed container for plugin-specific attack configuration.

    Replaces the untyped Dict[str, Any] that was previously passed
    via AttackContext.extra. Every field is explicitly typed and
    documented, providing IDE autocompletion and type-checker safety.

    Attributes:
        workers: Number of concurrent workers for this plugin
        delay_ms: Base delay between requests in milliseconds
        cache_bust: Whether to append cache-busting query params
        username_field: Form field name for username (login attacks)
        password_field: Form field name for password (login attacks)
        use_tls: Whether to use TLS for raw TCP connections
        evasion_manager: EvasionManagerStub for header rotation (Any to avoid circular import at runtime; typed as Any because the stub lives in tester/ and importing it here would create a circular dependency)
        waf_name: Name of the detected WAF (empty string if none)
        ssl_ctx: Pre-built SSL context (Any to avoid stdlib import overhead)
    """
    workers: int = 10
    delay_ms: float = 10.0
    cache_bust: bool = True
    username_field: str = "username"
    password_field: str = "password"
    use_tls: bool = False
    evasion_manager: Any = None  # EvasionManagerStub — avoid circular import
    waf_name: str = ""
    ssl_ctx: Any = None  # ssl.SSLContext — avoid stdlib import


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Context — Shared State Object
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackContext:
    """Shared context object passed to all attack plugins.

    This replaces the implicit dependency on VFTester's `self.*` attributes.
    Every plugin receives everything it needs through this single object,
    making plugins decoupled from the orchestrator's internal state.

    Attributes:
        url: Primary target URL
        site_root: Scheme + netloc (e.g. 'https://example.com')
        domain: Domain name without port
        session: aiohttp.ClientSession for making requests
        headers: Base headers dict (with evasion if active)
        stop_event: asyncio.Event — set when attack should stop
        stats_callback: Function to call with (mode, HitResult) for stats recording
        live_log_callback: Function to call with (mode, code, rt, err, url, hint) for logging
        health_callback: Function to call with HitResult for health monitoring
        profile: SiteProfile with target technology profile (or None)
        origin_ips: List of CDN bypass IPs
        page_targets: List of page URLs to attack
        resource_targets: List of resource URLs to attack
        verify_ssl: Whether to verify SSL certificates (default False)
        ssl_ctx: Pre-built SSL context (takes precedence over verify_ssl)
        extra: Typed container for plugin-specific configuration (AttackExtras)
    """
    url: str = ''
    site_root: str = ''
    domain: str = ''
    session: aiohttp.ClientSession | None = None  # type: ignore[name-defined]
    headers: Dict[str, str] = field(default_factory=dict)
    stop_event: asyncio.Event | None = None
    stats_callback: Callable[[str, bool, int, float, str, str, str], None] | None = None  # Called with (mode, ok, code, rt, err, url, hint)
    live_log_callback: Callable[[str, int, float, str | None, str, str], None] | None = None
    health_callback: Callable[[Any], None] | None = None
    profile: Optional[SiteProfile] = None  # type: ignore[type-arg]
    origin_ips: List[str] = field(default_factory=list)
    page_targets: List[str] = field(default_factory=list)
    resource_targets: List[str] = field(default_factory=list)
    verify_ssl: bool = True  # SEC-07: Default to True (matches config/defaults.py VERIFY_SSL)
    ssl_ctx: Any = None
    extra: AttackExtras = field(default_factory=AttackExtras)

    @property
    def ssl_param(self) -> Any:
        """Get the correct ssl parameter for aiohttp requests.

        Returns the pre-built SSL context if available, otherwise
        returns None (verify) or False (no verify) based on verify_ssl.
        """
        if self.ssl_ctx is not None:
            return self.ssl_ctx
        return None if self.verify_ssl else False

    def record(self, mode: str, ok: bool, code: int = 0, rt: float = 0.0,
                err: str = "", url: str = "", hint: str = "") -> None:
        """Record a hit result through the stats callback.

        Signature matches VFTester._record_hit(mode, ok, code, rt, err, url, hint).
        """
        if self.stats_callback:
            self.stats_callback(mode, ok, code, rt, err, url, hint)

    def log(self, mode: str, code: int = 0, rt: float = 0,
            err: str = '', url: str = '', hint: str = '') -> None:
        """Log a request result through the live log callback."""
        if self.live_log_callback:
            self.live_log_callback(mode, code, rt, err, url, hint)

    def health(self, result: Any) -> None:
        """Report a result to the health monitor."""
        if self.health_callback:
            self.health_callback(result)


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Registry — Auto-Discovery and Management
# ═══════════════════════════════════════════════════════════════════════════════

class PluginRegistry:
    """Dynamic plugin discovery, loading, and management.

    Scans specified directories for Python files containing PluginInterface
    subclasses. No manual registration needed — just drop a .py file in
    the plugin directory and it's automatically discovered.

    Usage:
        registry = PluginRegistry(['/path/to/tester', '/path/to/plugins'])
        registry.discover()

        # Get all attack plugins
        attacks = registry.get_by_type('attack')

        # Get plugins compatible with a target type
        conf_plugins = registry.get_by_tag('conference')

        # Get a specific plugin
        ws_flood = registry.get('ws_flood')
    """

    def __init__(self, search_dirs: List[str] | None = None) -> None:
        """Initialize the registry.

        Args:
            search_dirs: List of directories to scan for plugins.
                         If None, defaults to [_THIS_DIR/tester].
        """
        self._plugins: Dict[str, PluginInterface] = {}
        self._plugin_classes: Dict[str, type] = {}
        self._errors: Dict[str, str] = {}
        self._search_dirs: List[str] = search_dirs or []

    def discover(self) -> Dict[str, PluginInterface]:
        """Scan all search directories for plugins and load them.

        Returns:
            Dict of loaded plugins: {name: instance}
        """
        for search_dir in self._search_dirs:
            search_dir = os.path.normpath(search_dir)
            if not os.path.isdir(search_dir):
                continue
            # Append (not insert) to avoid plugin files shadowing stdlib modules.
            # Using insert(0, ...) would let a plugin named e.g. "json.py"
            # override the real json module. append() ensures stdlib is
            # always found first, then plugin dirs as fallback.
            if search_dir not in sys.path:
                sys.path.append(search_dir)

            for py_file in sorted(os.listdir(search_dir)):
                if not py_file.endswith('.py') or py_file.startswith('_'):
                    continue
                if py_file in ('VF_TESTER.py', 'vf_attack_base.py', 'vf_data.py',
                               'vf_health_monitor.py', 'vf_live_log.py',
                               'vf_keyboard.py', 'vf_evasion_stub.py',
                               'vf_viewstate_stub.py'):
                    continue  # Skip non-plugin/utility files

                module_name = py_file[:-3]  # Remove .py
                self._try_load_module(search_dir, py_file, module_name)

        return dict(self._plugins)

    def _try_load_module(self, search_dir: str, py_file: str, module_name: str) -> None:
        """Try to load a module and find PluginInterface subclasses.

        SEC-012: Plugin files are validated before execution:
        - File must contain a PluginInterface subclass definition (heuristic check)
        - File size is bounded (max 500KB to prevent loading non-plugin files)
        - exec_module() still runs arbitrary code, but the search_dir restriction
          and filename filtering reduce the attack surface.
        """
        mod_path = os.path.join(search_dir, py_file)

        # SEC-012: Validate file before loading
        try:
            file_stat = os.stat(mod_path)
            # Skip files larger than 500KB — likely not a plugin
            # W5.7: Use config/defaults.py constant for plugin size limit
            from config.defaults import PLUGIN_MAX_SIZE
            if file_stat.st_size > PLUGIN_MAX_SIZE:
                logger.warning(f"Plugin file too large, skipping: {py_file} ({file_stat.st_size} bytes)")
                # W5.7: Log security audit event
                try:
                    from security.audit import security_log, AuditEvent
                    security_log(AuditEvent.FILE_SIZE_EXCEEDED, severity="WARNING",
                                message=f"Plugin file too large: {py_file}",
                                file=py_file, size=file_stat.st_size, limit=PLUGIN_MAX_SIZE)
                except ImportError:
                    pass
                return
        except OSError as e:
            logger.debug(f"Cannot stat plugin file {py_file}: {e}")
            return

        # SEC-012: Quick heuristic — read first 4KB and check for class definition
        # This prevents accidentally executing non-plugin Python files
        try:
            with open(mod_path, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(4096)
            # Must contain a class definition (even legacy modules need one)
            if "class " not in header and "def attack" not in header:
                logger.debug(f"Skipping {py_file}: no class or attack function definition found")
                return
        except OSError:
            return

        # Strategy 1: importlib.util (find .py file directly)
        loaded_module = None
        try:
            spec = importlib.util.spec_from_file_location(module_name, mod_path)
            if spec and spec.loader:
                loaded_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(loaded_module)
        except (ImportError, SyntaxError, AttributeError) as e:
            # Strategy 2: Fallback to bare import
            try:
                loaded_module = importlib.import_module(module_name)
            except (ImportError, SyntaxError, AttributeError) as e2:
                self._errors[module_name] = f'load failed: {e}; fallback: {e2}'
                return

        if loaded_module is None:
            self._errors[module_name] = 'could not load module'
            return

        # Scan module for PluginInterface subclasses
        found = False
        for attr_name in dir(loaded_module):
            try:
                attr = getattr(loaded_module, attr_name)
            except (AttributeError, TypeError, ImportError) as exc:
                logger.debug(f"Failed to get attribute {attr_name}: {exc}")
                continue
            if (isinstance(attr, type)
                    and issubclass(attr, PluginInterface)
                    and attr is not PluginInterface):
                # Skip abstract classes (they can't be instantiated)
                if getattr(attr, '__abstractmethods__', None):
                    continue
                try:
                    instance = attr()
                    plugin_name = instance.meta.name
                    if plugin_name and plugin_name != 'unnamed':
                        self._plugins[plugin_name] = instance
                        self._plugin_classes[plugin_name] = attr
                        found = True
                except (TypeError, AttributeError) as e:
                    self._errors[f'{module_name}.{attr_name}'] = f'instantiation failed: {e}'

        # Also support legacy AttackModule subclasses (backward compat)
        if not found:
            self._try_load_legacy_module(loaded_module, module_name)

    def _try_load_legacy_module(self, module: object, module_name: str) -> None:
        """Try to load a legacy module as a plugin.

        Supports multiple patterns:
        1. Classes with attack()/async attack() method (duck typing)
        2. Classes with _get_stats() method (used by ws_flood, cookie_poison, etc.)
        """
        for attr_name in dir(module):
            try:
                attr = getattr(module, attr_name)
            except (AttributeError, TypeError, ImportError) as exc:
                logger.debug(f"Failed to get attribute {attr_name}: {exc}")
                continue
            if not isinstance(attr, type):
                continue
            if attr in (PluginInterface, object):
                continue
            # Skip abstract classes
            if getattr(attr, '__abstractmethods__', None):
                continue
            # Skip PluginInterface subclasses (they should be loaded above, not as legacy)
            if issubclass(attr, PluginInterface):
                continue

            # Check if it's a duck-typed module (has __init__ + attack/run method)
            has_init = hasattr(attr, '__init__')
            # C9: General check — any class with __init__ + attack() or run() method
            has_attack = hasattr(attr, 'attack') or hasattr(attr, 'run')
            has_stats = any(hasattr(attr, m) for m in ['get_stats', '_get_stats', '_update_stats'])

            # Must be a class that looks like an attack module
            if not (has_init and (has_attack or has_stats)):
                continue

            # Skip utility/data classes
            if attr_name.startswith('_'):
                continue

            try:
                # Get name — try get_info() first, then use class name
                info: Dict[str, Any] = {}
                plugin_name: str = module_name.replace('vf_', '')

                # Try get_info() if available
                if hasattr(attr, 'get_info'):
                    try:
                        info = attr.get_info()
                        info['display_name'] = info.get('name', '')
                        info['name'] = plugin_name
                    except (TypeError, AttributeError) as exc:
                        info = {'name': plugin_name, 'description': '',
                                'target_type': 'http'}
                else:
                    # Derive name from module filename (consistent naming)
                    name = attr.__name__
                    import re
                    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
                    snake_name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
                    info = {'name': plugin_name, 'description': name,
                            'target_type': 'http', 'class_name': name}

                # Create adapter
                adapter = LegacyPluginAdapter(attr, plugin_name, info)
                self._plugins[plugin_name] = adapter
                self._plugin_classes[plugin_name] = attr
            except (TypeError, AttributeError) as exc:
                self._errors[f'{module_name}.{attr_name}'] = f'legacy load failed: {exc}'
                logger.debug(f"Legacy module load failed for {module_name}.{attr_name}: {exc}")

    def get(self, name: str) -> PluginInterface | None:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_class(self, name: str) -> type | None:
        """Get a plugin class by name (for creating new instances)."""
        return self._plugin_classes.get(name)

    def get_by_type(self, plugin_type: str) -> List[PluginInterface]:
        """Get all plugins of a given type."""
        return [p for p in self._plugins.values()
                if p.meta.plugin_type == plugin_type]

    def get_by_tag(self, tag: str) -> List[PluginInterface]:
        """Get all plugins matching a tag."""
        return [p for p in self._plugins.values()
                if tag in p.meta.tags]

    def get_compatible(self, profile_type: str) -> List[PluginInterface]:
        """Get plugins compatible with a target profile type.

        If a plugin has no compatible_profiles defined, it's considered
        compatible with everything (universal).
        """
        return [p for p in self._plugins.values()
                if not p.meta.compatible_profiles
                or profile_type in p.meta.compatible_profiles]

    def get_sorted(self, plugin_type: str | None = None) -> List[PluginInterface]:
        """Get plugins sorted by priority (lower = earlier)."""
        plugins = list(self._plugins.values())
        if plugin_type:
            plugins = [p for p in plugins if p.meta.plugin_type == plugin_type]
        return sorted(plugins, key=lambda p: p.meta.priority)

    @property
    def names(self) -> List[str]:
        """List of all loaded plugin names."""
        return list(self._plugins.keys())

    @property
    def errors(self) -> Dict[str, str]:
        """Dict of module_name -> error_message for modules that failed to load."""
        return dict(self._errors)

    @property
    def count(self) -> int:
        """Number of loaded plugins."""
        return len(self._plugins)

    def __contains__(self, name: str) -> bool:
        return name in self._plugins

    def __len__(self) -> int:
        return len(self._plugins)

    def __repr__(self) -> str:
        return f"<PluginRegistry: {len(self._plugins)} plugins loaded>"


# ═══════════════════════════════════════════════════════════════════════════════
# Legacy Plugin Adapter — Backward Compatibility
# ═══════════════════════════════════════════════════════════════════════════════

class LegacyPluginAdapter(PluginInterface):
    """Adapter that wraps legacy AttackModule subclasses as PluginInterface.

    This allows existing attack modules (slow_read, ws_flood, etc.) to work
    with the new plugin system without any modifications. The adapter
    translates between the old AttackModule API and the new PluginInterface.

    The legacy module's get_info() is mapped to PluginMeta, and its attack()
    method is called from run().
    """

    def __init__(self, legacy_class: type, name: str, info: Dict[str, Any]) -> None:
        self._legacy_class: type = legacy_class
        self._legacy_instance: object | None = None
        self._name: str = name
        self._info: Dict[str, Any] = info

        # Build PluginMeta from legacy get_info()
        target_type = info.get('target_type', 'http')
        tags: List[str] = [target_type]
        # Add 'conference' tag if it's a ws/api module
        if 'ws' in name.lower() or 'websocket' in name.lower():
            tags.append('conference')
        if 'api' in name.lower():
            tags.append('conference')
            tags.append('student_portal')

        self.meta = PluginMeta(
            name=name,
            version='1.0.0',
            plugin_type='attack',
            description=info.get('description', ''),
            tags=tags,
            priority=50,
            requirements=info.get('requirements', []),
        )

    async def run(self, context: AttackContext) -> Dict[str, Any]:
        """Run the legacy attack module via its attack() method.

        Creates a legacy instance with URL and worker count from context,
        then calls attack(stop_event, stats_callback).
        """
        # Build kwargs for legacy constructor
        kwargs: Dict[str, Any] = {'url': context.url, 'workers': context.extra.workers}
        if context.origin_ips:
            kwargs['origin_ips'] = context.origin_ips
        # ARCH-3: Pass verify_ssl as explicit kwarg for legacy modules
        kwargs['verify_ssl'] = context.verify_ssl

        try:
            self._legacy_instance = self._legacy_class(**kwargs)
        except TypeError:
            # Module doesn't accept all provided kwargs — try with just url and workers
            self._legacy_instance = self._legacy_class(url=context.url, workers=kwargs['workers'])

        # Build stats callback that routes through context
        async def _stats_cb(stats_dict: Dict[str, Any]) -> None:
            """Route legacy stats updates through context's callbacks.
            
            This MUST be async because attack modules call `await stats_callback(...)`.
            Previously this was a sync function, causing TypeError when modules tried to await it.
            
            BUG-FIX: Legacy modules pass stats dicts, but context.stats_callback expects
            (mode, ok, code, rt, err, url, hint). We extract what we can from the dict.
            """
            if context.stats_callback:
                try:
                    mode = stats_dict.get('mode', 'LEGACY')
                    ok = stats_dict.get('ok', True)
                    code = stats_dict.get('code', 0)
                    rt = stats_dict.get('rt', 0.0)
                    err = stats_dict.get('err', '')
                    url = stats_dict.get('url', '')
                    hint = stats_dict.get('hint', '')
                    context.stats_callback(mode, ok, code, rt, err, url, hint)
                except (RuntimeError, TypeError) as exc:
                    logger.debug(f"Stats callback error in legacy adapter: {exc}")

        # C2 FIX: Support both attack() and run() method names.
        # Previously only attack() was called, but the duck-type check
        # accepts modules with either method. Now we check which one exists.
        if hasattr(self._legacy_instance, 'attack'):
            result = await self._legacy_instance.attack(
                stop_event=context.stop_event,
                stats_callback=_stats_cb
            )
        elif hasattr(self._legacy_instance, 'run'):
            result = await self._legacy_instance.run(
                stop_event=context.stop_event,
                stats_callback=_stats_cb
            )
        else:
            logger.error(f"Legacy module {self._name} has neither attack() nor run()")
            result = None
        return result or {}

    def get_stats(self) -> Dict[str, Any]:
        """Delegate to legacy module's get_stats()."""
        if self._legacy_instance:
            return self._legacy_instance.get_stats()
        return {}

    def stop(self) -> None:
        """Delegate to legacy module's stop()."""
        if self._legacy_instance:
            self._legacy_instance.stop()

    def create_instance(self, **kwargs: Any) -> Any:
        """Create a new legacy instance with custom kwargs.

        This is used by VF_TESTER.run() which needs to pass specific
        parameters like workers, read_delay, etc.
        """
        return self._legacy_class(**kwargs)
