#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""connection_pool — Connection pool lifecycle management.

Phase 0: Provides connection recycling and dead connection cleanup
for aiohttp sessions used during attacks.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from logging_config import get_logger
from config.defaults import (
    DEFAULT_POOL_MAX_SIZE,
    DEFAULT_POOL_RECYCLE_INTERVAL,
    DEFAULT_POOL_RECYCLE_MAX_AGE,
    DEFAULT_POOL_DEAD_CLEANUP_INTERVAL,
)

logger = get_logger(__name__)


@dataclass
class PoolStats:
    """Connection pool statistics."""
    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    recycled_count: int = 0
    dead_cleaned_count: int = 0
    last_recycle_time: float = 0.0
    last_cleanup_time: float = 0.0


class PoolLifecycleManager:
    """Manages aiohttp connection pool lifecycle.

    Wraps an aiohttp.TCPConnector and adds periodic connection
    recycling and dead connection cleanup.

    Usage:
        manager = PoolLifecycleManager(connector)
        task = asyncio.create_task(manager.run_cleanup_loop())
        # ... during attack ...
        manager.stop()
    """

    def __init__(
        self,
        connector: Any,
        max_size: int = DEFAULT_POOL_MAX_SIZE,
        recycle_interval: int = DEFAULT_POOL_RECYCLE_INTERVAL,
        recycle_max_age: int = DEFAULT_POOL_RECYCLE_MAX_AGE,
        cleanup_interval: int = DEFAULT_POOL_DEAD_CLEANUP_INTERVAL,
    ) -> None:
        self._connector = connector
        self._max_size = max_size
        self._recycle_interval = recycle_interval
        self._recycle_max_age = recycle_max_age
        self._cleanup_interval = cleanup_interval
        self._stats = PoolStats()
        self._running = False

    @property
    def stats(self) -> PoolStats:
        return self._stats

    async def run_cleanup_loop(self) -> None:
        """Background task that periodically cleans up the connection pool."""
        self._running = True
        last_recycle = time.monotonic()
        last_cleanup = time.monotonic()

        try:
            while self._running:
                now = time.monotonic()
                if now - last_recycle >= self._recycle_interval:
                    await self._recycle_old_connections()
                    last_recycle = now
                if now - last_cleanup >= self._cleanup_interval:
                    await self._cleanup_dead_connections()
                    last_cleanup = now
                self._update_stats()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            self._running = False
            raise

    async def _recycle_old_connections(self) -> int:
        """Close connections older than max_age."""
        now = time.monotonic()
        recycled = 0
        try:
            if not hasattr(self._connector, '_conns'):
                return 0
            for key, conn_deque in list(self._connector._conns.items()):
                if conn_deque is None:
                    continue
                to_remove = []
                for i, conn in enumerate(conn_deque):
                    try:
                        # aiohttp Connection objects track their creation time
                        if hasattr(conn, 'last_usage_time'):
                            age = now - conn.last_usage_time
                        else:
                            continue
                        if age > self._recycle_max_age:
                            to_remove.append(i)
                    except Exception:
                        pass
                for i in reversed(to_remove):
                    try:
                        conn_deque[i].close()
                    except Exception:
                        pass
                    recycled += 1
                if not conn_deque:
                    self._connector._conns.pop(key, None)
        except (AttributeError, TypeError) as e:
            logger.debug(f"[POOL] Recycle skipped: connector internals changed ({e})")

        self._stats.recycled_count += recycled
        self._stats.last_recycle_time = now
        if recycled > 0:
            logger.debug(f"[POOL] Recycled {recycled} connections (age > {self._recycle_max_age}s)")
        return recycled

    async def _cleanup_dead_connections(self) -> int:
        """Remove connections with closed transports."""
        cleaned = 0
        now = time.monotonic()
        try:
            if not hasattr(self._connector, '_conns'):
                return 0
            for key, conn_deque in list(self._connector._conns.items()):
                if conn_deque is None:
                    continue
                to_remove = []
                for i, conn in enumerate(conn_deque):
                    try:
                        if hasattr(conn, 'transport') and conn.transport is not None:
                            if conn.transport.is_closing():
                                to_remove.append(i)
                        elif hasattr(conn, 'connection') and conn.connection is not None:
                            proto = conn.connection
                            if hasattr(proto, 'transport') and proto.transport is not None:
                                if proto.transport.is_closing():
                                    to_remove.append(i)
                    except Exception:
                        pass
                for i in reversed(to_remove):
                    try:
                        conn_deque[i].close()
                    except Exception:
                        pass
                    cleaned += 1
                if not conn_deque:
                    self._connector._conns.pop(key, None)
        except (AttributeError, TypeError) as e:
            logger.debug(f"[POOL] Cleanup skipped: connector internals changed ({e})")

        self._stats.dead_cleaned_count += cleaned
        self._stats.last_cleanup_time = now
        if cleaned > 0:
            logger.debug(f"[POOL] Cleaned {cleaned} dead connections")
        return cleaned

    def _update_stats(self) -> None:
        """Update pool statistics from connector internals."""
        try:
            if hasattr(self._connector, '_conns'):
                total = sum(len(d) for d in self._connector._conns.values() if d)
                self._stats.idle_connections = total
            if hasattr(self._connector, '_acquired'):
                self._stats.active_connections = len(self._connector._acquired)
            self._stats.total_connections = (
                self._stats.active_connections + self._stats.idle_connections
            )
        except (AttributeError, TypeError):
            pass

    def stop(self) -> None:
        """Signal the cleanup loop to stop."""
        self._running = False


__all__ = ["PoolLifecycleManager", "PoolStats"]
