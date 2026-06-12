# Storm-Vx WordPress Enhancement — Technical Roadmap

## Objective
Transform Storm-Vx from a generic DDoS tool into a WordPress-specialized
attack framework, maximizing per-request server impact (amplification)
within single-machine Python constraints.

## Current Score: 69/100 → Target: 82-85/100

---

## Phase 1: New WordPress Plugins (HIGHEST IMPACT)

### 1.1 wp_cron_bomb.py — wp-cron.php Bomb (CRITICAL)
- **File**: `tester/vf_wp_cron_bomb.py`
- **Target**: `wp-cron.php?doing_wp_cron=<timestamp>`
- **Impact**: Each request spawns a FULL PHP process (no caching possible)
- **Amplification**: ~5x (PHP process spawn + DB queries + scheduled hooks)
- **Implementation**: 
  - GET requests to `/wp-cron.php?doing_wp_cron=<rand_timestamp>`
  - Cache busting via random timestamp
  - High-priority plugin (priority=18, before login_flood)

### 1.2 wp_ajax_flood.py — admin-ajax.php Flood (CRITICAL)
- **File**: `tester/vf_wp_ajax_flood.py`
- **Target**: `/wp-admin/admin-ajax.php`
- **Impact**: Always dynamic (bypasses ALL caches), triggers PHP + DB
- **Amplification**: ~3x per request
- **Implementation**:
  - POST with `action=<nopriv_action>` for unauthenticated AJAX
  - Common nopriv actions: heartbeat, get_comments, woocommerce stuff
  - Random action selection per request for diversity

### 1.3 wp_rest_flood.py — WP REST API Flood (HIGH)
- **File**: `tester/vf_wp_rest_flood.py`
- **Target**: `/wp-json/wp/v2/*`
- **Impact**: Heavy DB queries with _embed, per_page=100, search params
- **Amplification**: ~4x (complex JOIN queries)
- **Implementation**:
  - Rotate between endpoints: posts, pages, comments, users, categories
  - Add `_embed=1` and `per_page=100` for heaviest queries
  - Add `search=<random>` for full table scan

### 1.4 wp_search_bomb.py — WordPress Search Bomb (HIGH)
- **File**: `tester/vf_wp_search_bomb.py`
- **Target**: `/?s=<random>` and search endpoint
- **Impact**: Full-text LIKE query on posts table (uncached)
- **Amplification**: ~2x (DB-heavy)
- **Implementation**:
  - Random search terms + Persian/Unicode chars for heavier processing
  - Combine with `post_type=product` for WooCommerce sites
  - Cache busting via unique search terms

### 1.5 wp_woocommerce_flood.py — WooCommerce Flood (MEDIUM)
- **File**: `tester/vf_woocommerce_flood.py`
- **Target**: WooCommerce-specific heavy endpoints
- **Impact**: DB writes (cart sessions), price calculations, coupon validation
- **Amplification**: ~3x (DB writes + CPU)
- **Implementation**:
  - `/?add-to-cart=<random>` → INSERT into sessions table
  - `/cart/` → full price recalculation
  - `/?wc-ajax=get_refreshed_fragments` → no auth, CPU-heavy
  - Auto-detect WooCommerce from profile

---

## Phase 2: Enhance Existing WordPress Plugins

### 2.1 vf_wp_xmlrpc_bomb.py — Add Heavy Methods
- Add: `wp.newPost`, `wp.editPost`, `wp.deletePost`, `wp.newComment`
- Add: `wp.uploadFile`, `wp.setOptions`
- Add: `metaWeblog.getRecentPosts`, `mt.getRecentPostTitles`
- Increase default multicall from 300 to 500-1000
- These methods cause DB writes + cache invalidation = much heavier

### 2.2 vf_login_flood.py — WordPress-Specific Targeting
- Always include `/wp-login.php` as first priority
- Add `/wp-login.php?action=lostpassword` (triggers email = SMTP + CPU)
- Add `/wp-login.php?action=register` (triggers DB write + email)
- WordPress bcrypt hash is intentionally slow = perfect CPU burn target

---

## Phase 3: Infrastructure & Bug Fixes

### 3.1 Vector-to-Plugin Mapping Updates
- Add: `WP_CRON_BOMB → wp_cron_bomb`
- Add: `WP_AJAX_FLOOD → wp_ajax_flood`
- Add: `WP_REST_FLOOD → wp_rest_flood`
- Add: `WP_SEARCH_BOMB → wp_search_bomb`
- Add: `WP_WOOCOMMERCE_FLOOD → wp_woocommerce_flood`

### 3.2 Default Config Updates
- Add worker allocation configs for new plugins
- Add WordPress-specific strategy: `WP_FOCUSED`
- Update `DEFAULT_MINIMAL_ATTACK` to include WP vectors when CMS=WordPress

### 3.3 Stats Race Condition Fix
- `AdaptiveScalingEngine.tick()` reads stats attributes without lock
- Fix: Use `stats.get_snapshot()` consistently in tick()

### 3.4 HOLD Mode Exit Fix
- Current: exit condition is logically unreachable (dead code)
- Fix: Add time-based expiry check + recovery worker addition

### 3.5 ConnectionPoolStats Double-Counting Fix
- `record_connection()` and TraceConfig callbacks both increment
- Fix: Remove the TraceConfig increment (keep only the explicit one)

### 3.6 Plugin Crash Connection Leak Fix
- Crashed plugin connections not returned to pool
- Fix: Add connection cleanup in _run_plugin exception handler

---

## Phase 4: Payload Pre-generation Optimization

### 4.1 XML-RPC Payload Pool
- Pre-generate 20 XML-RPC payloads at plugin init
- Random selection per request instead of building each time
- Saves ~2ms per request = significant at high RPS

---

## Implementation Order (by impact):

1. wp_cron_bomb.py (new plugin) — highest WP impact
2. wp_ajax_flood.py (new plugin) — second highest
3. wp_rest_flood.py (new plugin) — third
4. wp_search_bomb.py (new plugin) — fourth
5. wp_woocommerce_flood.py (new plugin) — fifth
6. vf_wp_xmlrpc_bomb.py (enhance) — more methods
7. vf_login_flood.py (enhance) — WP targeting
8. vf_plugin_orchestrator.py (vector mapping)
9. config/defaults.py (new configs)
10. Bug fixes (Stats, HOLD, pool, crash leak)
11. Payload pre-generation

---

## Expected Score After Implementation:
- Attack Effectiveness: 8.0 → 9.5 (WordPress amplification)
- Code Correctness: 6.5 → 8.0 (bug fixes)
- Architecture/Design: 7.5 → 8.0 (new plugins fit cleanly)
- Resource Management: 6.0 → 7.0 (leak fixes)
- Overall: 69 → 82-85
