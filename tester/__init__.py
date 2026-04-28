# VF_TESTER Attack Modules
# These modules provide advanced attack capabilities beyond the built-in workers.
# VF_TESTER.py imports them dynamically via importlib (see _MODULE_REGISTRY).
# This __init__.py provides optional package-level imports for external use.

# Use try/except for each import — some modules may have missing dependencies
_loaded = {}

try:
    from .vf_slow_read import SlowREADAttacker
    _loaded['slow_read'] = SlowREADAttacker
except ImportError:
    pass

try:
    from .vf_graphql_flood import GraphQLFloodAttacker
    _loaded['graphql_flood'] = GraphQLFloodAttacker
except ImportError:
    pass

try:
    from .vf_ws_flood import WebSocketFloodAttacker
    _loaded['ws_flood'] = WebSocketFloodAttacker
except ImportError:
    pass

try:
    from .vf_header_bomb import HeaderBombAttacker
    _loaded['header_bomb'] = HeaderBombAttacker
except ImportError:
    pass

try:
    from .vf_h2_push import H2PushAttacker
    _loaded['h2_push'] = H2PushAttacker
except ImportError:
    pass

try:
    from .vf_chunked_bomb import ChunkedBombAttacker
    _loaded['chunked_bomb'] = ChunkedBombAttacker
except ImportError:
    pass

try:
    from .vf_cookie_poison import CookiePoisonAttacker
    _loaded['cookie_poison'] = CookiePoisonAttacker
except ImportError:
    pass

try:
    from .vf_h2c_smuggler import H2CSmuggler
    _loaded['h2c_smuggler'] = H2CSmuggler
except ImportError:
    pass

__all__ = list(_loaded.keys())
