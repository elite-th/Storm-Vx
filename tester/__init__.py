# VF_TESTER Attack Modules
# These modules provide advanced attack capabilities beyond the built-in workers.
# VF_TESTER.py imports them dynamically and runs them alongside its internal workers.

from .vf_slow_read import SlowREADAttacker
from .vf_graphql_flood import GraphQLFloodAttacker
from .vf_ws_flood import WebSocketFloodAttacker
from .vf_header_bomb import HeaderBombAttacker
from .vf_h2_push import H2PushAttacker
from .vf_chunked_bomb import ChunkedBombAttacker
from .vf_cookie_poison import CookiePoisonAttacker
from .vf_h2c_smuggler import H2CSmuggler

__all__ = [
    'SlowREADAttacker',
    'GraphQLFloodAttacker',
    'WebSocketFloodAttacker',
    'HeaderBombAttacker',
    'H2PushAttacker',
    'ChunkedBombAttacker',
    'CookiePoisonAttacker',
    'H2CSmuggler',
]
