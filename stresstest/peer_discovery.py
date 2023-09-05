import os
import time
from asyncio import run
from random import randint

# Check if we are running from the root directory
# If not, modify our path so that we can import IPv8
try:
    import ipv8
    del ipv8
except ImportError:
    import __scriptpath__  # noqa: F401

from ipv8.community import Community
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.util import create_event_with_signals
from ipv8_service import IPv8, _COMMUNITIES


START_TIME = time.time()
LOW_EDGE = 0
LOW_EDGE_PEER = None


class MyCommunity(Community):
    community_id = os.urandom(20)

    def started(self, event):
        async def check_peers():
            global LOW_EDGE, LOW_EDGE_PEER, START_TIME
            if self.get_peers():
                if LOW_EDGE and self.my_peer != LOW_EDGE_PEER:
                    print(f"{LOW_EDGE:.4f},{(time.time() - START_TIME):.4f}")
                    event.set()
                else:
                    LOW_EDGE = time.time() - START_TIME
                    LOW_EDGE_PEER = self.my_peer
        self.register_task("check_peers", check_peers, interval=0.1, delay=0)

    def create_introduction_response(self, lan_socket_address, socket_address, identifier, introduction=None,
                                     extra_bytes=b'', prefix=None, new_style=False):
        return super().create_introduction_response(lan_socket_address, socket_address,
                                                    identifier, introduction, b'1', prefix, new_style)

    def create_introduction_request(self, socket_address, extra_bytes=b'', new_style=False):
        return super().create_introduction_request(socket_address, b'2', new_style)


_COMMUNITIES['MyCommunity'] = MyCommunity


async def start_communities():
    event = create_event_with_signals()

    instances = []
    for i in [1, 2]:
        configuration = get_default_configuration()
        configuration['keys'] = [{
            'alias': "my peer",
            'generation': "medium",
            'file': "ec%d.pem" % i
        }]
        configuration['port'] = 12000 + randint(0, 10000)
        configuration['overlays'] = [{
            'class': 'MyCommunity',
            'key': "my peer",
            'walkers': [{
                'strategy': "RandomWalk",
                'peers': 10,
                'init': {
                    'timeout': 3.0
                }
            }],
            'bootstrappers': [DISPERSY_BOOTSTRAPPER],
            'initialize': {},
            'on_start': [('started', event)]
        }]
        ipv8 = IPv8(configuration)
        await ipv8.start()
        instances.append(ipv8)

    await event.wait()

    for ipv8 in instances:
        await ipv8.stop()


run(start_communities())
