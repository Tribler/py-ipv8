from __future__ import annotations

import os
import time
from asyncio import Event, run
from random import randint
from typing import TYPE_CHECKING

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
from ipv8_service import _COMMUNITIES, IPv8

if TYPE_CHECKING:
    from ipv8.types import Address, Peer


class MyCommunity(Community):
    """
    Community with a random id, to check introduction time for.
    """

    community_id = os.urandom(20)

    START_TIME = time.time()
    LOW_EDGE = 0
    LOW_EDGE_PEER = None

    def started(self, event: Event) -> None:
        """
        Callback for when IPv8 has started.

        :param event: The termination event.
        """
        async def check_peers() -> None:
            if self.get_peers():
                if MyCommunity.LOW_EDGE and self.my_peer != MyCommunity.LOW_EDGE_PEER:
                    print(f"{MyCommunity.LOW_EDGE:.4f},{(time.time() - MyCommunity.START_TIME):.4f}")  # noqa: T201
                    event.set()
                else:
                    MyCommunity.LOW_EDGE = time.time() - MyCommunity.START_TIME
                    MyCommunity.LOW_EDGE_PEER = self.my_peer
        self.register_task("check_peers", check_peers, interval=0.1, delay=0)

    def create_introduction_response(self, lan_socket_address: Address, socket_address: Address,  # noqa: PLR0913
                                     identifier: int, introduction: Peer | None = None, extra_bytes: bytes = b'',
                                     prefix: bytes | None = None, new_style: bool = False) -> bytes:
        """
        Add the extra_bytes ``b'1'`` to all introduction responses.
        """
        return super().create_introduction_response(lan_socket_address, socket_address,
                                                    identifier, introduction, b'1', prefix, new_style)

    def create_introduction_request(self, socket_address: Address, extra_bytes: bytes = b'', new_style: bool = False,
                                    prefix: bytes | None = None) -> bytes:
        """
        Add the extra_bytes ``b'2'`` to all introduction requests.
        """
        return super().create_introduction_request(socket_address, b'2', new_style)


_COMMUNITIES['MyCommunity'] = MyCommunity


async def start_communities() -> None:
    """
    Start two Communities that terminate when the peers have found each other.
    """
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
