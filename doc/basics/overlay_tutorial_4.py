import os
from asyncio import run

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.configuration import (ConfigBuilder, Strategy, WalkerDefinition,
                                       default_bootstrap_defs)
from pyipv8.ipv8.peerdiscovery.network import PeerObserver
from pyipv8.ipv8.types import Peer
from pyipv8.ipv8.util import run_forever
from pyipv8.ipv8_service import IPv8


class MyCommunity(Community, PeerObserver):
    community_id = os.urandom(20)

    def on_peer_added(self, peer: Peer) -> None:
        print("I am:", self.my_peer, "I found:", peer)

    def on_peer_removed(self, peer: Peer) -> None:
        pass

    def started(self):
        self.network.add_peer_observer(self)


async def start_communities():
    for i in [1, 2]:
        builder = ConfigBuilder().clear_keys().clear_overlays()
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        # We provide the 'started' function to the 'on_start'.
        # We will call the overlay's 'started' function without any
        # arguments once IPv8 is initialized.
        builder.add_overlay("MyCommunity", "my peer",
                            [WalkerDefinition(Strategy.RandomWalk,
                                              10, {'timeout': 3.0})],
                            default_bootstrap_defs, {}, [('started',)])
        await IPv8(builder.finalize(),
                   extra_communities={'MyCommunity': MyCommunity}).start()
    await run_forever()


run(start_communities())
