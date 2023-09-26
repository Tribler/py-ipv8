import os
from asyncio import run

from ipv8.community import Community
from ipv8.configuration import ConfigBuilder, Strategy, WalkerDefinition, default_bootstrap_defs
from ipv8.util import run_forever
from ipv8_service import IPv8


class MyCommunity(Community):
    # Register this community with a randomly generated community ID.
    # Other peers will connect to this community based on this identifier.
    community_id = os.urandom(20)


async def start_communities() -> None:
    for i in [1, 2]:
        builder = ConfigBuilder().clear_keys().clear_overlays()
        # If we actually want to communicate between two different peers
        # we need to assign them different keys.
        # We will generate an EC key called 'my peer' which has 'medium'
        # security and will be stored in file 'ecI.pem' where 'I' is replaced
        # by the peer number (1 or 2).
        builder.add_key("my peer", "medium", f"ec{i}.pem")
        # Instruct IPv8 to load our custom overlay, registered in _COMMUNITIES.
        # We use the 'my peer' key, which we registered before.
        # We will attempt to find other peers in this overlay using the
        # RandomWalk strategy, until we find 10 peers.
        # We do not provide additional startup arguments or a function to run
        # once the overlay has been initialized.
        builder.add_overlay("MyCommunity", "my peer",
                            [WalkerDefinition(Strategy.RandomWalk,
                                              10, {'timeout': 3.0})],
                            default_bootstrap_defs, {}, [])
        await IPv8(builder.finalize(),
                   extra_communities={'MyCommunity': MyCommunity}).start()
    await run_forever()


run(start_communities())
