from __future__ import annotations

import os

from ipv8.community import Community
from ipv8.configuration import DISPERSY_BOOTSTRAPPER, get_default_configuration
from ipv8.peerdiscovery.discovery import DiscoveryStrategy


class MyDiscoveryStrategy(DiscoveryStrategy):

    def take_step(self) -> None:
        pass


class MyCommunity(Community):
    community_id = os.urandom(20)

    def get_available_strategies(self) -> dict[str, type[DiscoveryStrategy]]:
        return {"MyDiscoveryStrategy": MyDiscoveryStrategy}


definition = {
    'strategy': "MyDiscoveryStrategy",
    'peers': -1,
    'init': {}
}

config = get_default_configuration()
config['overlays'] = [{
    'class': 'MyCommunity',
    'key': "anonymous id",
    'walkers': [definition],
    'bootstrappers': [DISPERSY_BOOTSTRAPPER.copy()],
    'initialize': {},
    'on_start': []
}]
