from typing import Type, Union

from .discovery import MockWalk
from .endpoint import AutoMockEndpoint
from ...dht.discovery import DHTDiscoveryCommunity
from ...keyvault.crypto import default_eccrypto
from ...messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ...peer import Peer
from ...peerdiscovery.network import Network
from ...types import Community
from ...util import maybe_coroutine


class MockIPv8(object):

    def __init__(self,
                 crypto_curve_or_peer: Union[str, Peer],
                 overlay_class: Type[Community],
                 create_dht: bool = False,
                 enable_statistics: bool = False,
                 **kwargs) -> None:
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()

        # Enable statistics
        if enable_statistics:
            self.endpoint = StatisticsEndpoint(self, self.endpoint)

        self.network = Network()
        if isinstance(crypto_curve_or_peer, Peer):
            self.my_peer = crypto_curve_or_peer
            self.my_peer.address = self.endpoint.wan_address
        else:
            self.my_peer = Peer(default_eccrypto.generate_key(crypto_curve_or_peer), self.endpoint.wan_address)

        # Load a DHT community if specified
        self.dht = None
        if create_dht:
            self.dht = DHTDiscoveryCommunity(self.my_peer, self.endpoint, self.network)
            kwargs.update({'dht': self.dht})

        self.overlay = overlay_class(self.my_peer, self.endpoint, self.network, **kwargs)
        self.overlay._use_main_thread = False
        self.discovery = MockWalk(self.overlay)

        self.overlay.my_estimated_wan = self.endpoint.wan_address
        self.overlay.my_estimated_lan = self.endpoint.lan_address

        self.overlays = []
        self.strategies = []

        if enable_statistics:
            self.endpoint.enable_community_statistics(self.overlay.get_prefix(), True)

    def add_strategy(self, overlay, strategy, target_peers):
        self.overlays.append(overlay)
        self.strategies.append((strategy, target_peers))

    def get_overlay(self, overlay_cls):
        return next(self.get_overlays(overlay_cls), None)

    def get_overlays(self, overlay_cls):
        return (o for o in [self.dht, self.overlay] if isinstance(o, overlay_cls))

    def unload_overlay(self, instance):
        self.overlays = [overlay for overlay in self.overlays if overlay != instance]
        self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                           if strategy.overlay != instance]
        return maybe_coroutine(instance.unload)

    async def stop(self, stop_loop=True):
        self.endpoint.close()
        await self.overlay.unload()
        if self.dht:
            await self.dht.unload()
