from __future__ import annotations

from typing import TYPE_CHECKING, Awaitable, Generator

from ...community import CommunitySettings
from ...dht.discovery import DHTDiscoveryCommunity
from ...keyvault.crypto import default_eccrypto
from ...messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ...peer import Peer
from ...peerdiscovery.network import Network
from ...util import maybe_coroutine
from .discovery import MockWalk
from .endpoint import AutoMockEndpoint

if TYPE_CHECKING:
    from ...peerdiscovery.discovery import DiscoveryStrategy
    from ...types import Community, Overlay


class MockIPv8:
    """
    Manager for IPv8 related objects during tests.

    Note that this is not the same as an IPv8 instance (nor is it a subclass)! However, many of the same
    functionalities are offered.
    """

    def __init__(self,
                 crypto_curve_or_peer: str | Peer,
                 overlay_class: type[Community],
                 settings: CommunitySettings | None = None,
                 create_dht: bool = False,
                 enable_statistics: bool = False) -> None:
        """
        Create a new MockIPv8 instance.
        """
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()

        # Enable statistics
        if enable_statistics:
            self.endpoint = StatisticsEndpoint(self.endpoint)

        self.network = Network()
        if isinstance(crypto_curve_or_peer, Peer):
            self.my_peer = crypto_curve_or_peer
            self.my_peer.address = self.endpoint.wan_address
        else:
            self.my_peer = Peer(default_eccrypto.generate_key(crypto_curve_or_peer), self.endpoint.wan_address)

        fwd_settings = overlay_class.settings_class(my_peer=self.my_peer, endpoint=self.endpoint, network=self.network)
        if settings is not None:
            settings.__dict__.update(fwd_settings.__dict__)
            fwd_settings = settings

        # Load a DHT community if specified
        self.dht = None
        if create_dht:
            self.dht = DHTDiscoveryCommunity(CommunitySettings(my_peer=self.my_peer, endpoint=self.endpoint,
                                                               network=self.network))
            fwd_settings.dht = self.dht

        self.overlay = overlay_class(fwd_settings)
        self.discovery = MockWalk(self.overlay)

        self.overlay.my_estimated_wan = self.endpoint.wan_address
        self.overlay.my_estimated_lan = self.endpoint.lan_address

        self.overlays = []
        self.strategies = []

        if enable_statistics:
            self.endpoint.enable_community_statistics(self.overlay.get_prefix(), True)

    def add_strategy(self, overlay: Overlay, strategy: DiscoveryStrategy, target_peers: int) -> None:
        """
        Register a strategy to call every tick unless a target number of peers has been reached.
        If the ``target_peers`` is equal to ``-1``, the strategy is always called.
        """
        self.overlays.append(overlay)
        self.strategies.append((strategy, target_peers))

    def get_overlay(self, overlay_cls: type[Overlay]) -> Overlay | None:
        """
        Get any loaded overlay instance from a given class type, if it exists.
        """
        return next(self.get_overlays(overlay_cls), None)

    def get_overlays(self, overlay_cls: type[Overlay]) -> Generator[Overlay]:
        """
        Get all loaded overlay instances from a given class type.
        """
        return (o for o in [self.dht, self.overlay] if isinstance(o, overlay_cls))

    def unload_overlay(self, instance: Overlay) -> Awaitable:
        """
        Unregister and unload a given overlay instance.
        """
        self.overlays = [overlay for overlay in self.overlays if overlay != instance]
        self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                           if strategy.overlay != instance]
        return maybe_coroutine(instance.unload)

    async def stop(self) -> None:
        """
        Stop all registered IPv8 strategies, unload all registered overlays and close the endpoint.
        """
        await maybe_coroutine(self.endpoint.close)
        await self.overlay.unload()
        if self.dht:
            await self.dht.unload()
