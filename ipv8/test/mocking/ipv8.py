from __future__ import absolute_import

from ...attestation.trustchain.community import TrustChainCommunity
from ...dht.discovery import DHTDiscoveryCommunity
from ...keyvault.crypto import ECCrypto
from ...messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ...peer import Peer
from ...peerdiscovery.network import Network
from .endpoint import AutoMockEndpoint
from .discovery import MockWalk


class MockIPv8(object):

    def __init__(self, crypto_curve, overlay_class, create_trustchain=False, create_dht=False, enable_statistics=False,
                 *args, **kwargs):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()

        # Enable statistics
        if enable_statistics:
            self.endpoint = StatisticsEndpoint(self, self.endpoint)

        self.network = Network()
        self.my_peer = Peer(ECCrypto().generate_key(crypto_curve), self.endpoint.wan_address)

        # Load a TrustChain community if specified
        self.trustchain = None
        if create_trustchain:
            self.trustchain = TrustChainCommunity(self.my_peer, self.endpoint, self.network,
                                                  working_directory=u":memory:")
            kwargs.update({'trustchain': self.trustchain})

        # Load a DHT community if specified
        self.dht = None
        if create_dht:
            self.dht = DHTDiscoveryCommunity(self.my_peer, self.endpoint, self.network)
            kwargs.update({'dht': self.dht})

        self.overlay = overlay_class(self.my_peer, self.endpoint, self.network, *args, **kwargs)
        self.overlay._use_main_thread = False
        self.discovery = MockWalk(self.overlay)

        self.overlay.my_estimated_wan = self.endpoint.wan_address
        self.overlay.my_estimated_lan = self.endpoint.lan_address

        if enable_statistics:
            self.endpoint.enable_community_statistics(self.overlay.get_prefix(), True)

    def unload(self):
        self.overlay.unload()
        if self.trustchain:
            self.trustchain.unload()
        if self.dht:
            self.dht.unload()
        self.endpoint.close()
