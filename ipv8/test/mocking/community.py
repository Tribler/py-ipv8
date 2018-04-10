from __future__ import absolute_import

from .endpoint import AutoMockEndpoint
from ...keyvault.crypto import ECCrypto
from ...peer import Peer
from ...peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ...peerdiscovery.network import Network


class MockCommunity(DiscoveryCommunity):

    def __init__(self):
        endpoint = AutoMockEndpoint()
        endpoint.open()
        network = Network()
        peer = Peer(ECCrypto().generate_key(u"very-low"), endpoint.wan_address)
        super(MockCommunity, self).__init__(peer, endpoint, network)

    def bootstrap(self):
        super(MockCommunity, self).bootstrap()
        self.last_bootstrap = 0
