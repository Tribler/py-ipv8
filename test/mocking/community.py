from __future__ import absolute_import

from .endpoint import AutoMockEndpoint
from ipv8.keyvault.crypto import ECCrypto
from ipv8.peer import Peer
from ipv8.peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ipv8.peerdiscovery.network import Network


class MockCommunity(DiscoveryCommunity):

    def __init__(self):
        endpoint = AutoMockEndpoint()
        endpoint.open()
        network = Network()
        peer = Peer(ECCrypto().generate_key(u"very-low"), endpoint.wan_address)
        super(MockCommunity, self).__init__(peer, endpoint, network)
