from .endpoint import AutoMockEndpoint
from ...keyvault.crypto import default_eccrypto
from ...peer import Peer
from ...peerdiscovery.community import DiscoveryCommunity
from ...peerdiscovery.network import Network


class MockCommunity(DiscoveryCommunity):

    def __init__(self):
        endpoint = AutoMockEndpoint()
        endpoint.open()
        network = Network()
        peer = Peer(default_eccrypto.generate_key(u"very-low"), endpoint.wan_address)
        super(MockCommunity, self).__init__(peer, endpoint, network)
        # workaround for race conditions in deliver_messages
        self._use_main_thread = False
        self.my_estimated_lan = endpoint.lan_address
        self.my_estimated_wan = endpoint.wan_address

    def bootstrap(self):
        super(MockCommunity, self).bootstrap()
        self.last_bootstrap = 0
