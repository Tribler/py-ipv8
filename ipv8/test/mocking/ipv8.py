from __future__ import absolute_import

from ...keyvault.crypto import ECCrypto
from ...peer import Peer
from ...peerdiscovery.network import Network
from .endpoint import AutoMockEndpoint
from .discovery import MockWalk


class MockIPv8(object):

    def __init__(self, crypto_curve, overlay_class, *args, **kwargs):
        self.endpoint = AutoMockEndpoint()
        self.endpoint.open()
        self.network = Network()
        self.my_peer = Peer(ECCrypto().generate_key(crypto_curve), self.endpoint.wan_address)
        self.overlay = overlay_class(self.my_peer, self.endpoint, self.network, *args, **kwargs)
        self.overlay._use_main_thread = False
        self.discovery = MockWalk(self.overlay)

        self.overlay.my_estimated_wan = self.endpoint.wan_address
        self.overlay.my_estimated_lan = self.endpoint.lan_address

    def unload(self):
        self.endpoint.close()
        self.overlay.unload()
