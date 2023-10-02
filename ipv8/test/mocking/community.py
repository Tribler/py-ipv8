from ...community import CommunitySettings
from ...keyvault.crypto import default_eccrypto
from ...peer import Peer
from ...peerdiscovery.community import DiscoveryCommunity
from ...peerdiscovery.network import Network
from .endpoint import AutoMockEndpoint


class MockCommunity(DiscoveryCommunity):
    """
    Semi-inert version of the DiscoveryCommunity for testing.
    """

    def __init__(self) -> None:
        """
        Create a new MockCommunity.
        """
        endpoint = AutoMockEndpoint()
        endpoint.open()

        settings = CommunitySettings(
            endpoint=endpoint,
            network=Network(),
            my_peer=Peer(default_eccrypto.generate_key("very-low"), endpoint.wan_address)
        )
        super().__init__(settings)
        # workaround for race conditions in deliver_messages
        self._use_main_thread = False
        self.my_estimated_lan = endpoint.lan_address
        self.my_estimated_wan = endpoint.wan_address
