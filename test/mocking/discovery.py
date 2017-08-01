from peerdiscovery.discovery import DiscoveryStrategy


class MockWalk(DiscoveryStrategy):

    def take_step(self, service_id=None):
        for peer in self.overlay.network.verified_peers:
            self.overlay.walk_to(peer.address)