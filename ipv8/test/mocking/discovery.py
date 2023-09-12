from ...peerdiscovery.discovery import DiscoveryStrategy


class MockWalk(DiscoveryStrategy):
    """
    Walker that connects to a random pre-known peer every step.
    """

    def take_step(self) -> None:
        """
        Walk to a random verified peer.
        """
        for peer in self.overlay.network.verified_peers:
            self.overlay.walk_to(peer.address)
