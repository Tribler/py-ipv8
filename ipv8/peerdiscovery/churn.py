from random import sample
from time import time
from .discovery import DiscoveryStrategy


class RandomChurn(DiscoveryStrategy):
    """
    Select random peers, ping them if inactive, remove them if unresponsive.
    """

    PING_INTERVAL = 10
    SAMPLE_SIZE = 8

    def __init__(self, overlay):
        super(RandomChurn, self).__init__(overlay)
        self._pinged = {}

    def take_step(self):
        """
        Select a new (set of) peer(s) to investigate liveness for.
        """
        # See if we need to clean our ping cache
        to_remove = []
        for address, timestamp in self._pinged.iteritems():
            if time() > (timestamp + self.PING_INTERVAL):
                to_remove.append(address)
        for address in to_remove:
            del self._pinged[address]
        # Find an inactive or droppable peer
        sample_size = min(len(self.overlay.network.verified_peers), self.SAMPLE_SIZE)
        if sample_size:
            window = sample(self.overlay.network.verified_peers, sample_size)

            for peer in window:
                if peer.should_drop():
                    self.overlay.network.remove_peer(peer)
                elif peer.is_inactive():
                    if peer.address not in self._pinged:
                        self._pinged[peer.address] = time()
                        packet = self.overlay.create_ping()
                        self.overlay.endpoint.send(peer.address, packet)
