from __future__ import annotations

from random import sample
from time import time
from typing import TYPE_CHECKING, cast

from ..types import Overlay
from .discovery import DiscoveryStrategy

if TYPE_CHECKING:
    from ..types import Address, Peer


class RandomChurn(DiscoveryStrategy[Overlay]):
    """
    Select random peers, ping them if inactive, remove them if unresponsive.
    """

    def __init__(self, overlay: Overlay, sample_size: int = 8,
                 ping_interval: float = 10.0, inactive_time: float = 27.5, drop_time: float = 57.5) -> None:
        """
        Random peer removal strategy.

        :param overlay: the overlay to sample peers from
        :param sample_size: the amount of peers to check at once
        :param ping_interval: time between pings in the range of inactive_time to drop_time
        :param inactive_time: time before pings are sent to check liveness
        :param drop_time: time after which a peer is dropped
        """
        super().__init__(overlay)
        self._pinged: dict[Address, float] = {}
        self.sample_size = sample_size
        self.ping_interval = ping_interval
        self.inactive_time = inactive_time
        self.drop_time = drop_time

    def should_drop(self, peer: Peer) -> bool:
        """
        Have we passed the time before we consider this peer to be unreachable.
        """
        if peer.last_response == 0:
            return False
        return time() > (peer.last_response + self.drop_time)

    def is_inactive(self, peer: Peer) -> bool:
        """
        Have we passed the time before we consider this peer to be inactive.
        """
        if peer.last_response == 0:
            return False
        return time() > (peer.last_response + self.inactive_time)

    def take_step(self) -> None:
        """
        Select a new (set of) peer(s) to investigate liveness for.
        """
        with self.walk_lock:
            # Find an inactive or droppable peer
            sample_size = min(len(self.overlay.network.verified_peers), self.sample_size)
            if sample_size:
                window = sample(list(self.overlay.network.verified_peers), sample_size)

                for peer in window:
                    if self.should_drop(peer) and peer.address in self._pinged:
                        self.overlay.network.remove_peer(peer)
                        self._pinged.pop(peer.address)
                    elif self.is_inactive(peer) or len(peer.pings) < cast(int, peer.pings.maxlen):
                        if ((peer.address in self._pinged)
                                and (time() > (self._pinged[peer.address] + self.ping_interval))):
                            self._pinged.pop(peer.address)
                        if peer.address not in self._pinged:
                            self._pinged[peer.address] = time()
                            self.overlay.send_ping(peer)  # type: ignore[attr-defined]
