from __future__ import annotations

import abc
from random import choice, randint
from threading import Lock
from time import time
from typing import TYPE_CHECKING, Generic, Optional, TypeVar

from ..types import Overlay

if TYPE_CHECKING:
    from ..types import Address, Peer

_OT = TypeVar("_OT", bound=Optional[Overlay])


class DiscoveryStrategy(Generic[_OT], metaclass=abc.ABCMeta):
    """
    Strategy for discovering peers in a network.
    """

    def __init__(self, overlay: _OT) -> None:
        """
        Create a new strategy instance for a particular overlay (or ``None``).
        """
        self.overlay: _OT = overlay
        self.walk_lock = Lock()

    @abc.abstractmethod
    def take_step(self) -> None:
        """
        Callback for when an IPv8 tick occurs (defaults to roughly every 0.5 seconds).
        """

    def get_peer_count(self) -> int:
        """
        Determine the current number of peers. This is used by IPv8 to determine whether to call this strategy.

        If ``self.overlay`` is not ``None``, we expect it to have a ``get_peers() -> list[Peer]`` method.
        """
        return 0 if self.overlay is None else len(self.overlay.get_peers())  # type: ignore[union-attr]


class RandomWalk(DiscoveryStrategy[Overlay]):
    """
    Walk randomly through the network.
    """

    def __init__(self, overlay: Overlay, timeout: float = 3.0,
                 window_size: int = 5, reset_chance: int = 50, target_interval: int = 0) -> None:
        """
        Create a new walk strategy.

        :param overlay: the Overlay to walk over
        :param timeout: the timeout (in seconds) after which peers are considered unreachable
        :param window_size: the amount of unanswered packets we can have in-flight
        :param reset_chance: the chance (0-255) to go back to the tracker
        :type reset_chance: int
        :param target_interval: the target interval (in seconds) between steps or 0 to use the default interval
        :type target_interval: int
        """
        super().__init__(overlay)
        self.intro_timeouts: dict[Address, float] = {}
        self.node_timeout = timeout
        self.window_size = window_size
        self.reset_chance = reset_chance
        self.target_interval = target_interval
        self.last_step: float = 0

    def take_step(self) -> None:
        """
        Walk to random walkable peer.
        """
        with self.walk_lock:
            # Sanitize unreachable nodes
            to_remove = [node for node in self.intro_timeouts if self.intro_timeouts[node] + self.node_timeout < time()]
            for node in to_remove:
                self.intro_timeouts.pop(node)
                if not self.overlay.network.get_verified_by_address(node):
                    self.overlay.network.remove_by_address(node)
            # Slow down the walk if a target_interval has been specified
            if self.target_interval > 0 and self.last_step + self.target_interval >= time():
                return
            # If a valid window size (>0) is specified and we are waiting for (at least) this many pings: return
            if self.window_size and self.window_size > 0 and len(self.intro_timeouts) >= self.window_size:
                return
            # Take step
            known = self.overlay.get_walkable_addresses()
            available = list(set(known) - set(self.intro_timeouts.keys()))

            # We can get stuck in an infinite loop of unreachable peers if we never contact the tracker again
            if available and randint(0, 255) >= self.reset_chance:
                peer = choice(available)
                self.overlay.walk_to(peer)
                self.intro_timeouts[peer] = time()
            else:
                self.overlay.get_new_introduction()
            self.last_step = time()


class EdgeWalk(DiscoveryStrategy[Overlay]):
    """
    Walk through the network by using edges.

    This will perform a depth-first search in the network starting from your direct neighborhood.
    When a certain depth is reached, we teleport home and start again from our neighborhood.
    """

    def __init__(self, overlay: Overlay, edge_length: int = 4, neighborhood_size: int = 6,
                 edge_timeout: float = 3.0) -> None:
        """
        Create a new edge walk instance with no known neighbors.
        """
        super().__init__(overlay)
        self._neighborhood: list[Peer] = []

        self.complete_edges: list[list[Peer]] = []
        self.under_construction: dict[Peer, list[Peer]] = {}
        self.last_edge_responses: dict[Peer, float] = {}

        self.edge_length = edge_length
        self.neighborhood_size = neighborhood_size
        self.edge_timeout = edge_timeout

    def get_available_root(self) -> Peer | None:
        """
        Get a root, if it exists, which is not busy constructing an edge for us.
        """
        available = list(set(self._neighborhood) - set(self.under_construction.keys()))
        return choice(available) if available else None

    def take_step(self) -> None:  # noqa: C901
        """
        Attempt to grow an edge.
        """
        with self.walk_lock:
            if not self._neighborhood or len(self._neighborhood) < self.neighborhood_size:
                # Wait for our immediate neighborhood to be discovered
                self._neighborhood = self.overlay.get_peers()[:self.neighborhood_size]
                self.overlay.bootstrap()
                for peer in self.overlay.get_walkable_addresses()[:self.neighborhood_size]:
                    self.overlay.walk_to(peer)
            else:
                waiting_root = self.get_available_root()
                # Make sure we have as many outstanding/actively growing edges as roots
                if waiting_root:
                    self.under_construction[waiting_root] = [waiting_root]
                    self.last_edge_responses[waiting_root] = time()
                    self.overlay.get_new_introduction(waiting_root)
                else:
                    # Check if our introduced peer has answered yet
                    completed = []
                    for root in self.under_construction:
                        last_verified = self.under_construction[root][-1]
                        introductions = []
                        for intro in self.overlay.network.get_introductions_from(last_verified):
                            verified = self.overlay.network.get_verified_by_address(intro)
                            if verified:
                                introductions.append(verified)
                            else:
                                self.overlay.walk_to(intro)
                        if introductions:
                            # We got (multiple?) introductions from this peer, add it as verified
                            self.last_edge_responses[root] = time()
                            next_in_edge = choice(introductions)
                            self.under_construction[root].append(next_in_edge)
                            if len(self.under_construction[root]) == self.edge_length:
                                # We have crawled the maximum depth, teleport home
                                self.complete_edges.append(self.under_construction[root])
                                completed.append(root)
                            else:
                                # Take this edge a step further
                                self.overlay.walk_to(next_in_edge.address)
                        elif self.last_edge_responses[root] + self.edge_timeout < time():
                            # This edge isn't growing, mark it as complete
                            if len(self.under_construction[root]) > 1:
                                self.complete_edges.append(self.under_construction[root])
                            completed.append(root)
                    for root in completed:
                        self.under_construction.pop(root)
