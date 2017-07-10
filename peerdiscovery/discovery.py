import abc

from random import choice


class DiscoveryStrategy(object):
    """
    Strategy for discovering peers in a network.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, overlay):
        self.overlay = overlay

    @abc.abstractmethod
    def take_step(self):
        pass


class RandomWalk(DiscoveryStrategy):
    """
    Walk randomly through the network.
    """

    def take_step(self):
        """
        Walk to random walkable peer.
        """
        known = self.overlay.network.get_walkable_addresses()

        if known:
            self.overlay.walk_to(choice(known))
        else:
            self.overlay.get_new_introduction()
