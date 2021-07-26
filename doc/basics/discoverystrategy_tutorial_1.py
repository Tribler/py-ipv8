from os import urandom
from random import choice

from pyipv8.ipv8.community import Community
from pyipv8.ipv8.peerdiscovery.discovery import DiscoveryStrategy
from pyipv8.ipv8.types import IPv8


class MyCommunity(Community):
    community_id = urandom(20)


class MyDiscoveryStrategy(DiscoveryStrategy):

    def take_step(self):
        with self.walk_lock:
            # Insert your logic here. For example:
            if self.overlay.get_peers():
                peer = choice(self.overlay.get_peers())
                self.overlay.send_introduction_request(peer)


def main(ipv8_instance: IPv8):
    overlay = ipv8_instance.get_overlay(MyCommunity)
    target_peers = -1
    ipv8_instance.add_strategy(overlay,
                               MyDiscoveryStrategy(overlay),
                               target_peers)
