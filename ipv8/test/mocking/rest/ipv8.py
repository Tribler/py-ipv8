from __future__ import absolute_import

import threading

from twisted.internet.task import LoopingCall

from .comunities import TestIdentityCommunity, TestAttestationCommunity, overlay_initializer
from ....keyvault.crypto import ECCrypto
from ....messaging.interfaces.udp.endpoint import UDPEndpoint
from ....peer import Peer
from ....peerdiscovery.discovery import RandomWalk
from ....peerdiscovery.network import Network


class TestRestIPv8(object):

    def __init__(self, crypto_curve, port, interface, overlay_classes, memory_dbs=True):
        self.memory_dbs = memory_dbs
        self.endpoint = UDPEndpoint(port=port, ip=interface)
        self.endpoint.open()

        self.network = Network()

        my_peer = Peer(ECCrypto().generate_key(crypto_curve))
        self.keys = {'my_peer': my_peer}

        database_working_dir = u":memory:" if memory_dbs else u""
        self.overlays = []

        for overlay_class in overlay_classes:
            self.overlays.append(overlay_initializer(overlay_class, my_peer, self.endpoint, self.network,
                                                     working_directory=database_working_dir))

        self.strategies = [
            (RandomWalk(overlay), 20) for overlay in self.overlays
        ]

        self.overlay_lock = threading.RLock()
        self.state_machine_lc = LoopingCall(self.on_tick)
        self.state_machine_lc.start(0.5, False)

    def on_tick(self):
        if self.endpoint.is_open():
            with self.overlay_lock:
                for strategy, target_peers in self.strategies:
                    peer_count = len(strategy.overlay.get_peers())
                    if (target_peers == -1) or (peer_count < target_peers):
                        strategy.take_step()

    def unload(self):
        # Make sure the state machine is running before closing it
        if self.state_machine_lc.running:
            self.state_machine_lc.stop()

        if self.endpoint.is_open():
            self.endpoint.close()

        for overlay in self.overlays:
            # Close the DBs since simply unloading will usually not do
            if isinstance(overlay, TestAttestationCommunity):
                overlay.database.close()
            elif isinstance(overlay, TestIdentityCommunity):
                overlay.persistence.close()
            # Clear the cache manually
            overlay.request_cache.clear()
            overlay.unload()
