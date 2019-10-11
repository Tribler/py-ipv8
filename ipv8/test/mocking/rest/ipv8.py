from __future__ import absolute_import

import threading

from twisted.internet.defer import DeferredList, inlineCallbacks, maybeDeferred

from .comunities import overlay_initializer
from ..endpoint import AutoMockEndpoint
from ....keyvault.crypto import ECCrypto
from ....peer import Peer
from ....peerdiscovery.discovery import RandomWalk
from ....peerdiscovery.network import Network


class TestRestIPv8(object):

    def __init__(self, crypto_curve, overlay_classes, memory_dbs=True):
        self.memory_dbs = memory_dbs
        self.endpoint = AutoMockEndpoint()
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

    def on_tick(self):
        if self.endpoint.is_open():
            with self.overlay_lock:
                for strategy, target_peers in self.strategies:
                    peer_count = len(strategy.overlay.get_peers())
                    if (target_peers == -1) or (peer_count < target_peers):
                        strategy.take_step()

    def unload_overlay(self, instance):
        with self.overlay_lock:
            self.overlays = [overlay for overlay in self.overlays if overlay != instance]
            self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                               if strategy.overlay != instance]
            return maybeDeferred(instance.unload)

    @inlineCallbacks
    def unload(self):
        with self.overlay_lock:
            unload_list = [self.unload_overlay(overlay) for overlay in self.overlays[:]]
            yield DeferredList(unload_list)
            yield self.endpoint.close()
