import threading
from asyncio import CancelledError, ensure_future, gather, sleep
from contextlib import suppress

from .comunities import overlay_initializer
from ..endpoint import AutoMockEndpoint
from ....keyvault.crypto import ECCrypto
from ....peer import Peer
from ....peerdiscovery.discovery import RandomWalk
from ....peerdiscovery.network import Network
from ....util import maybe_coroutine


class TestRestIPv8(object):

    def __init__(self, crypto_curve, overlay_classes, memory_dbs=True):
        self.memory_dbs = memory_dbs
        self.endpoint = AutoMockEndpoint()

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
        self.state_machine_task = ensure_future(self.ticker())

    async def ticker(self):
        self.endpoint.open()
        while True:
            self.on_tick()
            await sleep(0.5)

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
            return maybe_coroutine(instance.unload)

    async def unload(self):
        with self.overlay_lock:
            unload_list = [self.unload_overlay(overlay) for overlay in self.overlays[:]]
            await gather(*unload_list)
            self.endpoint.close()

        if self.state_machine_task:
            self.state_machine_task.cancel()
            with suppress(CancelledError):
                await self.state_machine_task
