from __future__ import annotations

import logging
import sys
import time
from asyncio import CancelledError, ensure_future, gather, run, sleep
from base64 import b64decode
from contextlib import suppress
from os.path import isfile
from threading import RLock
from traceback import format_exception
from typing import Any, Awaitable, Generator

if hasattr(sys.modules['__main__'], "IPv8"):
    sys.modules[__name__] = sys.modules['__main__']
else:
    if __name__ == '__main__' or __name__ == 'ipv8_service':  # noqa: PLR1714
        from ipv8.messaging.interfaces.statistics_endpoint import StatisticsEndpoint  # noqa: I001
        from ipv8.attestation.identity.community import IdentityCommunity
        from ipv8.attestation.wallet.community import AttestationCommunity
        from ipv8.bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
        from ipv8.bootstrapping.udpbroadcast.bootstrapper import UDPBroadcastBootstrapper
        from ipv8.keyvault.crypto import default_eccrypto as crypto
        from ipv8.messaging.anonymization.community import TunnelCommunity
        from ipv8.messaging.anonymization.endpoint import TunnelEndpoint
        from ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
        from ipv8.messaging.interfaces.dispatcher.endpoint import DispatcherEndpoint
        from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
        from ipv8.peer import Peer
        from ipv8.peerdiscovery.community import DiscoveryCommunity
        from ipv8.peerdiscovery.discovery import DiscoveryStrategy, EdgeWalk, RandomWalk
        from ipv8.peerdiscovery.network import Network
        from ipv8.dht.discovery import DHTDiscoveryCommunity
        from ipv8.types import Endpoint, Overlay
        from ipv8.util import maybe_coroutine
    else:
        from .ipv8.messaging.interfaces.statistics_endpoint import StatisticsEndpoint  # noqa: I001
        from .ipv8.attestation.identity.community import IdentityCommunity
        from .ipv8.attestation.wallet.community import AttestationCommunity
        from .ipv8.bootstrapping.dispersy.bootstrapper import DispersyBootstrapper
        from .ipv8.bootstrapping.udpbroadcast.bootstrapper import UDPBroadcastBootstrapper
        from .ipv8.keyvault.crypto import default_eccrypto as crypto
        from .ipv8.messaging.anonymization.community import TunnelCommunity
        from .ipv8.messaging.anonymization.endpoint import TunnelEndpoint
        from .ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
        from .ipv8.messaging.interfaces.dispatcher.endpoint import DispatcherEndpoint
        from .ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
        from .ipv8.peer import Peer
        from .ipv8.peerdiscovery.community import DiscoveryCommunity
        from .ipv8.peerdiscovery.discovery import DiscoveryStrategy, EdgeWalk, RandomWalk
        from .ipv8.peerdiscovery.network import Network
        from .ipv8.dht.discovery import DHTDiscoveryCommunity
        from .ipv8.types import Endpoint, Overlay  # noqa: TCH001
        from .ipv8.util import maybe_coroutine

    _COMMUNITIES = {
        'AttestationCommunity': AttestationCommunity,
        'DiscoveryCommunity': DiscoveryCommunity,
        'HiddenTunnelCommunity': HiddenTunnelCommunity,
        'IdentityCommunity': IdentityCommunity,
        'TunnelCommunity': TunnelCommunity,
        'DHTDiscoveryCommunity': DHTDiscoveryCommunity,
    }

    _WALKERS = {
        'EdgeWalk': EdgeWalk,
        'RandomWalk': RandomWalk
    }

    _BOOTSTRAPPERS = {
        'DispersyBootstrapper': DispersyBootstrapper,
        'UDPBroadcastBootstrapper': UDPBroadcastBootstrapper
    }

    class IPv8:
        """
        The main IPv8 controller that reads configurations and makes components.
        """

        def __init__(self,  # noqa: C901, PLR0912
                     configuration: dict[str, Any],
                     endpoint_override: Endpoint | None = None,
                     enable_statistics: bool = False,
                     extra_communities: dict[str, type[Overlay]] | None = None) -> None:
            """
            Create a new IPv8 instance, that is yet unstarted.
            """
            super().__init__()
            self.configuration = configuration

            # Setup logging
            logging.basicConfig(**configuration['logger'])

            if endpoint_override:
                self.endpoint = endpoint_override
            else:
                if 'address' in configuration or 'port' in configuration:
                    logging.warning("Using deprecated 'address' and 'port' configuration! "
                                    "Auto-porting your config to \"UDPIPv4\" interface configuration. "
                                    "Switch your code to IPv8 configuration using 'interfaces' instead.")
                    if 'interfaces' not in configuration:
                        configuration['interfaces'] = []
                    configuration['interfaces'].append({'interface': "UDPIPv4",
                                                        'ip': configuration.get('address', "0.0.0.0"),
                                                        'port': configuration.get('port', 8090)})
                endpoint_specs = (spec.copy() for spec in configuration['interfaces'])
                endpoint_args = {spec.pop('interface'): spec for spec in endpoint_specs}
                self.endpoint = DispatcherEndpoint(list(endpoint_args.keys()), **endpoint_args)

            if enable_statistics:
                self.endpoint = StatisticsEndpoint(self.endpoint)
            if any(overlay.get('initialize', {}).get('anonymize') for overlay in configuration['overlays']):
                self.endpoint = TunnelEndpoint(self.endpoint)

            self.network = Network()

            # Load/generate keys
            self.keys = {}
            for key_block in configuration['keys']:
                if key_block['file'] and isfile(key_block['file']):
                    with open(key_block['file'], 'rb') as f:
                        self.keys[key_block['alias']] = Peer(crypto.key_from_private_bin(f.read()))
                else:
                    self.keys[key_block['alias']] = Peer(crypto.key_from_private_bin(b64decode(key_block['bin']))
                                                         if 'bin' in key_block else
                                                         crypto.generate_key(key_block['generation']))
                    if key_block['file']:
                        with open(key_block['file'], 'wb') as f:
                            f.write(self.keys[key_block['alias']].key.key_to_bin())

            self.overlay_lock = RLock()
            self.strategies: list[tuple[DiscoveryStrategy, int]] = []
            self.overlays: list[Overlay] = []
            self.on_start = []

            for overlay in configuration['overlays']:
                overlay_class = _COMMUNITIES.get(overlay['class'], (extra_communities or {}).get(overlay['class']))
                my_peer = self.keys[overlay['key']]
                settings = overlay_class.settings_class(my_peer=my_peer, endpoint=self.endpoint, network=self.network)
                for k, v in overlay['initialize'].items():
                    setattr(settings, k, v)
                overlay_instance = overlay_class(settings)
                self.overlays.append(overlay_instance)
                for walker in overlay['walkers']:
                    strategy_class: type[DiscoveryStrategy]
                    strategy_class = _WALKERS.get(walker['strategy'],
                                                  overlay_instance.get_available_strategies().get(walker['strategy']))
                    args = walker['init']
                    target_peers = walker['peers']
                    self.strategies.append((strategy_class(overlay_instance, **args), target_peers))
                for config in overlay['on_start']:
                    self.on_start.append((getattr(overlay_instance, config[0]), config[1:]))
                for bootstrapper in overlay['bootstrappers']:
                    bootstrapper_class = _BOOTSTRAPPERS.get(bootstrapper['class'])
                    if bootstrapper_class:
                        overlay_instance.bootstrappers.append(bootstrapper_class(**bootstrapper['init']))
            self.walk_interval = configuration['walker_interval']
            self.state_machine_task = None

        async def start(self) -> None:
            """
            Open the IPv8 endpoint and schedule asyncio (possibly periodic) tasks.
            """
            await self.endpoint.open()

            await gather(*(ensure_future(maybe_coroutine(func, *args)) for func, args in self.on_start))

            async def ticker() -> None:
                while True:
                    await self.on_tick()
                    await sleep(0.0)
            self.state_machine_task = ensure_future(ticker())

        async def on_tick(self) -> None:
            """
            The main IPv8 asyncio loop that schedules all registered strategies.
            """
            if self.endpoint.is_open():
                with self.overlay_lock:
                    smooth = self.walk_interval // len(self.strategies) if self.strategies else 0
                    ticker = len(self.strategies)
                    for strategy, target_peers in self.strategies:
                        start_time = time.time()
                        try:
                            # We wrap the take_step into a general except as it is prone to programmer error.
                            # Even ``get_peers()`` may fail (https://github.com/Tribler/py-ipv8/issues/1136).
                            if (target_peers == -1) or (strategy.get_peer_count() < target_peers):
                                strategy.take_step()
                        except Exception:
                            logging.exception("Exception occurred while trying to walk!\n%s,"
                                              ''.join(format_exception(*sys.exc_info())))
                        ticker -= 1 if ticker else 0
                        sleep_time = smooth - (time.time() - start_time)
                        if ticker and sleep_time > 0.01:
                            await sleep(sleep_time)
                        if self.state_machine_task.done():
                            # By awaiting, we might have been stopped.
                            # In that case, exit out of the loop.
                            break
                    else:
                        await sleep(self.walk_interval)

        def add_strategy(self, overlay: Overlay, strategy: DiscoveryStrategy, target_peers: int) -> None:
            """
            Register a strategy to call every tick unless a target number of peers has been reached.
            If the ``target_peers`` is equal to ``-1``, the strategy is always called.
            """
            with self.overlay_lock:
                if overlay not in self.overlays:
                    self.overlays.append(overlay)
                self.strategies.append((strategy, target_peers))

        def unload_overlay(self, instance: Overlay) -> Awaitable:
            """
            Unregister and unload a given overlay instance.
            """
            with self.overlay_lock:
                self.overlays = [overlay for overlay in self.overlays if overlay != instance]
                self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                                   if strategy.overlay != instance]
                return maybe_coroutine(instance.unload)

        def get_overlay(self, overlay_cls: type[Overlay]) -> Overlay | None:
            """
            Get any loaded overlay instance from a given class type, if it exists.
            """
            return next(self.get_overlays(overlay_cls), None)

        def get_overlays(self, overlay_cls: type[Overlay]) -> Generator[Overlay]:
            """
            Get all loaded overlay instances from a given class type.
            """
            return (o for o in self.overlays if isinstance(o, overlay_cls))

        async def produce_anonymized_endpoint(self) -> TunnelEndpoint:
            """
            Create an endpoint that CAN pass data through a ``TunnelCommunity``.
            Note that a ``TunnelCommunity`` must still be registered with this endpoint.
            """
            address = self.configuration.get('address', "0.0.0.0")
            for spec in self.configuration.get('interfaces', []):
                if spec['interface'] == "UDPIPv4":
                    address = spec['ip']
            base_endpoint = UDPEndpoint(port=0, ip=address)
            await base_endpoint.open()
            return TunnelEndpoint(base_endpoint)

        async def stop(self) -> None:
            """
            Stop all registered IPv8 strategies, unload all registered overlays and close the endpoint.
            """
            if self.state_machine_task:
                self.state_machine_task.cancel()
                with suppress(CancelledError):
                    await self.state_machine_task
            with self.overlay_lock:
                unload_list = [self.unload_overlay(overlay) for overlay in self.overlays[:]]
                await gather(*unload_list)
                await maybe_coroutine(self.endpoint.close)


if __name__ == '__main__':
    from scripts.ipv8_plugin import main
    run(main(sys.argv[1:]))
