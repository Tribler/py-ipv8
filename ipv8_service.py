from __future__ import absolute_import
from __future__ import division

import logging
import sys
import time
from base64 import b64decode
from os.path import isfile
from threading import RLock
from traceback import format_exception

from twisted.internet import reactor
from twisted.internet.defer import DeferredList, inlineCallbacks, maybeDeferred
from twisted.internet.task import LoopingCall, deferLater

if hasattr(sys.modules['__main__'], "IPv8"):
    sys.modules[__name__] = sys.modules['__main__']
else:
    if __name__ == '__main__' or __name__ == 'ipv8_service':
        from ipv8.messaging.interfaces.statistics_endpoint import StatisticsEndpoint
        from ipv8.attestation.identity.community import IdentityCommunity
        from ipv8.attestation.trustchain.community import TrustChainCommunity, TrustChainTestnetCommunity
        from ipv8.attestation.wallet.community import AttestationCommunity
        from ipv8.keyvault.crypto import default_eccrypto
        from ipv8.keyvault.private.m2crypto import M2CryptoSK
        from ipv8.messaging.anonymization.community import TunnelCommunity
        from ipv8.messaging.anonymization.endpoint import TunnelEndpoint
        from ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
        from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
        from ipv8.peer import Peer
        from ipv8.peerdiscovery.community import DiscoveryCommunity
        from ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk
        from ipv8.peerdiscovery.network import Network
        from ipv8.dht.discovery import DHTDiscoveryCommunity
    else:
        from .ipv8.messaging.interfaces.statistics_endpoint import StatisticsEndpoint
        from .ipv8.attestation.identity.community import IdentityCommunity
        from .ipv8.attestation.trustchain.community import TrustChainCommunity, TrustChainTestnetCommunity
        from .ipv8.attestation.wallet.community import AttestationCommunity
        from .ipv8.keyvault.crypto import default_eccrypto
        from .ipv8.keyvault.private.m2crypto import M2CryptoSK
        from .ipv8.messaging.anonymization.community import TunnelCommunity
        from .ipv8.messaging.anonymization.endpoint import TunnelEndpoint
        from .ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
        from .ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
        from .ipv8.peer import Peer
        from .ipv8.peerdiscovery.community import DiscoveryCommunity
        from .ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk
        from .ipv8.peerdiscovery.network import Network
        from .ipv8.dht.discovery import DHTDiscoveryCommunity

    _COMMUNITIES = {
        'AttestationCommunity': AttestationCommunity,
        'DiscoveryCommunity': DiscoveryCommunity,
        'HiddenTunnelCommunity': HiddenTunnelCommunity,
        'IdentityCommunity': IdentityCommunity,
        'TrustChainCommunity': TrustChainCommunity,
        'TunnelCommunity': TunnelCommunity,
        'DHTDiscoveryCommunity': DHTDiscoveryCommunity,
        'TrustChainTestnetCommunity': TrustChainTestnetCommunity,
    }

    _WALKERS = {
        'EdgeWalk': EdgeWalk,
        'RandomWalk': RandomWalk
    }

    class IPv8(object):

        def __init__(self, configuration, endpoint_override=None, enable_statistics=False, extra_communities=None):
            if endpoint_override:
                self.endpoint = endpoint_override
            else:
                self.endpoint = UDPEndpoint(port=configuration['port'], ip=configuration['address'])
                self.endpoint.open()
                if enable_statistics:
                    self.endpoint = StatisticsEndpoint(self, self.endpoint)
                if any([overlay.get('initialize', {}).get('anonymize') for overlay in configuration['overlays']]):
                    self.endpoint = TunnelEndpoint(self.endpoint)

            self.network = Network()

            # Load/generate keys
            self.keys = {}
            for key_block in configuration['keys']:
                if key_block['file'] and isfile(key_block['file']):
                    with open(key_block['file'], 'rb') as f:
                        content = f.read()
                        try:
                            # IPv8 Standardized bin format
                            self.keys[key_block['alias']] = Peer(default_eccrypto.key_from_private_bin(content))
                        except ValueError:
                            try:
                                # Try old Tribler M2Crypto PEM format
                                content = b64decode(content[31:-30].replace('\n', ''))
                                peer = Peer(M2CryptoSK(keystring=content))
                                peer.mid  # This will error out if the keystring is not M2Crypto
                                self.keys[key_block['alias']] = peer
                            except:
                                # Try old LibNacl format
                                content = "LibNaCLSK:" + content
                                self.keys[key_block['alias']] = Peer(default_eccrypto.key_from_private_bin(content))
                else:
                    self.keys[key_block['alias']] = Peer(default_eccrypto.generate_key(key_block['generation']))
                    if key_block['file']:
                        with open(key_block['file'], 'wb') as f:
                            f.write(self.keys[key_block['alias']].key.key_to_bin())

            # Setup logging
            logging.basicConfig(**configuration['logger'])

            self.overlay_lock = RLock()
            self.strategies = []
            self.overlays = []

            for overlay in configuration['overlays']:
                overlay_class = _COMMUNITIES.get(overlay['class'], (extra_communities or {}).get(overlay['class']))
                my_peer = self.keys[overlay['key']]
                overlay_instance = overlay_class(my_peer, self.endpoint, self.network, **overlay['initialize'])
                self.overlays.append(overlay_instance)
                for walker in overlay['walkers']:
                    strategy_class = _WALKERS.get(walker['strategy'],
                                                  overlay_instance.get_available_strategies().get(walker['strategy']))
                    args = walker['init']
                    target_peers = walker['peers']
                    self.strategies.append((strategy_class(overlay_instance, **args), target_peers))
                for config in overlay['on_start']:
                    reactor.callWhenRunning(getattr(overlay_instance, config[0]), *config[1:])

            self.state_machine_lc = LoopingCall(self.on_tick)
            self.state_machine_lc.start(configuration['walker_interval'], False)

        @inlineCallbacks
        def on_tick(self):
            if self.endpoint.is_open():
                with self.overlay_lock:
                    smooth = self.state_machine_lc.interval / len(self.strategies) if self.strategies else 0
                    ticker = len(self.strategies)
                    for strategy, target_peers in self.strategies:
                        peer_count = len(strategy.overlay.get_peers())
                        start_time = time.time()
                        if (target_peers == -1) or (peer_count < target_peers):
                            # We wrap the take_step into a general except as it is prone to programmer error.
                            try:
                                strategy.take_step()
                            except:
                                logging.error("Exception occurred while trying to walk!\n"
                                              + ''.join(format_exception(*sys.exc_info())))
                        ticker -= 1 if ticker else 0
                        sleep_time = smooth - (time.time() - start_time)
                        if ticker and sleep_time > 0.01:
                            yield deferLater(reactor, sleep_time, lambda: None)
                        if not self.state_machine_lc.running:
                            # By yielding, we might have been stopped.
                            # In that case, exit out of the loop.
                            break

        def unload_overlay(self, instance):
            with self.overlay_lock:
                self.overlays = [overlay for overlay in self.overlays if overlay != instance]
                self.strategies = [(strategy, target_peers) for (strategy, target_peers) in self.strategies
                                   if strategy.overlay != instance]
                return maybeDeferred(instance.unload)

        @inlineCallbacks
        def stop(self, stop_reactor=True):
            self.state_machine_lc.stop()
            with self.overlay_lock:
                unload_list = [self.unload_overlay(overlay) for overlay in self.overlays[:]]
                yield DeferredList(unload_list)
                yield self.endpoint.close()
            if stop_reactor:
                reactor.callFromThread(reactor.stop)


if __name__ == '__main__':
    from twisted.plugins.ipv8_plugin import Options, service_maker

    options = Options()
    Options.parseOptions(options, sys.argv[1:])
    service_maker.makeService(options)
    reactor.run()
