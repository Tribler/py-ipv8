import logging
from os.path import isfile
import sys
from threading import RLock

from twisted.internet import reactor
from twisted.internet.defer import DeferredList, inlineCallbacks, maybeDeferred
from twisted.internet.task import LoopingCall

from ipv8.messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ipv8.attestation.identity.community import IdentityCommunity
from ipv8.attestation.trustchain.community import TrustChainCommunity, TrustChainTestnetCommunity
from ipv8.attestation.wallet.community import AttestationCommunity
from ipv8.keyvault.crypto import ECCrypto
from ipv8.keyvault.private.m2crypto import M2CryptoSK
from ipv8.messaging.anonymization.community import TunnelCommunity
from ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.peer import Peer
from ipv8.peerdiscovery.churn import RandomChurn
from ipv8.peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk
from ipv8.peerdiscovery.network import Network
from ipv8.dht.discovery import DHTDiscoveryCommunity


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
    'RandomChurn': RandomChurn,
    'RandomWalk': RandomWalk
}


class IPv8(object):

    def __init__(self, configuration, endpoint_override=None, enable_statistics=False):
        if endpoint_override:
            self.endpoint = endpoint_override
        else:
            self.endpoint = UDPEndpoint(port=configuration['port'], ip=configuration['address'])
            self.endpoint.open()
            if enable_statistics:
                self.endpoint = StatisticsEndpoint(self, self.endpoint)

        self.network = Network()

        # Load/generate keys
        self.keys = {}
        for key_block in configuration['keys']:
            if key_block['file'] and isfile(key_block['file']):
                with open(key_block['file'], 'r') as f:
                    content = f.read()
                    try:
                        # IPv8 Standardized bin format
                        self.keys[key_block['alias']] = Peer(ECCrypto().key_from_private_bin(content))
                    except ValueError:
                        try:
                            # Try old Tribler M2Crypto PEM format
                            content = content[31:-30].replace('\n','').decode("BASE64")
                            peer = Peer(M2CryptoSK(keystring=content))
                            peer.mid # This will error out if the keystring is not M2Crypto
                            self.keys[key_block['alias']] = peer
                        except:
                            # Try old LibNacl format
                            content = "LibNaCLSK:" + content
                            self.keys[key_block['alias']] = Peer(ECCrypto().key_from_private_bin(content))
            else:
                self.keys[key_block['alias']] = Peer(ECCrypto().generate_key(key_block['generation']))
                if key_block['file']:
                    with open(key_block['file'], 'w') as f:
                        f.write(self.keys[key_block['alias']].key.key_to_bin())

        # Setup logging
        logging.basicConfig(**configuration['logger'])

        self.overlay_lock = RLock()
        self.strategies = []
        self.overlays = []

        for overlay in configuration['overlays']:
            overlay_class = _COMMUNITIES[overlay['class']]
            my_peer = self.keys[overlay['key']]
            overlay_instance = overlay_class(my_peer, self.endpoint, self.network, **overlay['initialize'])
            self.overlays.append(overlay_instance)
            for walker in overlay['walkers']:
                strategy_class = _WALKERS[walker['strategy']]
                args = walker['init']
                target_peers = walker['peers']
                self.strategies.append((strategy_class(overlay_instance, **args), target_peers))
            for config in overlay['on_start']:
                reactor.callWhenRunning(getattr(overlay_instance, config[0]), *config[1:])

        self.state_machine_lc = LoopingCall(self.on_tick)
        self.state_machine_lc.start(configuration['walker_interval'], False)

    def on_tick(self):
        if self.endpoint.is_open():
            with self.overlay_lock:
                for strategy, target_peers in self.strategies:
                    service = strategy.overlay.master_peer.mid
                    peer_count = len(self.network.get_peers_for_service(service))
                    if (target_peers == -1) or (peer_count < target_peers):
                        strategy.take_step(service)

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
