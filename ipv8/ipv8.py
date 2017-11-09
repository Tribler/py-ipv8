import logging
from os.path import isfile
from twisted.internet import reactor

from .attestation.identity.community import IdentityCommunity
from .attestation.trustchain.community import TrustChainCommunity
from .attestation.wallet.community import AttestationCommunity
from .peerdiscovery.deprecated.discovery import DiscoveryCommunity
from .keyvault.crypto import ECCrypto
from .messaging.anonymization.community import TunnelCommunity
from .messaging.anonymization.hidden_services import HiddenTunnelCommunity
from .messaging.interfaces.udp.endpoint import UDPEndpoint
from .peerdiscovery.discovery import EdgeWalk, RandomWalk
from .peerdiscovery.churn import RandomChurn
from .peerdiscovery.network import Network
from .peer import Peer

from twisted.internet.task import LoopingCall


_COMMUNITIES = {
    'AttestationCommunity': AttestationCommunity,
    'DiscoveryCommunity': DiscoveryCommunity,
    'HiddenTunnelCommunity': HiddenTunnelCommunity,
    'IdentityCommunity': IdentityCommunity,
    'TrustChainCommunity': TrustChainCommunity,
    'TunnelCommunity': TunnelCommunity
}


_WALKERS = {
    'EdgeWalk': EdgeWalk,
    'RandomChurn': RandomChurn,
    'RandomWalk': RandomWalk
}


class IPV8(object):

    def __init__(self, configuration):
        self.endpoint = UDPEndpoint(configuration['port'])
        self.endpoint.open()

        self.network = Network()

        # Load/generate keys
        self.keys = {}
        for key_block in configuration['keys']:
            if key_block['file'] and isfile(key_block['file']):
                with open(key_block['file'], 'r') as f:
                    self.keys[key_block['alias']] = Peer(ECCrypto().key_from_private_bin(f.read()))
            else:
                self.keys[key_block['alias']] = Peer(ECCrypto().generate_key(key_block['generation']))
                if key_block['file']:
                    with open(key_block['file'], 'w') as f:
                        f.write(self.keys[key_block['alias']].key.key_to_bin())

        # Setup logging
        logging.basicConfig(**configuration['logger'])

        self.strategies = []

        for overlay in configuration['overlays']:
            overlay_class = _COMMUNITIES[overlay['class']]
            my_peer = self.keys[overlay['key']]
            overlay_instance = overlay_class(my_peer, self.endpoint, self.network, **overlay['initialize'])
            for walker in overlay['walkers']:
                strategy_class = _WALKERS[walker['strategy']]
                args = walker['init']
                target_peers = walker['peers']
                self.strategies.append((strategy_class(overlay_instance, **args), target_peers))
            for config in overlay['on_start']:
                reactor.callWhenRunning(getattr(overlay_instance, config[0]), *config[1:])

        self.state_machine_lc = LoopingCall(self.on_tick).start(configuration['walker_interval'], False)

    def on_tick(self):
        if self.endpoint.is_open():
            if not self.network.get_walkable_addresses():
                for strategy, _ in self.strategies:
                    overlay = strategy.overlay
                    if hasattr(overlay, 'bootstrap') and callable(overlay.bootstrap):
                        overlay.bootstrap()
            else:
                for strategy, target_peers in self.strategies:
                    service = strategy.overlay.master_peer.mid
                    peer_count = len(self.network.get_peers_for_service(service))
                    if (target_peers == -1) or (peer_count < target_peers):
                        strategy.take_step(service)

    def start(self):
        reactor.run()

    def stop(self):
        reactor.callFromThread(reactor.stop)

if __name__ == '__main__':
    from .configuration import get_default_configuration
    IPV8(get_default_configuration()).start()
