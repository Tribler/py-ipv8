"""
This twistd plugin enables to start IPv8 headless using the twistd command.
"""
import os
import signal

from os.path import isfile

import logging
from twisted.application.service import MultiService, IServiceMaker
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.plugin import IPlugin
from twisted.python import usage
from twisted.python.log import msg
from zope.interface import implements

from ipv8.attestation.identity.community import IdentityCommunity
from ipv8.attestation.trustchain.community import TrustChainCommunity
from ipv8.attestation.wallet.community import AttestationCommunity
from ipv8.configuration import get_default_configuration
from ipv8.keyvault.crypto import ECCrypto
from ipv8.messaging.anonymization.community import TunnelCommunity
from ipv8.messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from ipv8.peer import Peer
from ipv8.peerdiscovery.churn import RandomChurn
from ipv8.peerdiscovery.deprecated.discovery import DiscoveryCommunity
from ipv8.peerdiscovery.discovery import EdgeWalk, RandomWalk
from ipv8.peerdiscovery.network import Network

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

    def stop(self):
        self.state_machine_lc.cancel()
        for strategy, _ in self.strategies:
            overlay = strategy.overlay
            overlay.unload()
        reactor.callFromThread(reactor.stop)


class Options(usage.Options):
    optParameters = []
    optFlags = []


class IPV8ServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "ipv8"
    description = "IPv8 twistd plugin, starts IPv8 as a service"
    options = Options

    def __init__(self):
        """
        Initialize the variables of the IPV8ServiceMaker and the logger.
        """
        self.ipv8 = IPV8(get_default_configuration())
        self._stopping = False

    def start_ipv8(self, options):
        """
        Main method to startup IPv8.
        """
        def signal_handler(sig, _):
            msg("Received shut down signal %s" % sig)
            if not self._stopping:
                self._stopping = True
                self.ipv8.stop()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        msg("Starting IPv8")

    def makeService(self, options):
        """
        Construct a IPv8 service.
        """
        ipv8_service = MultiService()
        ipv8_service.setName("IPv8")

        reactor.callWhenRunning(self.start_ipv8, options)

        return ipv8_service

service_maker = IPV8ServiceMaker()
