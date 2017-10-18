from .peerdiscovery.deprecated.discovery import DiscoveryCommunity
from .keyvault.crypto import ECCrypto
from .messaging.anonymization.community import TunnelCommunity
from .messaging.interfaces.udp.endpoint import UDPEndpoint
from .peerdiscovery.discovery import EdgeWalk, RandomWalk
from .peerdiscovery.churn import RandomChurn
from .peerdiscovery.network import Network
from .peer import Peer

from twisted.internet.task import LoopingCall


class IPV8(object):

    def __init__(self):
        self.endpoint = UDPEndpoint(8090)
        self.endpoint.open()

        self.network = Network()

        self.my_peer = Peer(ECCrypto().generate_key(u"high"))
        self.my_anonymous_id = Peer(ECCrypto().generate_key(u"curve25519"))

        self.discovery_overlay = DiscoveryCommunity(self.my_peer, self.endpoint, self.network)
        self.discovery_strategy = RandomWalk(self.discovery_overlay)
        self.discovery_churn_strategy = RandomChurn(self.discovery_overlay)

        self.anonymization_overlay = TunnelCommunity(self.my_anonymous_id, self.endpoint, self.network)
        self.anonymization_strategy = RandomWalk(self.anonymization_overlay)
        self.anonymization_overlay.build_tunnels(1)

        self.state_machine_lc = LoopingCall(self.on_tick).start(0.5, False)

    def on_tick(self):
        if self.endpoint.is_open():
            if not self.discovery_overlay.network.get_walkable_addresses():
                self.discovery_overlay.bootstrap()
            else:
                self.discovery_strategy.take_step()
                self.discovery_churn_strategy.take_step()
                # TunnelCommunity overwrites intro. req./resp.
                self.anonymization_strategy.take_step()

if __name__ == '__main__':
    from twisted.internet import reactor
    import logging
    logging.basicConfig(level=logging.INFO)

    ipv8 = IPV8()

    reactor.run()
