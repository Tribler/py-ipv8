from database import Database
from deprecated.discovery import DiscoveryCommunity
from keyvault.crypto import ECCrypto
from messaging.interfaces.udp.endpoint import UDPEndpoint
from peerdiscovery.discovery import EdgeWalk, RandomWalk
from peerdiscovery.churn import RandomChurn
from peer import Peer

from twisted.internet.task import LoopingCall


class IPV8(object):

    def __init__(self):
        self.database = None # Database('ipv8')

        self.endpoint = UDPEndpoint(8090)
        self.endpoint.open()

        self.my_peer = Peer(ECCrypto().generate_key(u"high"))

        self.discovery_overlay = DiscoveryCommunity(self.my_peer, self.endpoint, self.database)
        self.discovery_strategy = RandomWalk(self.discovery_overlay)
        self.discovery_churn_strategy = RandomChurn(self.discovery_overlay)

        self.state_machine_lc = LoopingCall(self.on_tick).start(0.5, False)

    def on_tick(self):
        if self.endpoint.is_open():
            if not self.discovery_overlay.network.get_walkable_addresses():
                self.discovery_overlay.bootstrap()
            else:
                self.discovery_strategy.take_step()
                self.discovery_churn_strategy.take_step()

if __name__ == '__main__':
    from twisted.internet import reactor
    import logging
    logging.basicConfig(level=logging.DEBUG)

    ipv8 = IPV8()

    reactor.run()
