from random import choice
from keyvault.crypto import ECCrypto
from messaging.interfaces.udp.endpoint import UDPEndpoint
from peer import Peer
from .community import Community
from .discovery_payload import SimilarityRequestPayload

from twisted.internet.task import LoopingCall

_DEFAULT_ADDRESSES = [
    ("130.161.119.206", 6421),
    ("130.161.119.206", 6422),
    ("131.180.27.155", 6423),
    ("83.149.70.6", 6424),
    ("95.211.155.142", 6427),
    ("95.211.155.131", 6428),
]


class DiscoveryCommunity(Community):

    version = '\x02'
    master_peer = Peer("3081a7301006072a8648ce3d020106052b81040027038192000403b3ab059ced"
                       "9b20646ab5e01762b3595c5e8855227ae1e424cff38a1e4edee73734ff2e2e82"
                       "9eb4f39bab20d7578284fcba7251acd74e7daf96f21d01ea17077faf4d27a655"
                       "837d072baeb671287a88554e1191d8904b0dc572d09ff95f10ff092c8a5e2a01"
                       "cd500624376aec875a6e3028aab784cfaf0bac6527245db8d93900d904ac2a92"
                       "2a02716ccef5a22f7968".decode("HEX"))

    def __init__(self, my_peer, endpoint, database):
        super(DiscoveryCommunity, self).__init__(my_peer, endpoint, database)

        self.register_task("walk_random_branch", LoopingCall(self.walk_random_branch)).start(1.0, False)

        self.decode_map.update({
            chr(1): self.on_similarity_request
        })

    def walk_random_branch(self):
        peer = choice(self.contacted_addresses)
        self.send_introduction_request(peer, True)

    def bootstrap(self):
        for socket_address in _DEFAULT_ADDRESSES:
            self.send_introduction_request(socket_address)

    def on_similarity_request(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(SimilarityRequestPayload, data)


if __name__ == '__main__':
    from twisted.internet import reactor
    import logging

    logging.basicConfig(level=logging.DEBUG)

    my_peer = Peer(ECCrypto().generate_key(u"high"))

    endpoint = UDPEndpoint(8090)
    endpoint.open()

    def wait_for_ep(endpoint):
        while not endpoint._running:
            import time
            time.sleep(1)
        community = DiscoveryCommunity(my_peer, endpoint, None)
        community.bootstrap()

    reactor.callLater(1.0, wait_for_ep, endpoint)
    reactor.run()
