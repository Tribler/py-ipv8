from peer import Peer
from deprecated.community import Community
from .discovery_payload import PingPayload, PongPayload, SimilarityRequestPayload, SimilarityResponsePayload
from deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload

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

    def __init__(self, my_peer, endpoint, database, network):
        super(DiscoveryCommunity, self).__init__(my_peer, endpoint, database, network)

        self.decode_map.update({
            chr(1): self.on_similarity_request,
            chr(2): self.on_similarity_response,
            chr(3): self.on_ping,
            chr(4): self.on_pong
        })

        self.network.blacklist.extend(_DEFAULT_ADDRESSES)

        self.network.register_service_provider(self.master_peer.mid, self)

    def bootstrap(self):
        for socket_address in _DEFAULT_ADDRESSES:
            self.walk_to(socket_address)

    def on_similarity_request(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(SimilarityRequestPayload, data)

        packet = self.create_similarity_response(payload.identifier)
        self.endpoint.send(source_address, packet)

    def on_similarity_response(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(SimilarityResponsePayload, data)

        self.network.discover_services(Peer(auth.public_key_bin, source_address), payload.preference_list)

    def on_ping(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(PingPayload, data)

        packet = self.create_pong(payload.identifier)
        self.endpoint.send(source_address, packet)

    def on_pong(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(PongPayload, data)

    def create_similarity_request(self):
        global_time = self.claim_global_time()
        payload = SimilarityRequestPayload(global_time,
                                           self.my_estimated_lan,
                                           self.my_estimated_wan,
                                           u"unknown",
                                           self.network.service_overlays.keys()).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 1, [auth, dist, payload])

    def create_similarity_response(self, identifier):
        global_time = self.claim_global_time()
        payload = SimilarityResponsePayload(identifier, self.network.service_overlays.keys(), []).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 2, [auth, dist, payload])

    def create_ping(self):
        global_time = self.claim_global_time()
        payload = PingPayload(global_time).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 3, [dist, payload])

    def create_pong(self, identifier):
        global_time = self.claim_global_time()
        payload = PongPayload(identifier).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        return self._ez_pack(self._prefix, 4, [dist, payload])
