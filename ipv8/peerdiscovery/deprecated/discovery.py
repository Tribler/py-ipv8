from ...peer import Peer
from ...deprecated.community import Community, PacketDecodingError
from ...deprecated.payload import IntroductionRequestPayload
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .discovery_payload import PingPayload, PongPayload, SimilarityRequestPayload, SimilarityResponsePayload, \
    DiscoveryIntroductionRequestPayload
from ...messaging.serialization import PackError


class DiscoveryCommunity(Community):

    version = '\x02'
    master_peer = Peer("3081a7301006072a8648ce3d020106052b81040027038192000403b3ab059ced"
                       "9b20646ab5e01762b3595c5e8855227ae1e424cff38a1e4edee73734ff2e2e82"
                       "9eb4f39bab20d7578284fcba7251acd74e7daf96f21d01ea17077faf4d27a655"
                       "837d072baeb671287a88554e1191d8904b0dc572d09ff95f10ff092c8a5e2a01"
                       "cd500624376aec875a6e3028aab784cfaf0bac6527245db8d93900d904ac2a92"
                       "2a02716ccef5a22f7968".decode("HEX"))

    def __init__(self, my_peer, endpoint, network):
        super(DiscoveryCommunity, self).__init__(my_peer, endpoint, network)

        self.decode_map.update({
            chr(1): self.on_similarity_request,
            chr(2): self.on_similarity_response,
            chr(3): self.on_ping,
            chr(4): self.on_pong
        })

    def on_introduction_request(self, source_address, data):
        try:
            auth, dist, payload = self._ez_unpack_auth(DiscoveryIntroductionRequestPayload, data)
        except (PacketDecodingError, PackError):
            auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)

        peer = Peer(auth.public_key_bin, source_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

        introduce_to = getattr(payload, 'introduce_to', None)
        introduction = None
        if introduce_to:
            peers = self.network.verified_peers[:]
            matches = [p for p in peers if p.mid == introduce_to]
            introduction = matches[0] if matches else None
        packet = self.create_introduction_response(payload.destination_address, source_address, payload.identifier,
                                                   introduction=introduction)
        self.endpoint.send(source_address, packet)

    def on_introduction_response(self, source_address, data):
        super(DiscoveryCommunity, self).on_introduction_response(source_address, data)

        packet = self.create_similarity_request()
        self.endpoint.send(source_address, packet)

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

        return self._ez_pack(self._prefix, 3, [dist, payload], False)

    def create_pong(self, identifier):
        global_time = self.claim_global_time()
        payload = PongPayload(identifier).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        return self._ez_pack(self._prefix, 4, [dist, payload], False)
