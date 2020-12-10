from binascii import unhexlify
from random import sample
from time import time

from .churn import DiscoveryStrategy, RandomChurn
from .payload import (DiscoveryIntroductionRequestPayload, PingPayload, PongPayload, SimilarityRequestPayload,
                      SimilarityResponsePayload)
from ..community import Community, DEFAULT_MAX_PEERS
from ..keyvault.crypto import default_eccrypto
from ..lazy_community import PacketDecodingError, lazy_wrapper, lazy_wrapper_unsigned, retrieve_cache
from ..messaging.payload import IntroductionRequestPayload
from ..messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ..messaging.serialization import PackError
from ..peer import Peer
from ..requestcache import NumberCache, RequestCache


class PeriodicSimilarity(DiscoveryStrategy):

    def __init__(self, overlay):
        super(PeriodicSimilarity, self).__init__(overlay)
        self.last_step = 0

    def take_step(self):
        now = time()
        if (now - self.last_step < 1.0) or not self.overlay.network.verified_peers:
            return
        self.last_step = now
        with self.walk_lock:
            self.overlay.send_similarity_request(sample(self.overlay.network.verified_peers, 1)[0].address)


class PingRequestCache(NumberCache):

    name = "discoverypingcache"

    def __init__(self, request_cache, identifier, peer, start_time):
        super().__init__(request_cache, PingRequestCache.name, identifier)
        self.peer = peer
        self.start_time = start_time

    def finish(self):
        self.peer.pings.append(time() - self.start_time)

    @property
    def timeout_delay(self):
        return 5.0

    def on_timeout(self):
        pass


class DiscoveryCommunity(Community):

    version = b'\x02'
    community_id = unhexlify('7e313685c1912a141279f8248fc8db5899c5df5a')

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False):
        super(DiscoveryCommunity, self).__init__(my_peer, endpoint, network, max_peers=max_peers, anonymize=anonymize)

        self.request_cache = RequestCache()

        self.add_message_handler(SimilarityRequestPayload, self.on_similarity_request)
        self.add_message_handler(SimilarityResponsePayload, self.on_similarity_response)
        self.add_message_handler(PingPayload, self.on_ping)
        self.add_message_handler(PongPayload, self.on_pong)

    def get_available_strategies(self):
        return {'PeriodicSimilarity': PeriodicSimilarity, 'RandomChurn': RandomChurn}

    async def unload(self):
        await self.request_cache.shutdown()
        await super(DiscoveryCommunity, self).unload()

    def on_old_introduction_request(self, source_address, data):
        if self.max_peers >= 0 and len(self.get_peers()) > self.max_peers:
            self.logger.debug("Dropping introduction request from (%s, %d): too many peers!",
                              source_address[0], source_address[1])
            return

        try:
            auth, dist, payload = self._ez_unpack_auth(DiscoveryIntroductionRequestPayload, data)
        except (PacketDecodingError, PackError):
            auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)

        peer = Peer(auth.public_key_bin, source_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.community_id, ])

        introduce_to = getattr(payload, 'introduce_to', None)
        introduction = None
        if introduce_to:
            peers = self.network.verified_peers
            matches = [p for p in peers if p.mid == introduce_to]
            introduction = matches[0] if matches else None
        packet = self.create_introduction_response(payload.destination_address, source_address, payload.identifier,
                                                   introduction=introduction, new_style=False)
        self.endpoint.send(source_address, packet)

    def introduction_response_callback(self, peer, dist, payload):
        self.send_similarity_request(peer.address)

    def send_similarity_request(self, address):
        my_peer_set = set([overlay.my_peer for overlay in self.network.service_overlays.values()])
        for peer in my_peer_set:
            packet = self.create_similarity_request(peer)
            self.endpoint.send(address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, SimilarityRequestPayload)
    def on_similarity_request(self, node, dist, payload):
        self.network.discover_services(node, payload.preference_list)

        my_peer_set = set([overlay.my_peer for overlay in self.network.service_overlays.values()])
        for peer in my_peer_set:
            packet = self.create_similarity_response(payload.identifier, peer)
            self.endpoint.send(node.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, SimilarityResponsePayload)
    def on_similarity_response(self, node, dist, payload):
        if self.max_peers >= 0 and len(self.get_peers()) > self.max_peers and node not in self.network.verified_peers:
            self.logger.debug("Dropping similarity response from (%s, %d): too many peers!",
                              node.address[0], node.address[1])
            return

        self.network.add_verified_peer(node)
        self.network.discover_services(node, payload.preference_list)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PingPayload)
    def on_ping(self, source_address, dist, payload):
        packet = self.create_pong(payload.identifier)
        self.endpoint.send(source_address, packet)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PongPayload)
    @retrieve_cache(PingRequestCache)
    def on_pong(self, source_address, dist, payload, cache):
        cache.finish()

    def get_my_overlays(self, peer):
        return [service_id for service_id, overlay in self.network.service_overlays.items()
                if overlay.my_peer == peer]

    def custom_pack(self, peer, msg_num, payloads):
        packet = self._prefix + bytes([msg_num])
        packet += self.serializer.pack_serializable_list(payloads)
        packet += default_eccrypto.create_signature(peer.key, packet)
        return packet

    def create_similarity_request(self, peer):
        global_time = self.claim_global_time()
        payload = SimilarityRequestPayload(global_time,
                                           self.my_estimated_lan,
                                           self.my_estimated_wan,
                                           u"unknown",
                                           self.get_my_overlays(peer))
        auth = BinMemberAuthenticationPayload(peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self.custom_pack(peer, 1, [auth, dist, payload])

    def create_similarity_response(self, identifier, peer):
        global_time = self.claim_global_time()
        payload = SimilarityResponsePayload(identifier, self.get_my_overlays(peer), [])
        auth = BinMemberAuthenticationPayload(peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self.custom_pack(peer, 2, [auth, dist, payload])

    def send_ping(self, peer):
        global_time = self.claim_global_time()
        payload = PingPayload(global_time)
        dist = GlobalTimeDistributionPayload(global_time)

        packet = self._ez_pack(self._prefix, 3, [dist, payload], False)
        self.request_cache.add(PingRequestCache(self.request_cache, global_time, peer, time()))
        self.endpoint.send(peer.address, packet)

    def create_pong(self, identifier):
        global_time = self.claim_global_time()
        payload = PongPayload(identifier)
        dist = GlobalTimeDistributionPayload(global_time)
        return self._ez_pack(self._prefix, 4, [dist, payload], False)
