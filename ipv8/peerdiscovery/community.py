from __future__ import annotations

from binascii import unhexlify
from random import sample
from time import time
from typing import TYPE_CHECKING, Sequence, Union, cast

from ..community import Community, CommunitySettings
from ..keyvault.crypto import default_eccrypto
from ..keyvault.keys import PrivateKey
from ..lazy_community import PacketDecodingError, lazy_wrapper, lazy_wrapper_unsigned, retrieve_cache
from ..messaging.payload import IntroductionRequestPayload, IntroductionResponsePayload, NewIntroductionResponsePayload
from ..messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ..messaging.serialization import PackError, Serializable
from ..peer import Peer
from ..requestcache import NumberCache, RequestCache
from .churn import DiscoveryStrategy, RandomChurn
from .payload import (
    DiscoveryIntroductionRequestPayload,
    PingPayload,
    PongPayload,
    SimilarityRequestPayload,
    SimilarityResponsePayload,
)

if TYPE_CHECKING:
    from ..types import Address


class PeriodicSimilarity(DiscoveryStrategy):
    """
    Periodically send a request for similar Communities to a random peer.
    """

    def __init__(self, overlay: DiscoveryCommunity) -> None:
        """
        Create a new strategy to regularly send similarity requests.
        """
        super().__init__(overlay)
        self.last_step: float = 0

    def take_step(self) -> None:
        """
        Select a random peer, at most every second, to send a similarity request to.
        """
        self.overlay = cast(DiscoveryCommunity, self.overlay)
        now = time()
        if (now - self.last_step < 1.0) or not self.overlay.network.verified_peers:
            return
        self.last_step = now
        with self.walk_lock:
            self.overlay.send_similarity_request(sample(list(self.overlay.network.verified_peers), 1)[0].address)


class PingRequestCache(NumberCache):
    """
    Cache for ping measurements to a peer.
    """

    name = "discoverypingcache"

    def __init__(self, request_cache: RequestCache, identifier: int, peer: Peer, start_time: float) -> None:
        """
        Register a new ping to a peer that was sent at a given time.
        """
        super().__init__(request_cache, PingRequestCache.name, identifier)
        self.peer = peer
        self.start_time = start_time

    def finish(self) -> None:
        """
        Complete the ping measurement by adding it to a peer's pings.
        """
        self.peer.pings.append(time() - self.start_time)

    @property
    def timeout_delay(self) -> float:
        """
        After 5 seconds, consider the peer unreachable.
        """
        return 5.0

    def on_timeout(self) -> None:
        """
        If we can't reach a peer, we assume accidental packet drop. Actually dropping the peer is left to the churn.
        """


class DiscoveryCommunity(Community):
    """
    Community for peers to more quickly discover peers in other communities.

    Peers exchange the community ids they are part of with each other.
    """

    version = b'\x02'
    community_id = unhexlify('7e313685c1912a141279f8248fc8db5899c5df5a')

    def __init__(self, settings: CommunitySettings) -> None:
        """
        Create a new community with similarity and ping functionality.
        """
        super().__init__(settings)

        self.request_cache = RequestCache()

        self.add_message_handler(SimilarityRequestPayload, self.on_similarity_request)
        self.add_message_handler(SimilarityResponsePayload, self.on_similarity_response)
        self.add_message_handler(PingPayload, self.on_ping)
        self.add_message_handler(PongPayload, self.on_pong)

    def get_available_strategies(self) -> dict[str, type[DiscoveryStrategy]]:
        """
        Expose strategies for periodically checking similarity and unreachable peer churn.
        """
        return {'PeriodicSimilarity': PeriodicSimilarity, 'RandomChurn': RandomChurn}

    async def unload(self) -> None:
        """
        Unload the pending ping cache and then shut down the pending tasks.
        """
        await self.request_cache.shutdown()
        await super().unload()

    def on_old_introduction_request(self, source_address: Address, data: bytes) -> None:
        """
        A backward-compatible (2014) introduction request handler.

        The old logic flow was to first try to unpack the special DiscoveryCommunity intro request and then fall
        back to the actual intro request payload.
        """
        if 0 <= self.max_peers < len(self.get_peers()):
            self.logger.debug("Dropping introduction request from (%s, %d): too many peers!",
                              source_address[0], source_address[1])
            return

        payload: IntroductionRequestPayload | DiscoveryIntroductionRequestPayload
        try:
            auth, dist, payload = self._ez_unpack_auth(DiscoveryIntroductionRequestPayload, data)
        except (PacketDecodingError, PackError):
            auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)
        payload = cast(Union[IntroductionRequestPayload, DiscoveryIntroductionRequestPayload], payload)

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

    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        """
        If a peer sent us a response, send them a request for similarity.
        """
        self.send_similarity_request(peer.address)

    def send_similarity_request(self, address: Address) -> None:
        """
        Send a request for similarity with our communities.
        """
        my_peer_set = {overlay.my_peer for overlay in self.network.service_overlays.values()}
        for peer in my_peer_set:
            packet = self.create_similarity_request(peer)
            self.endpoint.send(address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, SimilarityRequestPayload)
    def on_similarity_request(self, node: Peer, dist: GlobalTimeDistributionPayload,
                              payload: SimilarityRequestPayload) -> None:
        """
        We received a request for similarity (overlap with another peer's communities).

        We update the known community ids for this peer and we send a response that contains our own ids.
        """
        self.network.discover_services(node, payload.preference_list)

        my_peer_set = {overlay.my_peer for overlay in self.network.service_overlays.values()}
        for peer in my_peer_set:
            packet = self.create_similarity_response(payload.identifier, peer)
            self.endpoint.send(node.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, SimilarityResponsePayload)
    def on_similarity_response(self, node: Peer, dist: GlobalTimeDistributionPayload,
                               payload: SimilarityResponsePayload) -> None:
        """
        We received a response to our request for similarity.
        """
        if 0 <= self.max_peers < len(self.get_peers()) and node not in self.network.verified_peers:
            self.logger.debug("Dropping similarity response from (%s, %d): too many peers!",
                              node.address[0], node.address[1])
            return

        self.network.add_verified_peer(node)
        self.network.discover_services(node, payload.preference_list)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PingPayload)
    def on_ping(self, source_address: Address, dist: GlobalTimeDistributionPayload, payload: PingPayload) -> None:
        """
        We received a ping, send a pong back.

        For backward compatibility, this message is unsigned.
        """
        packet = self.create_pong(payload.identifier)
        self.endpoint.send(source_address, packet)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PongPayload)
    @retrieve_cache(PingRequestCache)
    def on_pong(self, source_address: Address, dist: GlobalTimeDistributionPayload, payload: PongPayload,
                cache: PingRequestCache) -> None:
        """
        We got a valid pong to our existing ping (retrieve_cache ensures this), finish the request in the cache handler.

        Note: For backward compatibility, this message is UNSIGNED. The only thing guaranteeing that the response
              is not faked, is its nonce.
        """
        cache.finish()

    def get_my_overlays(self, peer: Peer) -> list[bytes]:
        """
        Get the known community ids that we are a part of.
        """
        return [service_id for service_id, overlay in self.network.service_overlays.items()
                if overlay.my_peer == peer]

    def custom_pack(self, peer: Peer, msg_num: int, payloads: Sequence[Serializable]) -> bytes:
        """
        You can have different key material for different communities. So, in order for you to cross-communicate,
        you should sign messages with the key material that is used by a particular community.
        """
        packet = self._prefix + bytes([msg_num])
        packet += self.serializer.pack_serializable_list(payloads)
        packet += default_eccrypto.create_signature(cast(PrivateKey, peer.key), packet)
        return packet

    def create_similarity_request(self, peer: Peer) -> bytes:
        """
        Create a similarity request message to send to the given peer.
        """
        global_time = self.claim_global_time()
        payload = SimilarityRequestPayload(global_time,
                                           self.my_estimated_lan,
                                           self.my_estimated_wan,
                                           "unknown",
                                           self.get_my_overlays(peer))
        auth = BinMemberAuthenticationPayload(peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self.custom_pack(peer, 1, [auth, dist, payload])

    def create_similarity_response(self, identifier: int, peer: Peer) -> bytes:
        """
        Create a response message to a similarity request from a given peer.
        """
        global_time = self.claim_global_time()
        payload = SimilarityResponsePayload(identifier, self.get_my_overlays(peer), [])
        auth = BinMemberAuthenticationPayload(peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self.custom_pack(peer, 2, [auth, dist, payload])

    def send_ping(self, peer: Peer) -> None:
        """
        Send a ping message to the given peer.
        """
        global_time = self.claim_global_time()
        payload = PingPayload(global_time)
        dist = GlobalTimeDistributionPayload(global_time)

        packet = self._ez_pack(self._prefix, 3, [dist, payload], False)
        self.request_cache.add(PingRequestCache(self.request_cache, global_time, peer, time()))
        self.endpoint.send(peer.address, packet)

    def create_pong(self, identifier: int) -> bytes:
        """
        Create a pong message for the given identifier.
        """
        global_time = self.claim_global_time()
        payload = PongPayload(identifier)
        dist = GlobalTimeDistributionPayload(global_time)
        return self._ez_pack(self._prefix, 4, [dist, payload], False)
