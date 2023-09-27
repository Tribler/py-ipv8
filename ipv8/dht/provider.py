from __future__ import annotations

import logging
from binascii import hexlify
from typing import TYPE_CHECKING, List, Tuple, cast

from ..messaging.anonymization.tunnel import PEER_SOURCE_DHT, IntroductionPoint
from ..messaging.lazy_payload import VariablePayload, vp_compile
from ..messaging.serialization import default_serializer
from ..peer import Peer
from . import DHTError

if TYPE_CHECKING:
    from ..types import Address
    from .discovery import DHTDiscoveryCommunity


@vp_compile
class DHTIntroPointPayload(VariablePayload):
    """
    Payload to pack an introduction point's address, most recent time of response, public key and associated
    seeder public key.
    """

    names = ['address', 'last_seen', 'intro_pk', 'seeder_pk']
    format_list = ['ip_address', 'I', 'varlenH', 'varlenH']

    address: Address
    last_seen: int
    intro_pk: bytes
    seeder_pk: bytes


class DHTCommunityProvider:
    """
    This class is a wrapper around the DHTDiscoveryCommunity and is used to discover introduction points
    for hidden services.
    """

    def __init__(self, dht_community: DHTDiscoveryCommunity, port: int) -> None:
        """
        Create a new provider api for the given community.
        """
        self.dht_community = dht_community
        self.port = port
        self.logger = logging.getLogger(self.__class__.__name__)

    async def peer_lookup(self, mid: bytes, peer: Peer | None = None) -> None:
        """
        Attempt to find and connect to the given mid.

        If provided, the given peer will be pinged first to potentially avoid an expensive lookup.
        """
        try:
            await self.dht_community.connect_peer(mid, peer)
        except DHTError as e:
            self.logger.debug("Failed to connect %s using the DHTCommunity (error: %s)", hexlify(mid), e)

    async def lookup(self, info_hash: bytes) -> tuple[bytes, list[IntroductionPoint]] | None:
        """
        Attempt to find introduction points for the given info hash (SHA-1 hash).
        """
        try:
            values = await self.dht_community.find_values(info_hash)
        except DHTError as e:
            self.logger.info("Failed to lookup %s on the DHTCommunity (error: %s)", hexlify(info_hash), e)
            return None

        results = []
        for value, _ in cast(Tuple[List[bytes], List[bytes]], values):
            try:
                payload, _ = default_serializer.unpack_serializable(DHTIntroPointPayload, value)
                intro_peer = Peer(b'LibNaCLPK:' + payload.intro_pk, payload.address)
                results.append(IntroductionPoint(intro_peer, b'LibNaCLPK:' + payload.seeder_pk,
                                                 PEER_SOURCE_DHT, payload.last_seen))
            except Exception as e:
                self.logger.info("Error during lookup %s on the DHTCommunity (error: %s)", hexlify(info_hash), e)
        self.logger.info("Looked up %s in the DHTCommunity, got %d results", hexlify(info_hash), len(results))
        return info_hash, results

    async def announce(self, info_hash: bytes, intro_point: IntroductionPoint) -> None:
        """
        Annonce the given introduction point to server the given info hash (SHA-1).
        """
        # We strip away the LibNaCLPK part of the public key to avoid going over the DHT size limit.
        value = default_serializer.pack_serializable(DHTIntroPointPayload(intro_point.peer.address,
                                                                          intro_point.last_seen,
                                                                          intro_point.peer.public_key.key_to_bin()[10:],
                                                                          intro_point.seeder_pk[10:]))

        try:
            await self.dht_community.store_value(info_hash, value)
        except DHTError as e:
            self.logger.info("Failed to announce %s to the DHTCommunity (error: %s)", hexlify(info_hash), e)
        else:
            self.logger.info("Announced %s to the DHTCommunity", hexlify(info_hash))
