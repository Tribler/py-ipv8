from __future__ import annotations

import logging
import time
from binascii import hexlify
from typing import TYPE_CHECKING, TypedDict, cast

from ..messaging.lazy_payload import VariablePayload, vp_compile
from ..messaging.serialization import default_serializer
from ..peer import Peer
from . import DHTError

if TYPE_CHECKING:
    from ..messaging.interfaces.udp.endpoint import Address
    from .discovery import DHTDiscoveryCommunity

PEER_SOURCE_DHT = 1


class AddressDict(TypedDict):
    """
    Serialized peer address and public key dictionary.
    """

    ip: str
    port: int
    public_key: str


class IntroPointDict(TypedDict):
    """
    Serialized dictionary representation of an IntroductionPoint.
    """

    address: AddressDict
    seeder_pk: str
    source: int


class IntroductionPoint:
    """
    A point of introduction, available for linking up.
    """

    def __init__(self, peer: Peer, seeder_pk: bytes, source: int = PEER_SOURCE_DHT,
                 last_seen: float | None = None) -> None:
        """
        Creates a new introduction point.
        """
        self.peer = peer
        self.seeder_pk = seeder_pk
        self.source = source
        self.last_seen = int(time.time()) if last_seen is None else last_seen

    def __eq__(self, other: object) -> bool:
        """
        Check if another object is equal to this intro point.
        """
        if not isinstance(other, IntroductionPoint):
            return False
        return self.peer == other.peer and self.seeder_pk == other.seeder_pk

    def __hash__(self) -> int:
        """
        Each intro point is unique to its peer and seeder's public key.
        """
        return hash((self.peer, self.seeder_pk))

    def to_dict(self) -> IntroPointDict:
        """
        Convert this intro point to a flat dict.
        """
        return{"address": {"ip": self.peer.address[0],
                           "port": int(self.peer.address[1]),
                           "public_key": hexlify(self.peer.public_key.key_to_bin()).decode()},
               "seeder_pk": hexlify(self.seeder_pk).decode(),
               "source": self.source}


@vp_compile
class DHTIntroPointPayload(VariablePayload):
    """
    Payload to pack an introduction point's address, most recent time of response, public key and associated
    seeder public key.
    """

    names = ["address", "last_seen", "intro_pk", "seeder_pk"]
    format_list = ["ip_address", "I", "varlenH", "varlenH"]

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
        for value, _ in cast("tuple[list[bytes], list[bytes]]", values):
            try:
                payload, _ = default_serializer.unpack_serializable(DHTIntroPointPayload, value)
                intro_peer = Peer(b"LibNaCLPK:" + payload.intro_pk, payload.address)
                results.append(IntroductionPoint(intro_peer, b"LibNaCLPK:" + payload.seeder_pk,
                                                 PEER_SOURCE_DHT, payload.last_seen))
            except Exception as e:
                self.logger.info("Error during lookup %s on the DHTCommunity (error: %s)", hexlify(info_hash), e)
        self.logger.info("Looked up %s in the DHTCommunity, got %d results", hexlify(info_hash), len(results))
        return info_hash, results

    async def announce(self, info_hash: bytes, intro_point: IntroductionPoint) -> None:
        """
        Announce the given introduction point to server the given info hash (SHA-1).
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
