from __future__ import annotations

import logging
from struct import unpack
from typing import TYPE_CHECKING, Any, Callable, Set

from ...requestcache import NumberCache, RequestCache

if TYPE_CHECKING:
    from typing_extensions import Self

    from ...types import AttestationCommunity



class HashCache(NumberCache):
    """
    Cache tied to a hash.
    """

    def __init__(self, request_cache: RequestCache, prefix: str, cache_hash: bytes, id_format: str) -> None:
        """
        Create a new cache for a given hash.
        """
        prefix, number = self.id_from_hash(prefix, cache_hash)
        super().__init__(request_cache, prefix, number)
        self.id_format = id_format

    @classmethod
    def id_from_hash(cls: type[Self], prefix: str, cache_hash: bytes) -> tuple[str, int]:
        """
        Get a cache prefix and identifier from a hash.
        """
        number = 0
        for i in range(len(cache_hash)):
            b, = unpack('>B', cache_hash[i:i + 1])
            number <<= 8
            number |= b
        return prefix, number


class PeerCache(NumberCache):
    """
    Cache tied to a peer (mid).
    """

    def __init__(self, request_cache: RequestCache, prefix: str, mid: bytes, id_format: str) -> None:
        """
        Create a new cache for the given mid.
        """
        prefix, number = self.id_from_address(prefix, mid)
        super().__init__(request_cache, prefix, number)
        self.id_format = id_format

    @classmethod
    def id_from_address(cls: type[Self], prefix: str, mid: bytes) -> tuple[str, int]:
        """
        Get a cache prefix and identifier from an mid.
        """
        return HashCache.id_from_hash(prefix, mid)

    @property
    def timeout_delay(self) -> float:
        """
        The default timeout is two minutes.
        """
        return 120.0


class ReceiveAttestationVerifyCache(HashCache):
    """
    Pending attestation transfer, after request for attestation verification.
    """

    def __init__(self, community: AttestationCommunity, cache_hash: bytes, id_format: str) -> None:
        """
        Create a new cache for a pending attestation transfer.
        """
        super().__init__(community.request_cache, "receive-verify-attestation", cache_hash, id_format)
        self.attestation_map: Set[tuple[int, bytes]] = set()

    def on_timeout(self) -> None:
        """
        Too bad, nothing gained and nothing lost: log and drop the cache.
        """
        logging.warning("ReceiveAttestationVerify timed out!")

    @property
    def timeout_delay(self) -> float:
        """
        The default timeout is two minutes.
        """
        return 120.0


class ReceiveAttestationRequestCache(PeerCache):
    """
    Pending attestation transfer, after request for a new attestation.
    Stores one-time key for this attribute attestation.
    """

    def __init__(self, community: AttestationCommunity, mid: bytes, key: Any,  # noqa: ANN401
                 name: str, id_format: str) -> None:
        """
        Create a new cache for a pending attestation transfer reception.
        """
        super().__init__(community.request_cache, "receive-request-attestation", mid, id_format)
        self.attestation_map: Set[tuple[int, bytes]] = set()
        self.key = key
        self.name = name

    def on_timeout(self) -> None:
        """
        Too bad, nothing gained and nothing lost: log and drop the cache.
        """
        logging.warning("ReceiveAttestation timed out!")


class ProvingAttestationCache(HashCache):
    """
    Pending attestation verification, stores expected relmap, hashed challenges and completion callback.
    """

    def __init__(self, community: AttestationCommunity, cache_hash: bytes, id_format: str,
                 public_key: Any | None =None,  # noqa: ANN401
                 on_complete: Callable[[bytes, dict], None] = lambda x, y: None) -> None:
        """
        Create a new cache for a pending attestation verification.
        """
        super().__init__(community.request_cache, "proving-attestation", cache_hash, id_format)
        self.hash = cache_hash
        self.public_key = public_key
        self.relativity_map: dict[int, int] = {}
        self.hashed_challenges: list[bytes] = []
        self.challenges: list[bytes] = []
        self.attestation_callbacks = on_complete

    def on_timeout(self) -> None:
        """
        Too bad, nothing gained and nothing lost: log and drop the cache.
        """
        logging.warning("ProvingAttestation timed out!")

    @property
    def timeout_delay(self) -> float:
        """
        The default timeout is two minutes.
        """
        return 120.0


class PendingChallengeCache(HashCache):
    """
    Single pending challenge for a ProvingAttestationCache.
    """

    def __init__(self, community: AttestationCommunity, cache_hash: bytes,
                 proving_cache: ProvingAttestationCache, id_format: str, honesty_check: int = -1) -> None:
        """
        Create a new cache for a pending challenge.
        """
        super().__init__(community.request_cache, "proving-hash", cache_hash, id_format)
        self.proving_cache = proving_cache
        self.honesty_check = honesty_check

    def on_timeout(self) -> None:
        """
        Too bad, nothing gained and nothing lost: log and drop the cache.
        """
        logging.warning("PendingChallenge timed out!")
