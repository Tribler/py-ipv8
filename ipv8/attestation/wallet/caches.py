import logging
from struct import unpack

from ...requestcache import NumberCache


class HashCache(NumberCache):
    """
    Cache tied to a hash.
    """

    def __init__(self, request_cache, prefix, cache_hash, id_format):
        prefix, number = self.id_from_hash(prefix, cache_hash)
        super(HashCache, self).__init__(request_cache, prefix, number)
        self.id_format = id_format

    @classmethod
    def id_from_hash(cls, prefix, cache_hash):
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

    def __init__(self, request_cache, prefix, mid, id_format):
        prefix, number = self.id_from_address(prefix, mid)
        super(PeerCache, self).__init__(request_cache, prefix, number)
        self.id_format = id_format

    @classmethod
    def id_from_address(cls, prefix, mid):
        return HashCache.id_from_hash(prefix, mid)

    @property
    def timeout_delay(self):
        return 120.0


class ReceiveAttestationVerifyCache(HashCache):
    """
    Pending attestation transfer, after request for attestation verification.
    """

    def __init__(self, community, cache_hash, id_format):
        super(ReceiveAttestationVerifyCache, self).__init__(community.request_cache, u"receive-verify-attestation",
                                                            cache_hash, id_format)
        self.attestation_map = set()

    def on_timeout(self):
        logging.warning("ReceiveAttestationVerify timed out!")

    @property
    def timeout_delay(self):
        return 120.0


class ReceiveAttestationRequestCache(PeerCache):
    """
    Pending attestation transfer, after request for a new attestation.
    Stores one-time key for this attribute attestation.
    """

    def __init__(self, community, mid, key, name, id_format):
        super(ReceiveAttestationRequestCache, self).__init__(community.request_cache, u"receive-request-attestation",
                                                             mid, id_format)
        self.attestation_map = set()
        self.key = key
        self.name = name

    def on_timeout(self):
        logging.warning("ReceiveAttestation timed out!")


class ProvingAttestationCache(HashCache):
    """
    Pending attestation verification, stores expected relmap, hashed challenges and completion callback.
    """

    def __init__(self, community, cache_hash, id_format, public_key=None, on_complete=lambda x, y: None):
        super(ProvingAttestationCache, self).__init__(community.request_cache, u"proving-attestation", cache_hash,
                                                      id_format)
        self.hash = cache_hash
        self.public_key = public_key
        self.relativity_map = {}
        self.hashed_challenges = []
        self.challenges = []
        self.attestation_callbacks = on_complete

    def on_timeout(self):
        logging.warning("ProvingAttestation timed out!")

    @property
    def timeout_delay(self):
        return 120.0


class PendingChallengeCache(HashCache):
    """
    Single pending challenge for a ProvingAttestationCache.
    """
    def __init__(self, community, cache_hash, proving_cache, id_format, honesty_check=-1):
        super(PendingChallengeCache, self).__init__(community.request_cache, u"proving-hash", cache_hash, id_format)
        self.proving_cache = proving_cache
        self.honesty_check = honesty_check

    def on_timeout(self):
        logging.warning("PendingChallenge timed out!")
