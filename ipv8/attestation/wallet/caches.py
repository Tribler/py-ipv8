from struct import unpack

from ...requestcache import NumberCache


class HashCache(NumberCache):
    """
    Cache tied to a hash.
    """

    def __init__(self, request_cache, prefix, hash):
        prefix, number = self.id_from_hash(prefix, hash)
        super(HashCache, self).__init__(request_cache, prefix, number)

    @classmethod
    def id_from_hash(cls, prefix, hash):
        number = 0
        for c in hash:
            b, = unpack('>B', c)
            number <<= 8
            number |= b
        return prefix, number


class PeerCache(NumberCache):
    """
    Cache tied to a peer (mid).
    """

    def __init__(self, request_cache, prefix, mid):
        prefix, number = self.id_from_address(prefix, mid)
        super(PeerCache, self).__init__(request_cache, prefix, number)

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

    def __init__(self, community, hash):
        super(ReceiveAttestationVerifyCache, self).__init__(community.request_cache, u"receive-verify-attestation",
                                                            hash)
        self.attestation_map = set()

    def on_timeout(self):
        pass


class ReceiveAttestationRequestCache(PeerCache):
    """
    Pending attestation transfer, after request for a new attestation.
    Stores one-time key for this attribute attestation.
    """

    def __init__(self, community, mid, key, name):
        super(ReceiveAttestationRequestCache, self).__init__(community.request_cache, u"receive-request-attestation",
                                                             mid)
        self.attestation_map = set()
        self.key = key
        self.name = name

    def on_timeout(self):
        print "ERROR ERROR ERROR!!"


class ProvingAttestationCache(HashCache):
    """
    Pending attestation verification, stores expected relmap, hashed challenges and completion callback.
    """

    def __init__(self, community, hash, public_key=None, on_complete=lambda x, y: None):
        super(ProvingAttestationCache, self).__init__(community.request_cache, u"proving-attestation", hash)
        self.hash = hash
        self.public_key = public_key
        self.relativity_map = {}
        self.hashed_challenges = []
        self.challenges = []
        self.attestation_callbacks = on_complete

    def on_timeout(self):
        pass


class PendingChallengeCache(HashCache):
    """
    Single pending challenge for a ProvingAttestationCache.
    """
    def __init__(self, community, hash, proving_cache, honesty_check=-1):
        super(PendingChallengeCache, self).__init__(community.request_cache, u"proving-hash", hash)
        self.proving_cache = proving_cache
        self.honesty_check = honesty_check

    def on_timeout(self):
        pass
