from socket import inet_aton
from struct import pack, unpack

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
    Cache tied to a peer (socket_address).
    """

    def __init__(self, request_cache, prefix, socket_address):
        prefix, number = self.id_from_address(prefix, socket_address)
        super(PeerCache, self).__init__(request_cache, prefix, number)

    @classmethod
    def id_from_address(cls, prefix, socket_address):
        return HashCache.id_from_hash(prefix, inet_aton(socket_address[0]) + pack('>H', socket_address[1]))


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

    def __init__(self, community, socket_address, key):
        super(ReceiveAttestationRequestCache, self).__init__(community.request_cache, u"receive-request-attestation",
                                                             socket_address)
        self.attestation_map = set()
        self.key = key

    def on_timeout(self):
        pass


class ProvingAttestationCache(HashCache):
    """
    Pending attestation verification, stores expected relmap, hashed challenges and completion callback.
    """

    def __init__(self, community, hash, on_complete=lambda x, y: None):
        super(ProvingAttestationCache, self).__init__(community.request_cache, u"proving-attestation", hash)
        self.hash = hash
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
    def __init__(self, community, hash, proving_cache):
        super(PendingChallengeCache, self).__init__(community.request_cache, u"proving-hash", hash)
        self.proving_cache = proving_cache

    def on_timeout(self):
        pass
