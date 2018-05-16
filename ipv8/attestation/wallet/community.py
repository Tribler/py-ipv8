from hashlib import sha1
import json
import os
from random import choice

from twisted.internet.defer import inlineCallbacks

from .caches import *
from .database import AttestationsDB
from ...deprecated.community import Community
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .payload import *
from .primitives.attestation import (attest_sha256_4, binary_relativity_certainty, create_challenge,
                                     create_challenge_response_from_pair, create_empty_relativity_map,
                                     create_honesty_check, process_challenge_response)
from .primitives.structs import Attestation, BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from ...peer import Peer
from ...requestcache import RequestCache


from threading import Lock
receive_block_lock = Lock()
def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """
    def wrapper(self, *args, **kwargs):
        with receive_block_lock:
            return f(self, *args, **kwargs)
    return wrapper


class AttestationCommunity(Community):
    """
    Community for sharing Attestations.

    Note that the logic for giving out Attestations is in the TrustChain.
    """
    master_peer = Peer(("3081a7301006072a8648ce3d020106052b810400270381920004057a009787f66ea54d5082ea2f56a842488e319" +
                        "c14c98967c39286433233f769a73e9c894149cf9053a9a0c2548f07171df9c46c3bdb106afa9e9a8a06926e0ec3" +
                        "5871c91f2ab1a20651d0a7b5fda209a3500a09b630a193b281a266230472ef0cc0622c793dc18eed6c57d7bcd1e" +
                        "eca33e2e38277ea99c28d4c62f850f81b5eb3eb19fcb601747bd87aa0b04e360ae9").decode("HEX"))

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', 'attestations')

        super(AttestationCommunity, self).__init__(*args, **kwargs)

        self.database = AttestationsDB(working_directory, db_name)
        self.attestation_request_callbacks = [lambda x, y: None, lambda x, y, z, w=None: None]

        # Map of attestation hash -> BonehPrivateKey
        self.attestation_keys = {}
        for hash, _, key in self.database.get_all():
            self.attestation_keys[str(hash)] = BonehPrivateKey.unserialize(str(key))

        self.request_cache = RequestCache()

        self.decode_map.update({
            chr(1): self.on_verify_attestation_request,
            chr(2): self.on_attestation_chunk,
            chr(3): self.on_challenge,
            chr(4): self.on_challenge_response,
            chr(5): self.on_request_attestation
        })

    def set_attestation_request_callback(self, f):
        """
        Set the callback to be called when someone requests an attestation from us.

        f should accept a (Peer, attribute name) and return a str()-able value.
        If it f returns None, no attestation is made.

        :param f: the callback function providing the value
        """
        self.attestation_request_callbacks[0] = f

    def set_attestation_request_complete_callback(self, f):
        """
        f should accept a (Peer, attribute_name, hash, Peer=None), it is called when an Attestation
        has been made for another peer

        :param f: the function to call when an Attestation has been completed
        """
        self.attestation_request_callbacks[1] = f

    def request_attestation(self, peer, attribute_name, secret_key):
        """
        Request attestation of one of our attributes.

        :param peer: Peer of the Attestor
        :param attribute_name: the attribute we want attested
        :param secret_key: the secret key we use for this attribute
        """
        public_key = secret_key.public_key()
        self.request_cache.add(ReceiveAttestationRequestCache(self, peer.mid, secret_key, attribute_name))

        metadata = json.dumps({
            "attribute": attribute_name,
            "public_key": public_key.serialize().encode('base64')
        })

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = RequestAttestationPayload(metadata).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 5, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @inlineCallbacks
    def on_request_attestation(self, source_address, data):
        """
        Someone wants us to attest their attribute.
        """
        auth, dist, payload = self._ez_unpack_auth(RequestAttestationPayload, data)
        peer = Peer(auth.public_key_bin, source_address)

        metadata = json.loads(payload.metadata)

        value = yield self.attestation_request_callbacks[0](peer, metadata['attribute'])
        if value is None:
            return

        PK = BonehPublicKey.unserialize(metadata['public_key'].decode('base64'))
        attestation_blob = attest_sha256_4(PK, value).serialize()

        self.attestation_request_callbacks[1](peer, metadata['attribute'], sha1(attestation_blob).digest())

        self.send_attestation(source_address, attestation_blob)

    def on_attestation_complete(self, unserialized, secret_key, peer, name, hash):
        """
        We got an Attestation delivered to us.
        """
        self.attestation_keys[str(hash)] = secret_key
        self.database.insert_attestation(unserialized, secret_key)
        self.attestation_request_callbacks[1](self.my_peer, name, hash, peer)

    def verify_attestation_values(self, socket_address, hash, values, callback):
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param hash: the hash of the Attestation to request
        :param values: the values for which we want to measure certainty
        :param callback: the callback to call with the map of (hash, {value: certainty})
        """
        def on_complete(hash, relativity_map):
            callback(hash, [binary_relativity_certainty(value, relativity_map) for value in values])
        self.request_cache.add(ProvingAttestationCache(self, hash, on_complete=on_complete))
        self.create_verify_attestation_request(socket_address, hash)

    def create_verify_attestation_request(self, socket_address, hash):
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param hash: the hash of the Attestation to request
        """
        self.request_cache.add(ReceiveAttestationVerifyCache(self, hash))

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = VerifyAttestationRequestPayload(hash).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 1, [auth, dist, payload])
        self.endpoint.send(socket_address, packet)

    def on_verify_attestation_request(self, source_address, data):
        """
        We received a request to verify one of our attestations. Send the requested attestation back.
        """
        auth, dist, payload = self._ez_unpack_auth(VerifyAttestationRequestPayload, data)

        attestation_blob, = self.database.get_attestation_by_hash(payload.hash)
        if not attestation_blob:
            return

        self.send_attestation(source_address, attestation_blob)

    def send_attestation(self, socket_address, blob):
        # If we want to serve this request send the attestation in chunks of 800 bytes
        sequence_number = 0
        for i in range (0, len(blob), 800):
            blob_chunk = blob[i:i+800]

            global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
            payload = AttestationChunkPayload(sha1(blob).digest(), sequence_number, blob_chunk).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
            packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
            self.endpoint.send(socket_address, packet)

            sequence_number += 1

    def on_attestation_chunk(self, source_address, data):
        """
        We received a chunk of an Attestation.
        """
        auth, dist, payload = self._ez_unpack_auth(AttestationChunkPayload, data)
        peer = Peer(auth.public_key_bin, source_address)
        hash_id = HashCache.id_from_hash(u"receive-verify-attestation", payload.hash)
        peer_id = PeerCache.id_from_address(u"receive-request-attestation", peer.mid)
        if self.request_cache.has(*hash_id):
            cache = self.request_cache.get(*hash_id)
            cache.attestation_map |= {(payload.sequence_number, payload.data), }

            serialized = ""
            for (_, chunk) in sorted(cache.attestation_map, key=lambda item: item[0]):
                serialized += chunk

            try:
                unserialized = Attestation.unserialize(serialized)
                if sha1(serialized).digest() == payload.hash:
                    self.request_cache.pop(*hash_id)
                    self.on_received_attestation(peer, unserialized, payload.hash)
            except:
                pass
        elif self.request_cache.has(*peer_id):
            cache = self.request_cache.get(*peer_id)
            cache.attestation_map |= {(payload.sequence_number, payload.data), }

            serialized = ""
            for (_, chunk) in sorted(cache.attestation_map, key=lambda item: item[0]):
                serialized += chunk

            try:
                unserialized = Attestation.unserialize(serialized)
                if sha1(serialized).digest() == payload.hash:
                    cache = self.request_cache.pop(*peer_id)
                    self.on_attestation_complete(unserialized, cache.key, peer, cache.name, payload.hash)
            except:
                pass
        else:
            self.logger.warning("Received Attestation chunk which we did not request!")

    def on_received_attestation(self, peer, attestation, attestation_hash):
        """
        Callback for when we got the entire attestation from a peer.

        :param peer: the Peer we got this attestation from
        :param attestation: the Attestation object we can check
        """
        relativity_map = create_empty_relativity_map()
        challenges = []
        hashed_challenges = []
        cache = self.request_cache.get(*HashCache.id_from_hash(u"proving-attestation", attestation_hash))
        cache.public_key = attestation.PK
        for bitpair in attestation.bitpairs:
            challenge = create_challenge(attestation.PK, bitpair)
            serialized = pack_pair(challenge.a, challenge.b)
            challenges.append(serialized)
            challenge_hash = sha1(serialized).digest()
            hashed_challenges.append(challenge_hash)
        cache.relativity_map = relativity_map
        cache.hashed_challenges = hashed_challenges
        cache.challenges = challenges

        for challenge in challenges[:10]:
            self.request_cache.add(PendingChallengeCache(self, sha1(challenge).digest(), cache))

            global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
            payload = ChallengePayload(attestation_hash, challenge).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

            packet = self._ez_pack(self._prefix, 3, [auth, dist, payload])
            self.endpoint.send(peer.address, packet)

    def on_challenge(self, source_address, data):
        """
        We received a challenge for an Attestation.
        """
        auth, dist, payload = self._ez_unpack_auth(ChallengePayload, data)

        SK = self.attestation_keys[payload.attestation_hash]
        challenge_hash = sha1(payload.challenge).digest()

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = ChallengeResponsePayload(challenge_hash,
                                           create_challenge_response_from_pair(SK, unpack_pair(payload.challenge))
                                           ).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 4, [auth, dist, payload])
        self.endpoint.send(source_address, packet)

    @synchronized
    def on_challenge_response(self, source_address, data):
        """
        We received a response to our challenge
        """
        auth, dist, payload = self._ez_unpack_auth(ChallengeResponsePayload, data)

        cache = self.request_cache.get(*HashCache.id_from_hash(u"proving-hash", payload.challenge_hash))
        if cache:
            self.request_cache.pop(*HashCache.id_from_hash(u"proving-hash", payload.challenge_hash))
            proving_cache = cache.proving_cache
            pcache_prefix, pcache_id = HashCache.id_from_hash(u"proving-attestation", proving_cache.hash)
            if payload.challenge_hash in proving_cache.hashed_challenges:
                proving_cache.hashed_challenges.remove(payload.challenge_hash)
                for challenge in proving_cache.challenges[:]:
                    if sha1(challenge).digest() == payload.challenge_hash:
                        proving_cache.challenges.remove(challenge)
                        break
            if cache.honesty_check < 0:
                process_challenge_response(proving_cache.relativity_map, payload.response)
            elif cache.honesty_check != payload.response:
                self.logger.error("%s tried to cheat in the ZKP!", source_address[0])
                # Liar, Completed
                if self.request_cache.has(pcache_prefix, pcache_id):
                    self.request_cache.pop(pcache_prefix, pcache_id)
                proving_cache.attestation_callbacks(proving_cache.hash, create_empty_relativity_map())
            if len(proving_cache.hashed_challenges) == 0:
                self.logger.info("Completed attestation verification")
                # Completed
                if self.request_cache.has(pcache_prefix, pcache_id):
                    self.request_cache.pop(pcache_prefix, pcache_id)
                proving_cache.attestation_callbacks(proving_cache.hash, proving_cache.relativity_map)
            else:
                # Send another proving hash
                honesty_check = (ord(os.urandom(1)[0]) < 38)
                honesty_check_byte = choice(range(3)) if honesty_check else -1
                challenge = None
                if honesty_check:
                    raw_challenge = create_honesty_check(proving_cache.public_key, honesty_check_byte)
                    challenge = pack_pair(raw_challenge.a, raw_challenge.b)
                if (not honesty_check) or (challenge and self.request_cache.has(*HashCache.id_from_hash(u"proving-hash",
                                                                                sha1(challenge).digest()))):
                    honesty_check_byte = -1
                    challenge = None
                    for c in proving_cache.challenges:
                        if not self.request_cache.has(*HashCache.id_from_hash(u"proving-hash", sha1(c).digest())):
                            challenge = c
                            break
                    if not challenge:
                        self.logger.debug("No more bitpairs to challenge!")
                        return
                self.logger.debug("Sending challenge: %d (%d)", honesty_check_byte, len(proving_cache.hashed_challenges))
                self.request_cache.add(PendingChallengeCache(self, sha1(challenge).digest(), proving_cache,
                                                             honesty_check_byte))

                global_time = self.claim_global_time()
                auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
                payload = ChallengePayload(proving_cache.hash, challenge).to_pack_list()
                dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

                packet = self._ez_pack(self._prefix, 3, [auth, dist, payload])
                self.endpoint.send(source_address, packet)
