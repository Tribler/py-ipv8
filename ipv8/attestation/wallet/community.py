import json
import os
from base64 import decodebytes, encodebytes
from binascii import unhexlify
from functools import wraps
from hashlib import sha1
from random import choice
from threading import RLock

from .caches import (HashCache, PeerCache, PendingChallengeCache, ProvingAttestationCache,
                     ReceiveAttestationRequestCache, ReceiveAttestationVerifyCache)
from .database import AttestationsDB
from .payload import (AttestationChunkPayload, ChallengePayload, ChallengeResponsePayload, RequestAttestationPayload,
                      VerifyAttestationRequestPayload)
from ..schema.manager import SchemaManager
from ...community import Community
from ...lazy_community import lazy_wrapper
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peer import Peer
from ...requestcache import RequestCache
from ...util import cast_to_bin, cast_to_chr, maybe_coroutine


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with self.receive_block_lock:
            return f(self, *args, **kwargs)
    return wrapper


class AttestationCommunity(Community):
    """
    Community for sharing Attestations.

    Note that the logic for giving out Attestations is in the TrustChain.
    """
    master_peer = Peer(unhexlify("3081a7301006072a8648ce3d020106052b810400270381920004057a009787f66ea54d5082ea2f56a8"
                                 "42488e319c14c98967c39286433233f769a73e9c894149cf9053a9a0c2548f07171df9c46c3bdb106a"
                                 "fa9e9a8a06926e0ec35871c91f2ab1a20651d0a7b5fda209a3500a09b630a193b281a266230472ef0c"
                                 "c0622c793dc18eed6c57d7bcd1eeca33e2e38277ea99c28d4c62f850f81b5eb3eb19fcb601747bd87a"
                                 "a0b04e360ae9"))

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', 'attestations')

        super(AttestationCommunity, self).__init__(*args, **kwargs)

        self.receive_block_lock = RLock()

        self.schema_manager = SchemaManager()
        self.schema_manager.register_default_schemas()

        self.attestation_request_callback = lambda peer, attribute_name, metadata: None
        self.attestation_request_complete_callback = \
            lambda for_peer, attribute_name, attr_hash, id_format, from_peer=None: None
        self.verify_request_callback = lambda attribute_name, attr_hash: True

        # Map of attestation hash -> (PrivateKey, id_format)
        self.attestation_keys = {}
        self.database = AttestationsDB(working_directory, db_name)
        for attribute_hash, _, key, id_format in self.database.get_all():
            attribute_hash = attribute_hash if isinstance(attribute_hash, bytes) else str(attribute_hash)
            key = key if isinstance(key, bytes) else str(key)
            id_format = (id_format if isinstance(id_format, bytes) else str(id_format)).decode('utf-8')
            self.attestation_keys[attribute_hash] = (self.get_id_algorithm(id_format).load_secret_key(key), id_format)
        self.cached_attestation_blobs = {}
        self.allowed_attestations = {}  # mid -> global_time

        self.request_cache = RequestCache()

        self.decode_map.update({
            chr(1): self.on_verify_attestation_request,
            chr(2): self.on_attestation_chunk,
            chr(3): self.on_challenge,
            chr(4): self.on_challenge_response,
            chr(5): self.on_request_attestation
        })

    async def unload(self):
        await self.request_cache.shutdown()

        await super(AttestationCommunity, self).unload()
        # Close the database after we stop accepting requests.
        self.database.close()

    def get_id_algorithm(self, id_format):
        return self.schema_manager.get_algorithm_instance(id_format)

    def set_attestation_request_callback(self, f):
        """
        Set the callback to be called when someone requests an attestation from us.

        f should accept a (Peer, attribute name, metadata) and return a str()-able value.
        If it f returns None, no attestation is made.

        :param f: the callback function providing the value
        """
        self.attestation_request_callback = f

    def set_attestation_request_complete_callback(self, f):
        """
        f should accept a (Peer, attribute_name, hash, id_format, Peer=None), it is called when an Attestation
        has been made for another peer

        :param f: the function to call when an Attestation has been completed
        """
        self.attestation_request_complete_callback = f

    def set_verify_request_callback(self, f):
        """
        Set the callback to be called when someone wants to verify our attribute.

        f should accept a (Peer, attribute_name) and return a boolean value.
        If f return True, the attribute will be verified.

        :param f: the function to call when our attribute is requested for verification
        """
        self.verify_request_callback = f

    def dump_blob(self, attribute_name, id_format, blob, metadata={}):
        """
        Add an attribute directly (without the help of an IPv8 peer).

        This is only for advanced use, where the blob already has (1) some form of attestation embedded and (2)
        follows some form of non-interactive Zero-Knowledge Proof.

        :param attribute_name: the attribute we are creating
        :param id_format: the identity format
        :param blob: the raw data to be processed by the given id_format
        :param metadata: optional additional metadata
        """
        id_algorithm = self.get_id_algorithm(id_format)
        attestation_blob, key = id_algorithm.import_blob(blob)
        attestation = id_algorithm.get_attestation_class().unserialize_private(key, attestation_blob, id_format)

        self.on_attestation_complete(attestation, key, self.my_peer, attribute_name, attestation.get_hash(), id_format)

    def request_attestation(self, peer, attribute_name, secret_key, metadata={}):
        """
        Request attestation of one of our attributes.

        :param peer: Peer of the Attestor
        :param attribute_name: the attribute we want attested
        :param secret_key: the secret key we use for this attribute
        """
        public_key = secret_key.public_key()
        id_format = metadata.pop("id_format", "id_metadata")

        meta_dict = {
            "attribute": attribute_name,
            "public_key": cast_to_chr(encodebytes(public_key.serialize())),
            "id_format": id_format
        }
        meta_dict.update(metadata)
        metadata = json.dumps(meta_dict).encode()

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = RequestAttestationPayload(metadata).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        gtime_str = str(global_time).encode('utf-8')
        self.request_cache.add(ReceiveAttestationRequestCache(self, peer.mid + gtime_str, secret_key, attribute_name,
                                                              id_format))
        self.allowed_attestations[peer.mid] = (self.allowed_attestations.get(peer.mid, [])
                                               + [gtime_str])

        packet = self._ez_pack(self._prefix, 5, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, RequestAttestationPayload)
    async def on_request_attestation(self, peer, dist, payload):
        """
        Someone wants us to attest their attribute.
        """
        metadata = json.loads(payload.metadata)
        attribute = metadata.pop('attribute')
        pubkey_b64 = cast_to_bin(metadata.pop('public_key'))
        id_format = metadata.pop('id_format')
        id_algorithm = self.get_id_algorithm(id_format)

        value = await maybe_coroutine(self.attestation_request_callback, peer, attribute, metadata)
        if value is None:
            return

        PK = id_algorithm.load_public_key(decodebytes(pubkey_b64))
        attestation_blob = id_algorithm.attest(PK, value)
        attestation = id_algorithm.get_attestation_class().unserialize(attestation_blob, id_format)

        self.attestation_request_complete_callback(peer, attribute, attestation.get_hash(), id_format)

        self.send_attestation(peer.address, attestation_blob, dist.global_time)

    def on_attestation_complete(self, unserialized, secret_key, peer, name, attestation_hash, id_format):
        """
        We got an Attestation delivered to us.
        """
        self.attestation_keys[cast_to_bin(attestation_hash)] = (secret_key, id_format)
        self.database.insert_attestation(unserialized, attestation_hash, secret_key, id_format)
        self.attestation_request_complete_callback(self.my_peer, name, attestation_hash, id_format, peer)

    def verify_attestation_values(self, socket_address, attestation_hash, values, callback, id_format):
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param attestation_hash: the hash of the Attestation to request
        :param values: the values for which we want to measure certainty
        :param callback: the callback to call with the map of (hash, {value: certainty})
        :param id_format: the identity format specifier
        """
        algorithm = self.get_id_algorithm(id_format)

        def on_complete(attestation_hash, relativity_map):
            callback(attestation_hash, [algorithm.certainty(value, relativity_map) for value in values])
        self.request_cache.add(ProvingAttestationCache(self, attestation_hash, id_format, on_complete=on_complete))
        self.create_verify_attestation_request(socket_address, attestation_hash, id_format)

    def create_verify_attestation_request(self, socket_address, attestation_hash, id_format):
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param attestation_hash: the hash of the Attestation to request
        :param id_format: the identity format specifier
        """
        self.request_cache.add(ReceiveAttestationVerifyCache(self, attestation_hash, id_format))

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = VerifyAttestationRequestPayload(attestation_hash).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 1, [auth, dist, payload])
        self.endpoint.send(socket_address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, VerifyAttestationRequestPayload)
    async def on_verify_attestation_request(self, peer, dist, payload):
        """
        We received a request to verify one of our attestations. Send the requested attestation back.
        """
        attestation_blob = self.database.get_attestation_by_hash(payload.hash)
        if not attestation_blob:
            self.logger.warning("Dropping verification request of unknown hash!")
            return
        attestation_blob, = attestation_blob
        if not attestation_blob:
            self.logger.warning("Attestation blob for verification is empty!")
            return

        value = await maybe_coroutine(self.verify_request_callback, peer, payload.hash)
        if not value:
            return

        SK, id_format = self.attestation_keys[payload.hash]
        attestation_cls = self.get_id_algorithm(id_format).get_attestation_class()
        private_attestation = attestation_cls.unserialize_private(SK, attestation_blob, id_format)
        public_attestation_blob = private_attestation.serialize()
        self.cached_attestation_blobs[payload.hash] = private_attestation
        self.send_attestation(peer.address, public_attestation_blob)

    def send_attestation(self, socket_address, blob, global_time=None):
        # If we want to serve this request send the attestation in chunks of 800 bytes
        sequence_number = 0
        for i in range(0, len(blob), 800):
            blob_chunk = blob[i:i + 800]
            self.logger.debug("Sending attestation chunk %d to %s", sequence_number, str(socket_address))
            if global_time is None:
                global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
            payload = AttestationChunkPayload(sha1(blob).digest(), sequence_number, blob_chunk).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
            packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
            self.endpoint.send(socket_address, packet)

            sequence_number += 1

    @lazy_wrapper(GlobalTimeDistributionPayload, AttestationChunkPayload)
    def on_attestation_chunk(self, peer, dist, payload):
        """
        We received a chunk of an Attestation.
        """
        hash_id = HashCache.id_from_hash(u"receive-verify-attestation", payload.hash)
        peer_ids = [PeerCache.id_from_address(u"receive-request-attestation", peer.mid + allowed_glob)
                    for allowed_glob in self.allowed_attestations.get(peer.mid, [])
                    if allowed_glob == str(dist.global_time).encode('utf-8')]
        if self.request_cache.has(*hash_id):
            cache = self.request_cache.get(*hash_id)
            cache.attestation_map |= {(payload.sequence_number, payload.data), }

            serialized = b""
            for (_, chunk) in sorted(cache.attestation_map, key=lambda item: item[0]):
                serialized += chunk

            attestation_class = self.get_id_algorithm(cache.id_format).get_attestation_class()
            if sha1(serialized).digest() == payload.hash:
                unserialized = attestation_class.unserialize(serialized, cache.id_format)
                self.request_cache.pop(*hash_id)
                self.on_received_attestation(peer, unserialized, payload.hash)

            self.logger.debug("Received attestation chunk %d for proving by %s", payload.sequence_number, str(peer))
        else:
            handled = False
            for peer_id in peer_ids:
                if self.request_cache.has(*peer_id):
                    cache = self.request_cache.get(*peer_id)
                    cache.attestation_map |= {(payload.sequence_number, payload.data), }

                    serialized = b""
                    for (_, chunk) in sorted(cache.attestation_map, key=lambda item: item[0]):
                        serialized += chunk

                    attestation_class = self.get_id_algorithm(cache.id_format).get_attestation_class()
                    if sha1(serialized).digest() == payload.hash:
                        unserialized = attestation_class.unserialize_private(cache.key, serialized, cache.id_format)
                        cache = self.request_cache.pop(*peer_id)
                        self.allowed_attestations[peer.mid] = [glob_time for glob_time
                                                               in self.allowed_attestations[peer.mid]
                                                               if glob_time != str(dist.global_time).encode('utf-8')]
                        if not self.allowed_attestations[peer.mid]:
                            self.allowed_attestations.pop(peer.mid)
                        self.on_attestation_complete(unserialized, cache.key, peer, cache.name, unserialized.get_hash(),
                                                     cache.id_format)

                    self.logger.debug("Received attestation chunk %d for my attribute %s",
                                      payload.sequence_number,
                                      cache.name)
                    handled = True
                    break
            if not handled:
                self.logger.warning("Received Attestation chunk which we did not request!")

    def on_received_attestation(self, peer, attestation, attestation_hash):
        """
        Callback for when we got the entire attestation from a peer.

        :param peer: the Peer we got this attestation from
        :param attestation: the Attestation object we can check
        """
        algorithm = self.get_id_algorithm(attestation.id_format)

        relativity_map = algorithm.create_certainty_aggregate(attestation)
        hashed_challenges = []
        cache = self.request_cache.get(*HashCache.id_from_hash(u"proving-attestation", attestation_hash))
        cache.public_key = attestation.PK
        challenges = algorithm.create_challenges(attestation.PK, attestation)
        for challenge in challenges:
            challenge_hash = sha1(challenge).digest()
            hashed_challenges.append(challenge_hash)
        cache.relativity_map = relativity_map
        cache.hashed_challenges = hashed_challenges
        cache.challenges = challenges
        self.logger.debug("Sending %d challenges to %s", len(challenges), str(peer))
        remaining = 10
        for challenge in challenges:
            if remaining == 0:
                break
            elif self.request_cache.has(*PendingChallengeCache.id_from_hash(u"proving-hash", sha1(challenge).digest())):
                continue
            remaining -= 1
            self.request_cache.add(PendingChallengeCache(self, sha1(challenge).digest(), cache, cache.id_format))

            global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
            payload = ChallengePayload(attestation_hash, challenge).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

            packet = self._ez_pack(self._prefix, 3, [auth, dist, payload])
            self.endpoint.send(peer.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, ChallengePayload)
    def on_challenge(self, peer, dist, payload):
        """
        We received a challenge for an Attestation.
        """
        SK, id_format = self.attestation_keys[payload.attestation_hash]
        challenge_hash = sha1(payload.challenge).digest()
        algorithm = self.get_id_algorithm(id_format)
        attestation = self.cached_attestation_blobs[payload.attestation_hash]

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = ChallengeResponsePayload(challenge_hash,
                                           algorithm.create_challenge_response(SK, attestation, payload.challenge)
                                           ).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 4, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, ChallengeResponsePayload)
    def on_challenge_response(self, peer, dist, payload):
        """
        We received a response to our challenge
        """
        cache = self.request_cache.get(*HashCache.id_from_hash(u"proving-hash", payload.challenge_hash))
        if cache:
            self.request_cache.pop(*HashCache.id_from_hash(u"proving-hash", payload.challenge_hash))
            proving_cache = cache.proving_cache
            pcache_prefix, pcache_id = HashCache.id_from_hash(u"proving-attestation", proving_cache.hash)
            challenge = None
            if payload.challenge_hash in proving_cache.hashed_challenges:
                proving_cache.hashed_challenges.remove(payload.challenge_hash)
                for challenge in proving_cache.challenges[:]:
                    if sha1(challenge).digest() == payload.challenge_hash:
                        proving_cache.challenges.remove(challenge)
                        break
            algorithm = self.get_id_algorithm(proving_cache.id_format)
            if cache.honesty_check < 0:
                algorithm.process_challenge_response(proving_cache.relativity_map, challenge, payload.response)
            elif not algorithm.process_honesty_challenge(cache.honesty_check, payload.response):
                self.logger.error("%s tried to cheat in the ZKP!", peer.address[0])
                # Liar, Completed
                if self.request_cache.has(pcache_prefix, pcache_id):
                    self.request_cache.pop(pcache_prefix, pcache_id)
                proving_cache.attestation_callbacks(proving_cache.hash, algorithm.create_certainty_aggregate(None))
            if len(proving_cache.hashed_challenges) == 0:
                self.logger.info("Completed attestation verification")
                # Completed
                if self.request_cache.has(pcache_prefix, pcache_id):
                    self.request_cache.pop(pcache_prefix, pcache_id)
                proving_cache.attestation_callbacks(proving_cache.hash, proving_cache.relativity_map)
            else:
                # Send another proving hash
                honesty_check = algorithm.honesty_check and (ord(os.urandom(1)[0:1]) < 38)
                honesty_check_byte = choice([0, 1, 2]) if honesty_check else -1
                challenge = None
                if honesty_check:
                    while not challenge or self.request_cache.has(*HashCache.id_from_hash(u"proving-hash",
                                                                                          sha1(challenge).digest())):
                        challenge = algorithm.create_honesty_challenge(proving_cache.public_key, honesty_check_byte)
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
                self.logger.debug("Sending challenge: %d (%d)", honesty_check_byte,
                                  len(proving_cache.hashed_challenges))
                self.request_cache.add(PendingChallengeCache(self, sha1(challenge).digest(), proving_cache,
                                                             cache.id_format, honesty_check_byte))

                global_time = self.claim_global_time()
                auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
                payload = ChallengePayload(proving_cache.hash, challenge).to_pack_list()
                dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

                packet = self._ez_pack(self._prefix, 3, [auth, dist, payload])
                self.endpoint.send(peer.address, packet)
