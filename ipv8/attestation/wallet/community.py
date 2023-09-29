from __future__ import annotations

import json
import os
from base64 import decodebytes, encodebytes
from binascii import unhexlify
from functools import wraps
from hashlib import sha1
from random import choice
from threading import RLock
from typing import TYPE_CHECKING, Any, Callable, Optional, TypeVar, cast

from ...community import Community, CommunitySettings
from ...lazy_community import lazy_wrapper
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...requestcache import RequestCache
from ...util import maybe_coroutine, succeed
from ..schema.manager import SchemaManager
from .caches import (
    HashCache,
    PeerCache,
    PendingChallengeCache,
    ProvingAttestationCache,
    ReceiveAttestationRequestCache,
    ReceiveAttestationVerifyCache,
)
from .database import AttestationsDB, SecretKeyProtocol
from .payload import (
    AttestationChunkPayload,
    ChallengePayload,
    ChallengeResponsePayload,
    RequestAttestationPayload,
    VerifyAttestationRequestPayload,
)

if TYPE_CHECKING:
    from asyncio import Future

    from ...types import Address, IdentityAlgorithm, Peer
    from ..identity_formats import Attestation

# ruff: noqa: N806

WF = TypeVar("WF", bound=Callable)


def synchronized(f: WF) -> WF:
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """

    @wraps(f)
    def wrapper(self: AttestationCommunity, *args: Any, **kwargs) -> Any:  # noqa: ANN401
        with self.receive_block_lock:
            return f(self, *args, **kwargs)

    return cast(WF, wrapper)


def _default_attestation_request_callback(peer: Peer, attribute_name: str,
                                          metadata: dict[str, str]) -> Future[bytes | None]:
    return succeed(None)


def _default_attestation_request_complete_callback(for_peer: Peer, attribute_name: str, attr_hash: bytes,
                                                   id_format: str, from_peer: Peer | None = None) -> None:
    pass


def _default_verify_callback(peer: Peer, attr_hash: bytes) -> Future[bool]:
    return succeed(True)


class AttestationSettings(CommunitySettings):
    """
    Settings for the Attestation community.
    """

    working_directory: str = ""

    db_name: str = "attestations"


class AttestationCommunity(Community):
    """
    Community for sharing Attestations.

    Note that the logic for giving out Attestations is in the identity chain.
    """

    community_id = unhexlify('b42c93d167a0fc4a0843f917d4bf1e9ebb340ec4')
    settings_class = AttestationSettings

    def __init__(self, settings: AttestationSettings) -> None:
        """
        Create a new community to transfer and verify attestations.
        """
        super().__init__(settings)

        self.receive_block_lock = RLock()

        self.schema_manager = SchemaManager()
        self.schema_manager.register_default_schemas()

        self.attestation_request_callback: Callable[[Peer, str, dict[str, str]],
                                                    Future[bytes | None]] = _default_attestation_request_callback
        self.attestation_request_complete_callback: Callable[[Peer, str, bytes, str, Peer | None],
                                                             None] = _default_attestation_request_complete_callback
        self.verify_request_callback: Callable[[Peer, bytes], Future[bool]] = _default_verify_callback

        # Map of attestation hash -> (PrivateKey, id_format)
        self.attestation_keys: dict[bytes, tuple[SecretKeyProtocol, str]] = {}
        self.database = AttestationsDB(settings.working_directory, settings.db_name)
        for attribute_hash, _, key, id_format in self.database.get_all():
            self.attestation_keys[attribute_hash] = (self.get_id_algorithm(id_format.decode()).load_secret_key(key),
                                                     id_format.decode())
        self.cached_attestation_blobs: dict[bytes, Attestation] = {}
        self.allowed_attestations: dict[bytes, list[bytes]] = {}  # mid -> global_time

        self.request_cache = RequestCache()

        self.add_message_handler(VerifyAttestationRequestPayload, self.on_verify_attestation_request)
        self.add_message_handler(AttestationChunkPayload, self.on_attestation_chunk)
        self.add_message_handler(ChallengePayload, self.on_challenge)
        self.add_message_handler(ChallengeResponsePayload, self.on_challenge_response)
        self.add_message_handler(RequestAttestationPayload, self.on_request_attestation)

    async def unload(self) -> None:
        """
        Shutdown our request cache and database.
        """
        await self.request_cache.shutdown()

        await super().unload()
        # Close the database after we stop accepting requests.
        self.database.close()

    def get_id_algorithm(self, id_format: str) -> IdentityAlgorithm:
        """
        Resolve an algorithm from a name.
        """
        return self.schema_manager.get_algorithm_instance(id_format)

    def set_attestation_request_callback(self, f: Callable[[Peer, str, dict[str, str]], Future[bytes | None]]) -> None:
        """
        Set the callback to be called when someone requests an attestation from us.

        f should accept a (Peer, attribute name, metadata) and return a str()-able value.
        If it f returns None, no attestation is made.

        :param f: the callback function providing the value
        """
        self.attestation_request_callback = f

    def set_attestation_request_complete_callback(self,
                                                  f: Callable[[Peer, str, bytes, str, Peer | None], None]) -> None:
        """
        f should accept a (Peer, attribute_name, hash, id_format, Peer=None), it is called when an Attestation
        has been made for another peer.

        :param f: the function to call when an Attestation has been completed
        """
        self.attestation_request_complete_callback = f

    def set_verify_request_callback(self, f: Callable[[Peer, bytes], Future[bool]]) -> None:
        """
        Set the callback to be called when someone wants to verify our attribute.

        f should accept a (Peer, attribute_name) and return a boolean value.
        If f return True, the attribute will be verified.

        :param f: the function to call when our attribute is requested for verification
        """
        self.verify_request_callback = f

    def dump_blob(self, attribute_name: str, id_format: str, blob: bytes,
                  metadata: dict[str, str] | None = None) -> None:
        """
        Add an attribute directly (without the help of an IPv8 peer).

        This is only for advanced use, where the blob already has (1) some form of attestation embedded and (2)
        follows some form of non-interactive Zero-Knowledge Proof.

        :param attribute_name: the attribute we are creating
        :param id_format: the identity format
        :param blob: the raw data to be processed by the given id_format
        :param metadata: optional additional metadata
        """
        if metadata is None:
            metadata = {}
        id_algorithm = self.get_id_algorithm(id_format)
        attestation_blob, key = id_algorithm.import_blob(blob)
        attestation = id_algorithm.get_attestation_class().unserialize_private(key, attestation_blob, id_format)

        self.on_attestation_complete(attestation, key, self.my_peer, attribute_name, attestation.get_hash(), id_format)

    def request_attestation(self, peer: Peer, attribute_name: str, secret_key: SecretKeyProtocol,
                            metadata: dict[str, str] | None = None) -> None:
        """
        Request attestation of one of our attributes.

        :param peer: Peer of the Attestor
        :param attribute_name: the attribute we want attested
        :param secret_key: the secret key we use for this attribute
        """
        if metadata is None:
            metadata = {}
        public_key = secret_key.public_key()
        id_format = metadata.pop("id_format", "id_metadata")

        meta_dict = {
            "attribute": attribute_name,
            "public_key": encodebytes(public_key.serialize()).decode(),
            "id_format": id_format
        }
        meta_dict.update(metadata)
        bmetadata = json.dumps(meta_dict).encode()

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        payload = RequestAttestationPayload(bmetadata)
        dist = GlobalTimeDistributionPayload(global_time)

        gtime_str = str(global_time).encode('utf-8')
        self.request_cache.add(ReceiveAttestationRequestCache(self, peer.mid + gtime_str, secret_key, attribute_name,
                                                              id_format))
        self.allowed_attestations[peer.mid] = [*self.allowed_attestations.get(peer.mid, []), gtime_str]

        packet = self._ez_pack(self._prefix, 5, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, RequestAttestationPayload)
    async def on_request_attestation(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                     payload: RequestAttestationPayload) -> None:
        """
        Someone wants us to attest their attribute.
        """
        metadata = json.loads(payload.metadata)
        attribute = metadata.pop('attribute')
        pubkey_b64 = metadata.pop('public_key').encode()
        id_format = metadata.pop('id_format')
        id_algorithm = self.get_id_algorithm(id_format)

        value = await maybe_coroutine(self.attestation_request_callback, peer, attribute, metadata)
        if value is None:
            return

        PK = id_algorithm.load_public_key(decodebytes(pubkey_b64))
        attestation_blob = id_algorithm.attest(PK, value)
        attestation = id_algorithm.get_attestation_class().unserialize(attestation_blob, id_format)

        self.attestation_request_complete_callback(peer, attribute, attestation.get_hash(), id_format, None)

        self.send_attestation(peer.address, attestation_blob, dist.global_time)

    def on_attestation_complete(self, unserialized: Attestation, secret_key: SecretKeyProtocol,  # noqa: PLR0913
                                peer: Peer, name: str, attestation_hash: bytes, id_format: str) -> None:
        """
        We got an Attestation delivered to us.
        """
        self.attestation_keys[attestation_hash] = (secret_key, id_format)
        self.database.insert_attestation(unserialized, attestation_hash, secret_key, id_format)
        self.attestation_request_complete_callback(self.my_peer, name, attestation_hash, id_format, peer)

    def verify_attestation_values(self, socket_address: Address, attestation_hash: bytes,
                                  values: list[bytes], callback: Callable[[bytes, list[float]], None],
                                  id_format: str) -> None:
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param attestation_hash: the hash of the Attestation to request
        :param values: the values for which we want to measure certainty
        :param callback: the callback to call with the map of (hash, {value: certainty})
        :param id_format: the identity format specifier
        """
        algorithm = self.get_id_algorithm(id_format)

        def on_complete(attestation_hash: bytes, relativity_map: dict[int, int]) -> None:
            callback(attestation_hash, [algorithm.certainty(value, relativity_map) for value in values])

        self.request_cache.add(ProvingAttestationCache(self, attestation_hash, id_format, on_complete=on_complete))
        self.create_verify_attestation_request(socket_address, attestation_hash, id_format)

    def create_verify_attestation_request(self, socket_address: Address, attestation_hash: bytes,
                                          id_format: str) -> None:
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param attestation_hash: the hash of the Attestation to request
        :param id_format: the identity format specifier
        """
        self.request_cache.add(ReceiveAttestationVerifyCache(self, attestation_hash, id_format))

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        payload = VerifyAttestationRequestPayload(attestation_hash)
        dist = GlobalTimeDistributionPayload(global_time)

        packet = self._ez_pack(self._prefix, 1, [auth, dist, payload])
        self.endpoint.send(socket_address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, VerifyAttestationRequestPayload)
    async def on_verify_attestation_request(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                            payload: VerifyAttestationRequestPayload) -> None:
        """
        We received a request to verify one of our attestations. Send the requested attestation back.
        """
        attestation_blobs = self.database.get_attestation_by_hash(payload.hash)
        if not attestation_blobs:
            self.logger.warning("Dropping verification request of unknown hash!")
            return
        attestation_blob, = attestation_blobs
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

    def send_attestation(self, socket_address: Address, blob: bytes, global_time: int | None = None) -> None:
        """
        Send a serialized attestation (blob) to an address, split into chunks.

        If we want to serve this request, send the attestation in chunks of 800 bytes.
        """
        sequence_number = 0
        for i in range(0, len(blob), 800):
            blob_chunk = blob[i:i + 800]
            self.logger.debug("Sending attestation chunk %d to %s", sequence_number, str(socket_address))
            if global_time is None:
                global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
            payload = AttestationChunkPayload(sha1(blob).digest(), sequence_number, blob_chunk)
            dist = GlobalTimeDistributionPayload(global_time)
            packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
            self.endpoint.send(socket_address, packet)

            sequence_number += 1

    @lazy_wrapper(GlobalTimeDistributionPayload, AttestationChunkPayload)
    def on_attestation_chunk(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                             payload: AttestationChunkPayload) -> None:
        """
        We received a chunk of an Attestation.
        """
        hash_id = HashCache.id_from_hash("receive-verify-attestation", payload.hash)
        peer_ids = [PeerCache.id_from_address("receive-request-attestation", peer.mid + allowed_glob)
                    for allowed_glob in self.allowed_attestations.get(peer.mid, [])
                    if allowed_glob == str(dist.global_time).encode('utf-8')]
        if self.request_cache.has(*hash_id):
            rcache = cast(ReceiveAttestationVerifyCache, self.request_cache.get(*hash_id))
            rcache.attestation_map |= {(payload.sequence_number, payload.data), }

            serialized = b""
            for (_, chunk) in sorted(rcache.attestation_map, key=lambda item: item[0]):
                serialized += chunk

            attestation_class = self.get_id_algorithm(rcache.id_format).get_attestation_class()
            if sha1(serialized).digest() == payload.hash:
                unserialized = attestation_class.unserialize(serialized, rcache.id_format)
                self.request_cache.pop(*hash_id)
                self.on_received_attestation(peer, unserialized, payload.hash)

            self.logger.debug("Received attestation chunk %d for proving by %s", payload.sequence_number, str(peer))
        else:
            handled = False
            for peer_id in peer_ids:
                if self.request_cache.has(*peer_id):
                    cache = cast(ReceiveAttestationRequestCache, self.request_cache.get(*peer_id))
                    cache.attestation_map |= {(payload.sequence_number, payload.data), }

                    serialized = b""
                    for (_, chunk) in sorted(cache.attestation_map, key=lambda item: item[0]):
                        serialized += chunk

                    attestation_class = self.get_id_algorithm(cache.id_format).get_attestation_class()
                    if sha1(serialized).digest() == payload.hash:
                        unserialized = attestation_class.unserialize_private(cache.key, serialized, cache.id_format)
                        cache = cast(ReceiveAttestationRequestCache, self.request_cache.pop(*peer_id))
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

    def on_received_attestation(self, peer: Peer, attestation: Attestation, attestation_hash: bytes) -> None:
        """
        Callback for when we got the entire attestation from a peer.

        :param peer: the Peer we got this attestation from
        :param attestation: the Attestation object we can check
        """
        if attestation.id_format is None:
            self.logger.exception("Received %s with None as its id_format: dropping!", str(attestation))
            return
        algorithm = self.get_id_algorithm(attestation.id_format)

        relativity_map = algorithm.create_certainty_aggregate(attestation)
        hashed_challenges = []
        cache = cast(ProvingAttestationCache,
                     self.request_cache.get(*HashCache.id_from_hash("proving-attestation", attestation_hash)))
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
            if self.request_cache.has(*PendingChallengeCache.id_from_hash("proving-hash", sha1(challenge).digest())):
                continue
            remaining -= 1
            self.request_cache.add(PendingChallengeCache(self, sha1(challenge).digest(), cache, cache.id_format))

            global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
            payload = ChallengePayload(attestation_hash, challenge)
            dist = GlobalTimeDistributionPayload(global_time)

            packet = self._ez_pack(self._prefix, 3, [auth, dist, payload])
            self.endpoint.send(peer.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, ChallengePayload)
    def on_challenge(self, peer: Peer, dist: GlobalTimeDistributionPayload, payload: ChallengePayload) -> None:
        """
        We received a challenge for an Attestation.
        """
        SK, id_format = self.attestation_keys[payload.attestation_hash]
        challenge_hash = sha1(payload.challenge).digest()
        algorithm = self.get_id_algorithm(id_format)
        attestation = self.cached_attestation_blobs[payload.attestation_hash]

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        rpayload = ChallengeResponsePayload(challenge_hash,
                                            algorithm.create_challenge_response(SK, attestation, payload.challenge))
        dist = GlobalTimeDistributionPayload(global_time)

        packet = self._ez_pack(self._prefix, 4, [auth, dist, rpayload])
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, ChallengeResponsePayload)
    def on_challenge_response(self, peer: Peer, dist: GlobalTimeDistributionPayload,  # noqa: C901, PLR0912
                              payload: ChallengeResponsePayload) -> None:
        """
        We received a response to our challenge.
        """
        cache = cast(Optional[PendingChallengeCache],
                     self.request_cache.get(*HashCache.id_from_hash("proving-hash", payload.challenge_hash)))
        if cache is not None:
            self.request_cache.pop(*HashCache.id_from_hash("proving-hash", payload.challenge_hash))
            proving_cache = cache.proving_cache
            pcache_prefix, pcache_id = HashCache.id_from_hash("proving-attestation", proving_cache.hash)
            challenge = None
            if payload.challenge_hash in proving_cache.hashed_challenges:
                proving_cache.hashed_challenges.remove(payload.challenge_hash)
                for challenge in proving_cache.challenges[:]:
                    if sha1(challenge).digest() == payload.challenge_hash:
                        proving_cache.challenges.remove(challenge)
                        break
            algorithm = self.get_id_algorithm(proving_cache.id_format)
            if cache.honesty_check < 0:
                bchallenge = cast(bytes, challenge)
                algorithm.process_challenge_response(proving_cache.relativity_map, bchallenge, payload.response)
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
                honesty_check = algorithm.honesty_check and (os.urandom(1)[0] < 38)
                honesty_check_byte = choice([0, 1, 2]) if honesty_check else -1
                challenge = None
                if honesty_check:
                    while not challenge or self.request_cache.has(*HashCache.id_from_hash("proving-hash",
                                                                                          sha1(challenge).digest())):
                        challenge = algorithm.create_honesty_challenge(proving_cache.public_key, honesty_check_byte)
                if (not honesty_check) or (challenge and self.request_cache.has(*HashCache.id_from_hash("proving-hash",
                                                                                                        sha1(
                                                                                                            challenge).digest()))):
                    honesty_check_byte = -1
                    challenge = None
                    for c in proving_cache.challenges:
                        if not self.request_cache.has(*HashCache.id_from_hash("proving-hash", sha1(c).digest())):
                            challenge = c
                            break
                    if not challenge:
                        self.logger.debug("No more bitpairs to challenge!")
                        return
                rchallenge = cast(bytes, challenge)
                self.logger.debug("Sending challenge: %d (%d)", honesty_check_byte,
                                  len(proving_cache.hashed_challenges))
                self.request_cache.add(PendingChallengeCache(self, sha1(rchallenge).digest(), proving_cache,
                                                             cache.id_format, honesty_check_byte))

                global_time = self.claim_global_time()
                auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
                rpayload = ChallengePayload(proving_cache.hash, rchallenge)
                dist = GlobalTimeDistributionPayload(global_time)

                packet = self._ez_pack(self._prefix, 3, [auth, dist, rpayload])
                self.endpoint.send(peer.address, packet)
