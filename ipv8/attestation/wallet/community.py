import json
from hashlib import sha1

from .database import AttestationsDB
from ...deprecated.community import Community
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .payload import *
from .primitives.attestation import (attest_sha512, binary_relativity_certainty, create_challenge,
                                     create_challenge_response_from_pair, create_empty_relativity_map,
                                     process_challenge_response)
from .primitives.structs import Attestation, BonehPrivateKey, BonehPublicKey, pack_pair, unpack_pair
from ...peer import Peer


class AttestationCommunity(Community):
    """
    Community for sharing Attestations.

    Note that the logic for giving out Attestations is in the TrustChain.
    """
    version = '\x01'
    master_peer = Peer(("3081a7301006072a8648ce3d020106052b810400270381920004057a009787f66ea54d5082ea2f56a842488e319" +
                        "c14c98967c39286433233f769a73e9c894149cf9053a9a0c2548f07171df9c46c3bdb106afa9e9a8a06926e0ec3" +
                        "5871c91f2ab1a20651d0a7b5fda209a3500a09b630a193b281a266230472ef0cc0622c793dc18eed6c57d7bcd1e" +
                        "eca33e2e38277ea99c28d4c62f850f81b5eb3eb19fcb601747bd87aa0b04e360ae9").decode("HEX"))

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', 'attestations')

        super(AttestationCommunity, self).__init__(*args, **kwargs)

        self.database = AttestationsDB(working_directory, db_name)
        self.attestation_request_callbacks = [lambda x, y: None, lambda x, y, z: None]

        # Map of attestation hash -> BonehPrivateKey
        self.attestation_keys = {}
        for hash, _, key in self.database.get_all():
            self.attestation_keys[hash] = BonehPrivateKey(key)
        # Map of attestation hash -> set((index, serialized attestation), )
        self.attestation_map = {}
        # List of ([proof hash, ], relativity map)
        self.proofs = []
        # Callbacks for when an attestation is complete
        self.attestation_callbacks = {}
        # Pending keys for attestation requests
        self.pending_keys = []

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
        f should accept a (Peer, attribute_name, hash), it is called when an Attestation
        has been made for another peer

        :param f: the function to call when an Attestation has been completed
        """
        self.attestation_request_callbacks[1] = f

    def request_attestation(self, socket_address, attribute_name, secret_key):
        """
        Request attestation of one of our attributes.

        :param socket_address: address of the Attestor
        :param attribute_name: the attribute we want attested
        :param secret_key: the secret key we use for this attribute
        """
        public_key = secret_key.public_key()
        self.pending_keys.append(secret_key)

        metadata = json.dumps({
            "attribute": attribute_name,
            "public_key": public_key.serialize().encode('base64')
        })

        self.attestation_map[socket_address] = set()

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = RequestAttestationPayload(metadata).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 5, [auth, dist, payload])
        self.endpoint.send(socket_address, packet)

    def on_request_attestation(self, source_address, data):
        """
        Someone wants us to attest their attribute.
        """
        auth, dist, payload = self._ez_unpack_auth(RequestAttestationPayload, data)
        peer = Peer(auth.public_key_bin, source_address)

        metadata = json.loads(payload.metadata)

        value = self.attestation_request_callbacks[0](peer, metadata['attribute'])
        if value is None:
            return

        PK = BonehPublicKey.unserialize(metadata['public_key'].decode('base64'))
        attestation_blob = attest_sha512(PK, value).serialize()

        self.attestation_request_callbacks[1](peer, metadata['attribute'], sha1(attestation_blob).digest())

        self.send_attestation(source_address, attestation_blob)

    def on_attestation_complete(self, unserialized):
        """
        We got an Attestation delivered to us.
        """
        secret_key = None
        index = -1
        for i in range(len(self.pending_keys)):
            key = self.pending_keys[i]
            if key.public_key().serialize() == unserialized.PK.serialize():
                secret_key = key
                index = i
                break
        if index == -1 or not secret_key:
            return
        del self.pending_keys[index]
        self.database.insert_attestation(unserialized, secret_key)

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
        self.attestation_callbacks[hash] = on_complete
        self.create_verify_attestation_request(socket_address, hash)

    def create_verify_attestation_request(self, socket_address, hash):
        """
        Ask the peer behind a socket address to deliver the Attestation with a certain hash.

        :param socket_address: the socket address to send to
        :param hash: the hash of the Attestation to request
        """
        self.attestation_map[hash] = set()

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

        if payload.hash in self.attestation_map:
            self.attestation_map[payload.hash] |= {(payload.sequence_number, payload.data), }

            serialized = ""
            for (_, chunk) in sorted(self.attestation_map[payload.hash], key=lambda item: item[0]):
                serialized += chunk

            try:
                unserialized = Attestation.unserialize(serialized)
                if sha1(serialized).digest() == payload.hash:
                    del self.attestation_map[payload.hash]
                    peer = Peer(auth.public_key_bin, source_address)
                    self.on_received_attestation(peer, unserialized, payload.hash)
            except:
                pass
        elif source_address in self.attestation_map:
            self.attestation_map[source_address] |= {(payload.sequence_number, payload.data), }

            serialized = ""
            for (_, chunk) in sorted(self.attestation_map[source_address], key=lambda item: item[0]):
                serialized += chunk

            try:
                unserialized = Attestation.unserialize(serialized)
                if sha1(serialized).digest() == payload.hash:
                    del self.attestation_map[source_address]
                    self.on_attestation_complete(unserialized)
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
        for bitpair in attestation.bitpairs:
            challenge = create_challenge(attestation.PK, bitpair)
            serialized = pack_pair(challenge.a, challenge.b)
            challenges.append(serialized)
            hashed_challenges.append(sha1(serialized).digest())
        self.proofs.append((hashed_challenges, relativity_map, attestation_hash))

        # TODO: Don't send this all at once
        for challenge in challenges:
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

    def on_challenge_response(self, source_address, data):
        """
        We received a response to our challenge
        """
        auth, dist, payload = self._ez_unpack_auth(ChallengeResponsePayload, data)

        completed = -1
        for i in range(len(self.proofs)):
            challenges, relativity_map, _ = self.proofs[i]
            if payload.challenge_hash in challenges:
                challenges.remove(payload.challenge_hash)
                process_challenge_response(relativity_map, payload.response)
                if len(challenges) == 0:
                    completed = i
                break

        if completed != -1:
            _, relativity_map, attestation_hash = self.proofs[completed]
            del self.proofs[completed]
            if attestation_hash in self.attestation_callbacks:
                self.attestation_callbacks[attestation_hash](attestation_hash, relativity_map)
            del self.attestation_callbacks[attestation_hash]
