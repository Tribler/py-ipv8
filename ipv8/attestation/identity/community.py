from __future__ import absolute_import

from binascii import unhexlify
from time import time

from ...attestation.trustchain.community import TrustChainCommunity
from ...attestation.trustchain.listener import BlockListener
from ...peer import Peer


class IdentityCommunity(TrustChainCommunity, BlockListener):

    master_peer = Peer(unhexlify("3081a7301006072a8648ce3d020106052b810400270381920004009ad2a2e35c328a3e92019873820d"
                                 "70b53b82a752490febbce8bbbe2531a06a165121b8068e674236f26055a59b12c2139445f14dd86c4c"
                                 "3c9598e8c999109f184556dac595f69001b5b16d2c14fe5f641f1a25227152df1989f0c8fb71a107ec"
                                 "55e8e67f464391491c2390bb53fc9b314c7eeb46be1955024ad9e632130e4e92e61295ed1bb1783663"
                                 "fd47fae71293"))

    def __init__(self, *args, **kwargs):
        super(IdentityCommunity, self).__init__(*args, **kwargs)

        self.add_listener(self, [b'id_metadata'])

        # Dict of hash -> (attribute_name, date, public_key)
        self.known_attestation_hashes = {}

    def add_known_hash(self, attribute_hash, name, public_key, metadata=None):
        """
        We know about this hash+peer combination. Thus we can handle sign requests for it.
        """
        self.known_attestation_hashes[attribute_hash] = (name, time(), public_key, metadata)

    def get_attestation_by_hash(self, attribute_hash):
        blocks = self.persistence.get_all_blocks()
        for block in blocks:
            if block.transaction and block.transaction.get(b"hash", None) == attribute_hash:
                return block
        return None

    def received_block(self, block):
        pass

    def should_sign(self, block):
        transaction = block.transaction
        requested_keys = set(transaction.keys())
        if requested_keys - {b"hash", b"name", b"date", b"metadata"} != set():
            return False
        if requested_keys - {b"metadata"} != {b"hash", b"name", b"date"}:
            return False
        attribute_hash = transaction[b'hash']
        if attribute_hash not in self.known_attestation_hashes:
            return False
        if block.public_key != self.known_attestation_hashes[attribute_hash][2]:
            return False
        # Refuse to sign blocks older than 5 minutes
        if time() > self.known_attestation_hashes[attribute_hash][1] + 300:
            return False
        if transaction[b'name'] != self.known_attestation_hashes[attribute_hash][0]:
            return False
        if (self.known_attestation_hashes[attribute_hash][3] and
                transaction.get(b'metadata', None) != self.known_attestation_hashes[attribute_hash][3]):
            return False
        return True

    def request_attestation_advertisement(self, peer, attribute_hash, name, metadata=None):
        """
        Request a peer to sign for our attestation advertisement.
        :param peer: the attestor of our block
        :param attribute_hash: the hash of the attestation
        :param name: the name of the attribute (metadata)
        """
        self.sign_block(peer,
                        public_key=peer.public_key.key_to_bin(),
                        block_type=b"id_metadata",
                        transaction={
                            b"hash": attribute_hash,
                            b"name": name,
                            b"date": time(),
                            b"metadata": metadata or {}
                        })
