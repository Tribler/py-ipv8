from __future__ import absolute_import

from binascii import unhexlify
from time import time

from twisted.internet.defer import succeed

from ..identity_formats import FORMATS
from ...attestation.trustchain.community import TrustChainCommunity
from ...attestation.trustchain.listener import BlockListener
from ...peer import Peer


class IdentityCommunity(TrustChainCommunity, BlockListener):

    master_peer = Peer(unhexlify("307e301006072a8648ce3d020106052b81040024036a000400c9104b573ea18b795cb23b1defe6e5b7"
                                 "41afa4b2b5edfe7d211c9342dfb753a22e850fb1bff01d5ca66cfe0b1a845fa3e333d200b6d742151f"
                                 "3e4db3fe8b8508720744c70afe692c73264f789aa36a8c219acebeaa2b6ba652743d6580300fa1d98d"
                                 "96b766dfcd"))

    DB_NAME = 'identity'

    def __init__(self, *args, **kwargs):
        TrustChainCommunity.__init__(self, *args, **kwargs)
        BlockListener.__init__(self)

        self.add_listener(self, [identity_format.encode('utf-8') for identity_format in FORMATS])

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
            return succeed(False)
        if requested_keys - {b"metadata"} != {b"hash", b"name", b"date"}:
            return succeed(False)
        attribute_hash = transaction[b'hash']
        if attribute_hash not in self.known_attestation_hashes:
            return succeed(False)
        if block.public_key != self.known_attestation_hashes[attribute_hash][2]:
            return succeed(False)
        # Refuse to sign blocks older than 5 minutes
        if time() > self.known_attestation_hashes[attribute_hash][1] + 300:
            return succeed(False)
        if transaction[b'name'] != self.known_attestation_hashes[attribute_hash][0]:
            return succeed(False)
        if (self.known_attestation_hashes[attribute_hash][3]
                and transaction.get(b'metadata', None) != self.known_attestation_hashes[attribute_hash][3]):
            return succeed(False)
        return succeed(True)

    def request_attestation_advertisement(self, peer, attribute_hash, name, block_type="id_metadata", metadata=None):
        """
        Request a peer to sign for our attestation advertisement.
        :param peer: the attestor of our block
        :param attribute_hash: the hash of the attestation
        :param name: the name of the attribute (metadata)
        :param block_type: the type of block (from identity_foromats.py)
        :param metadata: custom additional metadata
        """
        self.sign_block(peer,
                        public_key=peer.public_key.key_to_bin(),
                        block_type=block_type.encode('utf-8'),
                        transaction={
                            b"hash": attribute_hash,
                            b"name": name,
                            b"date": time(),
                            b"metadata": metadata or {}
                        })

    def self_advertise(self, attribute_hash, name, block_type="id_metadata", metadata=None):
        """
        Self-sign an attribute.

        :param attribute_hash: he hash of the attestation
        :param name: the name of the attribute (metadata)
        :param block_type: the type of block (from identity_foromats.py)
        :param metadata: custom additional metadata
        """
        self.create_source_block(block_type=block_type.encode('utf-8'),
                                 transaction={
                                     b"hash": attribute_hash,
                                     b"name": name,
                                     b"date": time(),
                                     b"metadata": metadata or {}
                                 })
