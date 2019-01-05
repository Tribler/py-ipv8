from __future__ import absolute_import

import time
from _sha256 import sha256
from binascii import hexlify

from ..trustchain.payload import HalfBlockPayload
from ...database import database_blob
from ...keyvault.crypto import default_eccrypto
from ...util import old_round
from ...messaging.serialization import default_serializer
from ...messaging.deprecated.encoding import decode, encode

GENESIS_HASH = b'0' * 32  # ID of the first block of the chain.
GENESIS_SEQ = 1
UNKNOWN_SEQ = 0
EMPTY_SIG = b'0' * 64
EMPTY_PK = b'0' * 74
ANY_COUNTERPARTY_PK = EMPTY_PK


class BobChainBlock(object):
    """
    Container for BobChain block information
    """

    def __init__(self, data=None, serializer=default_serializer):
        super(BobChainBlock, self).__init__()
        self.serializer = serializer

        # TODO see what is needed from below
        if data is None:
            # data
            self.type = b'unknown'
            self.transaction = {}
            self._transaction = encode({})
            # identity
            self.public_key = EMPTY_PK
            self.sequence_number = GENESIS_SEQ
            # linked identity
            self.link_public_key = EMPTY_PK
            self.link_sequence_number = UNKNOWN_SEQ
            # validation
            self.previous_hash = GENESIS_HASH
            self.signature = EMPTY_SIG
            self.timestamp = int(old_round(time.time() * 1000))
            # debug stuff
            self.insert_time = None
        else:
            self._transaction = data[1] if isinstance(data[1], bytes) else str(data[1])
            _, self.transaction = decode(self._transaction)
            (self.type, self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number,
             self.previous_hash, self.signature, self.timestamp, self.insert_time) = (data[0], data[2], data[3],
                                                                                      data[4], data[5], data[6],
                                                                                      data[7], data[8], data[9])
            self.type = self.type if isinstance(self.type, bytes) else str(self.type)
            self.public_key = self.public_key if isinstance(self.public_key, bytes) else str(self.public_key)
            self.link_public_key = (self.link_public_key if isinstance(self.link_public_key, bytes)
                                    else str(self.link_public_key))
            self.previous_hash = (self.previous_hash if isinstance(self.previous_hash, bytes)
                                  else str(self.previous_hash))
            self.signature = self.signature if isinstance(self.signature, bytes) else str(self.signature)
        self.hash = self.calculate_hash()
        self.crypto = default_eccrypto

    @classmethod
    def create(cls, block_type, transaction, database, public_key, link=None, additional_info=None, link_pk=None):
        """
        Create an empty next block.
        :param block_type: the type of the block to be constructed
        :param transaction: the transaction to use in this block
        :param database: the database to use as information source
        :param public_key: the public key to use for this block
        :param link: optionally create the block as a linked block to this block
        :param additional_info: additional information, which has a higher priority than the
               transaction when link exists
        :param link_pk: the public key of the counterparty in this transaction
        :return: A newly created block
        """
        blk = database.get_latest(public_key)
        ret = cls()
        if link:
            ret.type = link.type if link.link_public_key != ANY_COUNTERPARTY_PK else block_type
            ret.transaction = link.transaction if additional_info is None else additional_info
            ret.link_public_key = link.public_key
            ret.link_sequence_number = link.sequence_number
        else:
            ret.type = block_type
            ret.transaction = transaction
            ret.link_public_key = link_pk or EMPTY_PK
            ret.link_sequence_number = UNKNOWN_SEQ

        if blk:
            ret.sequence_number = blk.sequence_number + 1
            ret.previous_hash = blk.hash

        ret._transaction = encode(ret.transaction)
        ret.public_key = public_key
        ret.signature = EMPTY_SIG
        ret.hash = ret.calculate_hash()
        return ret

    @property
    def block_id(self):
        return b"%s.%d" % (hexlify(self.public_key), self.sequence_number)

    @property
    def linked_block_id(self):
        return b"%s.%d" % (hexlify(self.link_public_key), self.link_sequence_number)

    @property
    def is_genesis(self):
        return self.sequence_number == GENESIS_SEQ or self.previous_hash == GENESIS_HASH

    def sign(self, key):
        """
        Signs this block with the given key
        :param key: the key to sign this block with
        """
        self.signature = self.crypto.create_signature(key, self.pack(signature=False))
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return sha256(self.pack()).digest()

    def pack_db_insert(self):
        """
        Prepare a tuple to use for inserting into the database
        :return: A database insertable tuple
        """
        return (self.type, database_blob(self._transaction), database_blob(self.public_key),
                self.sequence_number, database_blob(self.link_public_key), self.link_sequence_number,
                database_blob(self.previous_hash), database_blob(self.signature), self.timestamp,
                database_blob(self.hash))

    def pack(self, signature=True):
        """
        Encode this block for transport
        :param signature: False to pack EMPTY_SIG in the signature location, true to pack the signature field
        :return: the database_blob the data was packed into
        """
        args = [self.public_key, self.sequence_number, self.link_public_key, self.link_sequence_number,
                self.previous_hash, self.signature if signature else EMPTY_SIG, self.type, self._transaction,
                self.timestamp]
        return self.serializer.pack_multiple(HalfBlockPayload(*args).to_pack_list())[0]
