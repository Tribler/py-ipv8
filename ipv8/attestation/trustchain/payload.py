from ...deprecated.payload import Payload
from ...messaging.deprecated.encoding import encode


class CrawlRequestPayload(Payload):
    """
    Request a crawl of blocks starting with a specific sequence number or the first if 0.
    """

    format_list = ['74s', 'l', 'I']

    def __init__(self, requested_sequence_number, crawl_id):
        super(CrawlRequestPayload, self).__init__()
        self.requested_sequence_number = requested_sequence_number
        self.crawl_id = crawl_id

    def to_pack_list(self):
        data = [('74s', '0'*74),
                ('l', self.requested_sequence_number),
                ('I', self.crawl_id)]

        return data

    @classmethod
    def from_unpack_list(cls, public_key, sequence_number, crawl_id):
        return CrawlRequestPayload(sequence_number, crawl_id)


class HalfBlockPayload(Payload):
    """
    Payload for message that ships a half block
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash,
                 signature, transaction):
        super(HalfBlockPayload, self).__init__()
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.link_public_key = link_public_key
        self.link_sequence_number = link_sequence_number
        self.previous_hash = previous_hash
        self.signature = signature
        self.transaction = transaction

    @classmethod
    def from_half_block(cls, block):
        return HalfBlockPayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.previous_hash,
            block.signature,
            block.transaction
        )

    def to_pack_list(self):
        data = [('74s', self.public_key),
                ('I', self.sequence_number),
                ('74s', self.link_public_key),
                ('I', self.link_sequence_number),
                ('32s', self.previous_hash),
                ('64s', self.signature),
                ('varlenI', encode(self.transaction))]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPayload(*args)


class HalfBlockBroadcastPayload(HalfBlockPayload):
    """
    Payload for a message that contains a half block and a TTL field for broadcasts.
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'I']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash,
                 signature, transaction, ttl):
        super(HalfBlockBroadcastPayload, self).__init__(public_key, sequence_number, link_public_key,
                                                        link_sequence_number, previous_hash, signature, transaction)
        self.ttl = ttl

    @classmethod
    def from_half_block(cls, block, ttl):
        return HalfBlockBroadcastPayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.previous_hash,
            block.signature,
            block.transaction,
            ttl
        )

    def to_pack_list(self):
        data = super(HalfBlockBroadcastPayload, self).to_pack_list()
        data.append(('I', self.ttl))
        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockBroadcastPayload(*args)


class CrawlResponsePayload(Payload):
    """
    Payload for the response to a crawl request.
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'I', 'I', 'I']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash, signature,
                 transaction, crawl_id, cur_count, total_count):
        super(CrawlResponsePayload, self).__init__()
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.link_public_key = link_public_key
        self.link_sequence_number = link_sequence_number
        self.previous_hash = previous_hash
        self.signature = signature
        self.transaction = transaction
        self.crawl_id = crawl_id
        self.cur_count = cur_count
        self.total_count = total_count

    @classmethod
    def from_crawl(cls, block, crawl_id, cur_count, total_count):
        return CrawlResponsePayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.previous_hash,
            block.signature,
            block.transaction,
            crawl_id,
            cur_count,
            total_count,
        )

    def to_pack_list(self):
        data = [('74s', self.public_key),
                ('I', self.sequence_number),
                ('74s', self.link_public_key),
                ('I', self.link_sequence_number),
                ('32s', self.previous_hash),
                ('64s', self.signature),
                ('varlenI', encode(self.transaction)),
                ('I', self.crawl_id),
                ('I', self.cur_count),
                ('I', self.total_count)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return CrawlResponsePayload(*args)


class HalfBlockPairPayload(Payload):
    """
    Payload for message that ships two half blocks
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI'] * 2

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, previous_hash1,
                 signature1, transaction1, public_key2, sequence_number2, link_public_key2, link_sequence_number2,
                 previous_hash2, signature2, transaction2):
        super(HalfBlockPairPayload, self).__init__()
        self.public_key1 = public_key1
        self.sequence_number1 = sequence_number1
        self.link_public_key1 = link_public_key1
        self.link_sequence_number1 = link_sequence_number1
        self.previous_hash1 = previous_hash1
        self.signature1 = signature1
        self.transaction1 = transaction1

        self.public_key2 = public_key2
        self.sequence_number2 = sequence_number2
        self.link_public_key2 = link_public_key2
        self.link_sequence_number2 = link_sequence_number2
        self.previous_hash2 = previous_hash2
        self.signature2 = signature2
        self.transaction2 = transaction2

    @classmethod
    def from_half_blocks(cls, block1, block2):
        return HalfBlockPairPayload(
            block1.public_key,
            block1.sequence_number,
            block1.link_public_key,
            block1.link_sequence_number,
            block1.previous_hash,
            block1.signature,
            block1.transaction,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.previous_hash,
            block2.signature,
            block2.transaction
        )

    def to_pack_list(self):
        data = [('74s', self.public_key1),
                ('I', self.sequence_number1),
                ('74s', self.link_public_key1),
                ('I', self.link_sequence_number1),
                ('32s', self.previous_hash1),
                ('64s', self.signature1),
                ('varlenI', encode(self.transaction1)),
                ('74s', self.public_key2),
                ('I', self.sequence_number2),
                ('74s', self.link_public_key2),
                ('I', self.link_sequence_number2),
                ('32s', self.previous_hash2),
                ('64s', self.signature2),
                ('varlenI', encode(self.transaction2))]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairPayload(*args)


class HalfBlockPairBroadcastPayload(HalfBlockPairPayload):
    """
    Payload for a broadcast message that ships two half blocks
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI'] * 2 + ['I']

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, previous_hash1,
                 signature1, transaction1, public_key2, sequence_number2, link_public_key2, link_sequence_number2,
                 previous_hash2, signature2, transaction2, ttl):
        super(HalfBlockPairBroadcastPayload, self).__init__(public_key1, sequence_number1, link_public_key1,
                                                            link_sequence_number1, previous_hash1, signature1,
                                                            transaction1, public_key2, sequence_number2,
                                                            link_public_key2, link_sequence_number2, previous_hash2,
                                                            signature2, transaction2)
        self.ttl = ttl

    @classmethod
    def from_half_blocks(cls, block1, block2, ttl):
        return HalfBlockPairBroadcastPayload(
            block1.public_key,
            block1.sequence_number,
            block1.link_public_key,
            block1.link_sequence_number,
            block1.previous_hash,
            block1.signature,
            block1.transaction,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.previous_hash,
            block2.signature,
            block2.transaction,
            ttl
        )

    def to_pack_list(self):
        data = super(HalfBlockPairBroadcastPayload, self).to_pack_list()
        data.append(('I', self.ttl))
        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairBroadcastPayload(*args)
