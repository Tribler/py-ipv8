from ...messaging.payload import Payload


class CrawlRequestPayload(Payload):
    """
    Request a crawl of blocks starting with a specific sequence number or the first if 0.
    """

    format_list = ['74s', 'l', 'l', 'I']

    def __init__(self, public_key, start_seq_num, end_seq_num, crawl_id):
        super(CrawlRequestPayload, self).__init__()
        self.public_key = public_key
        self.start_seq_num = start_seq_num
        self.end_seq_num = end_seq_num
        self.crawl_id = crawl_id

    def to_pack_list(self):
        data = [('74s', self.public_key),
                ('l', self.start_seq_num),
                ('l', self.end_seq_num),
                ('I', self.crawl_id)]

        return data

    @classmethod
    def from_unpack_list(cls, public_key, start_seq_num, end_seq_num, crawl_id):
        return CrawlRequestPayload(public_key, start_seq_num, end_seq_num, crawl_id)


class EmptyCrawlResponsePayload(Payload):
    """
    Payload for the message that indicates that there are no blocks to respond.
    """

    format_list = ['I']

    def __init__(self, crawl_id):
        super(EmptyCrawlResponsePayload, self).__init__()
        self.crawl_id = crawl_id

    def to_pack_list(self):
        data = [('I', self.crawl_id)]
        return data

    @classmethod
    def from_unpack_list(cls, crawl_id):
        return EmptyCrawlResponsePayload(crawl_id)


class HalfBlockPayload(Payload):
    """
    Payload for message that ships a half block
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash,
                 signature, block_type, transaction, timestamp):
        super(HalfBlockPayload, self).__init__()
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.link_public_key = link_public_key
        self.link_sequence_number = link_sequence_number
        self.previous_hash = previous_hash
        self.signature = signature
        self.type = block_type
        self.transaction = transaction
        self.timestamp = timestamp

    @classmethod
    def from_half_block(cls, block):
        return HalfBlockPayload(
            block.public_key,
            block.sequence_number,
            block.link_public_key,
            block.link_sequence_number,
            block.previous_hash,
            block.signature,
            block.type,
            block._transaction,
            block.timestamp
        )

    def to_pack_list(self):
        data = [('74s', self.public_key),
                ('I', self.sequence_number),
                ('74s', self.link_public_key),
                ('I', self.link_sequence_number),
                ('32s', self.previous_hash),
                ('64s', self.signature),
                ('varlenI', self.type),
                ('varlenI', self.transaction),
                ('Q', self.timestamp)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPayload(*args)


class HalfBlockBroadcastPayload(HalfBlockPayload):
    """
    Payload for a message that contains a half block and a TTL field for broadcasts.
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q', 'I']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash,
                 signature, block_type, transaction, timestamp, ttl):
        super(HalfBlockBroadcastPayload, self).__init__(public_key, sequence_number, link_public_key,
                                                        link_sequence_number, previous_hash, signature,
                                                        block_type, transaction, timestamp)
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
            block.type,
            block._transaction,
            block.timestamp,
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

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q', 'I', 'I', 'I']

    def __init__(self, public_key, sequence_number, link_public_key, link_sequence_number, previous_hash, signature,
                 block_type, transaction, timestamp, crawl_id, cur_count, total_count):
        super(CrawlResponsePayload, self).__init__()
        self.public_key = public_key
        self.sequence_number = sequence_number
        self.link_public_key = link_public_key
        self.link_sequence_number = link_sequence_number
        self.previous_hash = previous_hash
        self.signature = signature
        self.type = block_type
        self.transaction = transaction
        self.timestamp = timestamp
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
            block.type,
            block._transaction,
            block.timestamp,
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
                ('varlenI', self.type),
                ('varlenI', self.transaction),
                ('Q', self.timestamp),
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

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q'] * 2

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, previous_hash1,
                 signature1, block_type1, transaction1, timestamp1, public_key2, sequence_number2, link_public_key2,
                 link_sequence_number2, previous_hash2, signature2, block_type2, transaction2, timestamp2):
        super(HalfBlockPairPayload, self).__init__()
        self.public_key1 = public_key1
        self.sequence_number1 = sequence_number1
        self.link_public_key1 = link_public_key1
        self.link_sequence_number1 = link_sequence_number1
        self.previous_hash1 = previous_hash1
        self.signature1 = signature1
        self.type1 = block_type1
        self.transaction1 = transaction1
        self.timestamp1 = timestamp1

        self.public_key2 = public_key2
        self.sequence_number2 = sequence_number2
        self.link_public_key2 = link_public_key2
        self.link_sequence_number2 = link_sequence_number2
        self.previous_hash2 = previous_hash2
        self.signature2 = signature2
        self.type2 = block_type2
        self.transaction2 = transaction2
        self.timestamp2 = timestamp2

    @classmethod
    def from_half_blocks(cls, block1, block2):
        return HalfBlockPairPayload(
            block1.public_key,
            block1.sequence_number,
            block1.link_public_key,
            block1.link_sequence_number,
            block1.previous_hash,
            block1.signature,
            block1.type,
            block1._transaction,
            block1.timestamp,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.previous_hash,
            block2.signature,
            block2.type,
            block2._transaction,
            block2.timestamp
        )

    def to_pack_list(self):
        data = [('74s', self.public_key1),
                ('I', self.sequence_number1),
                ('74s', self.link_public_key1),
                ('I', self.link_sequence_number1),
                ('32s', self.previous_hash1),
                ('64s', self.signature1),
                ('varlenI', self.type1),
                ('varlenI', self.transaction1),
                ('Q', self.timestamp1),
                ('74s', self.public_key2),
                ('I', self.sequence_number2),
                ('74s', self.link_public_key2),
                ('I', self.link_sequence_number2),
                ('32s', self.previous_hash2),
                ('64s', self.signature2),
                ('varlenI', self.type2),
                ('varlenI', self.transaction2),
                ('Q', self.timestamp2)]

        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairPayload(*args)


class HalfBlockPairBroadcastPayload(HalfBlockPairPayload):
    """
    Payload for a broadcast message that ships two half blocks
    """

    format_list = ['74s', 'I', '74s', 'I', '32s', '64s', 'varlenI', 'varlenI', 'Q'] * 2 + ['I']

    def __init__(self, public_key1, sequence_number1, link_public_key1, link_sequence_number1, previous_hash1,
                 signature1, block_type1, transaction1, timestamp1, public_key2, sequence_number2, link_public_key2,
                 link_sequence_number2, previous_hash2, signature2, block_type2, transaction2, timestamp2, ttl):
        super(HalfBlockPairBroadcastPayload, self).__init__(public_key1, sequence_number1, link_public_key1,
                                                            link_sequence_number1, previous_hash1, signature1,
                                                            block_type1, transaction1, timestamp1, public_key2,
                                                            sequence_number2, link_public_key2, link_sequence_number2,
                                                            previous_hash2, signature2, block_type2, transaction2,
                                                            timestamp2)
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
            block1.type,
            block1._transaction,
            block1.timestamp,
            block2.public_key,
            block2.sequence_number,
            block2.link_public_key,
            block2.link_sequence_number,
            block2.previous_hash,
            block2.signature,
            block2.type,
            block2._transaction,
            block2.timestamp,
            ttl
        )

    def to_pack_list(self):
        data = super(HalfBlockPairBroadcastPayload, self).to_pack_list()
        data.append(('I', self.ttl))
        return data

    @classmethod
    def from_unpack_list(cls, *args):
        return HalfBlockPairBroadcastPayload(*args)


class DHTBlockPayload(Payload):
    """
    Class which represents the payloads published to the DHT for disseminating chunks of TrustChain blocks
    """
    format_list = ['64s', 'H', 'H', 'H', 'raw']
    PREAMBLE_OVERHEAD = 70  # This stems from the 64 byte signature and the 6 bytes of unsigned shorts

    def __init__(self, signature, version, block_position, block_count, payload):
        """
        Construct a DHTBlockPayload object (which generally represents a chuck of a TrustChain block),
        which should normally be serialized and published to the DHT

        :param signature: A signature of this block's body (version + block_position + block_count + payload)
        :param version: This block's version (greater values indicate newer blocks)
        :param block_position: This chunk's position in the original block (among the other chunks)
        :param block_count: The total number of chunks in the block
        :param payload: The chunk itself
        """
        super(DHTBlockPayload, self).__init__()
        self.signature = signature
        self.version = version
        self.block_position = block_position
        self.block_count = block_count
        self.payload = payload

    def to_pack_list(self):
        return [
            ('64s', self.signature),
            ('H', self.version),
            ('H', self.block_position),
            ('H', self.block_count),
            ('raw', self.payload)
        ]

    @classmethod
    def from_unpack_list(cls, signature, version, payload, block_position, block_count):
        return DHTBlockPayload(signature, version, payload, block_position, block_count)
