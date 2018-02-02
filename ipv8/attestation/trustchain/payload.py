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
    def from_block(cls, block):
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
