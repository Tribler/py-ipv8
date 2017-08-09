"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
import logging
import time
from threading import Lock

from .block import TrustChainBlock, ValidationResult, EMPTY_PK, GENESIS_SEQ, UNKNOWN_SEQ
from .database import TrustChainDB
from ...deprecated.community import Community
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .payload import *
from ...peer import Peer

HALF_BLOCK = u"half_block"
CRAWL = u"crawl"
receive_block_lock = Lock()


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """
    def wrapper(self, *args, **kwargs):
        with receive_block_lock:
            return f(self, *args, **kwargs)
    return wrapper


class TrustChainCommunity(Community):
    """
    Community for reputation based on TrustChain tamper proof interaction history.
    """
    BLOCK_CLASS = TrustChainBlock
    DB_CLASS = TrustChainDB
    DB_NAME = 'trustchain'
    version = '\x01'
    master_peer = Peer(("3081a7301006072a8648ce3d020106052b81040027038192000403428b0fa33d3ed62dd39852481f535e2161714" +
                        "4a95e682ad5733b9a739b27051dc6ad1da743a463821fc8d3d1849191d5fb84fab1f3fe3ad44fb2b83f07d0c78a" +
                        "13b7ad1d311063069f49070cad7dc15620996cdd625c1abcdbfabf750727f1dec706f6f16cb28ce6946fdf39887" +
                        "a84fc457a5f9edc660adbe0a72ea5219f9578dd6432de825c167e80987ca4c6a2bf").decode("HEX"))

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', self.DB_NAME)
        super(TrustChainCommunity, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.persistence = self.DB_CLASS(working_directory, db_name)

        self.logger.debug("The trustchain community started with Public Key: %s",
                          self.my_peer.public_key.key_to_bin().encode("hex"))

        self.decode_map.update({
            chr(1): self.received_half_block,
            chr(2): self.received_crawl_request
        })

    def bootstrap(self):
        pass

    def should_sign(self, payload):
        """
        Return whether we should sign the block in the passed message.
        @param payload: the payload containing a block we want to sign or not.
        """
        return True

    def send_block(self, peer, block):
        self.logger.debug("Sending block to %s (%s)", peer, block)

        global_time = self.claim_global_time()
        payload = HalfBlockPayload.from_block(block).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 1, [dist, payload], False)
        self.endpoint.send(peer.address, packet)

    def sign_block(self, peer, public_key=EMPTY_PK, transaction=None, linked=None):
        """
        Create, sign, persist and send a block signed message
        :param peer: The peer with whom you have interacted, as a dispersy candidate
        :param transaction: A string describing the interaction in this block
        :param linked: The block that the requester is asking us to sign
        """
        # NOTE to the future: This method reads from the database, increments and then writes back. If in some future
        # this method is allowed to execute in parallel, be sure to lock from before .create up to after .add_block
        assert transaction is None and linked is not None or transaction is not None and linked is None, \
            "Either provide a linked block or a transaction, not both"
        assert linked is None or linked.link_public_key == self.my_peer.public_key.key_to_bin(), \
            "Cannot counter sign block not addressed to self"
        assert linked is None or linked.link_sequence_number == UNKNOWN_SEQ, \
            "Cannot counter sign block that is not a request"
        assert transaction is None or isinstance(transaction, dict), "Transaction should be a dictionary"

        block = self.BLOCK_CLASS.create(transaction, self.persistence, self.my_peer.public_key.key_to_bin(),
                                        link=linked, link_pk=public_key)
        block.sign(self.my_peer.key)
        validation = block.validate(self.persistence)
        self.logger.info("Signed block to %s (%s) validation result %s",
                         block.link_public_key.encode("hex")[-8:], block, validation)
        if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
            self.logger.error("Signed block did not validate?! Result %s", repr(validation))
        else:
            self.persistence.add_block(block)
            self.send_block(peer, block)

    @synchronized
    def received_half_block(self, source_address, data):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        :param messages The half block messages
        """
        dist, payload = self._ez_unpack_noauth(HalfBlockPayload, data)
        peer = Peer(payload.public_key, source_address)

        blk = TrustChainBlock([payload.transaction, payload.public_key, payload.sequence_number,
                               payload.link_public_key, payload.link_sequence_number, payload.previous_hash,
                               payload.signature, time.time()], self.serializer)
        validation = blk.validate(self.persistence)
        self.logger.debug("Block validation result %s, %s, (%s)", validation[0], validation[1], blk)
        if validation[0] == ValidationResult.invalid:
            return
        elif not self.persistence.contains(blk):
            self.persistence.add_block(blk)
        else:
            self.logger.debug("Received already known block (%s)", blk)

        # Is this a request, addressed to us, and have we not signed it already?
        if blk.link_sequence_number != UNKNOWN_SEQ or \
                blk.link_public_key != self.my_peer.public_key.key_to_bin() or \
                self.persistence.get_linked(blk) is not None:
            return

        self.logger.info("Received request block addressed to us (%s)", blk)

        # determine if we want to sign this block
        if not self.should_sign(payload):
            return

        # It is important that the request matches up with its previous block, gaps cannot be tolerated at
        # this point. We already dropped invalids, so here we delay this message if the result is partial,
        # partial_previous or no-info. We send a crawl request to the requester to (hopefully) close the gap
        if validation[0] == ValidationResult.partial_previous or validation[0] == ValidationResult.partial or \
                validation[0] == ValidationResult.no_info:
            self.logger.info("Request block could not be validated sufficiently, crawling requester. %s",
                             validation)
            # Note that this code does not cover the scenario where we obtain this block indirectly.

            self.send_crawl_request(peer, blk.public_key, max(GENESIS_SEQ, blk.sequence_number - 5))
        else:
            self.sign_block(peer, linked=blk)

    def send_crawl_request(self, peer, public_key, sequence_number=None):
        sq = sequence_number
        if sequence_number is None:
            blk = self.persistence.get_latest(public_key)
            sq = blk.sequence_number if blk else GENESIS_SEQ
        sq = max(GENESIS_SEQ, sq) if sq >= 0 else sq
        self.logger.info("Requesting crawl of node %s:%d", public_key.encode("hex")[-8:], sq)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = CrawlRequestPayload(sq).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    def received_crawl_request(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(CrawlRequestPayload, data)
        peer = Peer(auth.public_key_bin, source_address)

        self.logger.info("Received crawl request from node %s for sequence number %d",
                         peer.public_key.key_to_bin().encode("hex")[-8:],
                         payload.requested_sequence_number)
        sq = payload.requested_sequence_number
        if sq < 0:
            last_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            # The -1 element is the last_block.seq_nr
            # The -2 element is the last_block.seq_nr - 1
            # Etc. until the genesis seq_nr
            sq = max(GENESIS_SEQ, last_block.sequence_number + (sq + 1)) if last_block else GENESIS_SEQ
        blocks = self.persistence.crawl(self.my_peer.public_key.key_to_bin(), sq)
        count = len(blocks)

        for blk in blocks:
            self.send_block(peer, blk)
        self.logger.info("Sent %d blocks", count)

    def unload(self):
        self.logger.debug("Unloading the TrustChain Community.")

        # Close the persistence layer
        self.persistence.close()

        super(TrustChainCommunity, self).unload()
