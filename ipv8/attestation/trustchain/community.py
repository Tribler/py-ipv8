"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

from binascii import hexlify, unhexlify
import logging
import random
import struct
from threading import RLock

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed, fail
from twisted.internet.task import LoopingCall

from ...attestation.trustchain.settings import TrustChainSettings
from .block import TrustChainBlock, ValidationResult, EMPTY_PK, GENESIS_SEQ, UNKNOWN_SEQ, ANY_COUNTERPARTY_PK
from .caches import CrawlRequestCache, HalfBlockSignCache, IntroCrawlTimeout, ChainCrawlCache
from .database import TrustChainDB
from ...deprecated.community import Community
from ...deprecated.lazy_community import lazy_wrapper, lazy_wrapper_unsigned, lazy_wrapper_unsigned_wd, lazy_wrapper_wd
from ...deprecated.payload import IntroductionResponsePayload
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .payload import *
from ...peer import Peer
from ...requestcache import RandomNumberCache, RequestCache
from ...util import grange

receive_block_lock = RLock()


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
    master_peer = Peer(unhexlify("3081a7301006072a8648ce3d020106052b810400270381920004026c015f205478073708b9a50b0e74"
                                 "60139b615ba34830b3b3a288e41480eda48ad6adfb39d3d17636169fc06cc68844b5e6ef4e264faa96"
                                 "76f487bb4e445ca52188076296fb9a9a037c37d977cd0fff8b367318a088ad64b46b1e947eab3356e1"
                                 "50cf14a3a4b58c6ee59a33ce7036f2c39e0099b68c8cf7430d88ad2b67a4565e07b1e37e94dbc832fb"
                                 "b4b1927fc297"))

    DB_CLASS = TrustChainDB
    DB_NAME = 'trustchain'
    version = b'\x02'

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', self.DB_NAME)
        self.settings = kwargs.pop('settings', TrustChainSettings())
        super(TrustChainCommunity, self).__init__(*args, **kwargs)
        self.request_cache = RequestCache()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.persistence = self.DB_CLASS(working_directory, db_name)
        self.relayed_broadcasts = []
        self.logger.debug("The trustchain community started with Public Key: %s",
                          hexlify(self.my_peer.public_key.key_to_bin()))
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]
        self.db_cleanup_lc = self.register_task("db_cleanup", LoopingCall(self.do_db_cleanup))
        self.db_cleanup_lc.start(600)

        self.decode_map.update({
            chr(1): self.received_half_block,
            chr(2): self.received_crawl_request,
            chr(3): self.received_crawl_response,
            chr(4): self.received_half_block_pair,
            chr(5): self.received_half_block_broadcast,
            chr(6): self.received_half_block_pair_broadcast,
            chr(7): self.received_empty_crawl_response,
        })

    def do_db_cleanup(self):
        """
        Cleanup the database if necessary.
        """
        blocks_in_db = self.persistence.get_number_of_known_blocks()
        if blocks_in_db > self.settings.max_db_blocks:
            my_pk = self.my_peer.public_key.key_to_bin()
            self.persistence.remove_old_blocks(blocks_in_db - self.settings.max_db_blocks, my_pk)

    def add_listener(self, listener, block_types):
        """
        Add a listener for specific block types.
        """
        for block_type in block_types:
            if block_type not in self.listeners_map:
                self.listeners_map[block_type] = []
            self.listeners_map[block_type].append(listener)
            self.persistence.block_types[block_type] = listener.BLOCK_CLASS

    def remove_listener(self, listener, block_types):
        for block_type in block_types:
            if block_type in self.listeners_map and listener in self.listeners_map[block_type]:
                self.listeners_map[block_type].remove(listener)
            if block_type in self.persistence.block_types:
                self.persistence.block_types.pop(block_type, None)

    def get_block_class(self, block_type):
        """
        Get the block class for a specific block type.
        """
        if block_type not in self.listeners_map or not self.listeners_map[block_type]:
            return TrustChainBlock

        return self.listeners_map[block_type][0].BLOCK_CLASS

    def should_sign(self, block):
        """
        Return whether we should sign the block in the passed message.
        @param block: the block we want to sign or not.
        """
        if block.type not in self.listeners_map:
            return False  # There are no listeners for this block

        for listener in self.listeners_map[block.type]:
            if listener.should_sign(block):
                return True

        return False

    def send_block(self, block, address=None, ttl=1):
        """
        Send a block to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.debug("Sending block to (%s:%d) (%s)", address[0], address[1], block)
            payload = HalfBlockPayload.from_half_block(block).to_pack_list()
            packet = self._ez_pack(self._prefix, 1, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:
            self.logger.debug("Broadcasting block %s", block)
            payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 5, [dist, payload], False)
            for peer in random.sample(self.network.verified_peers, min(len(self.network.verified_peers),
                                                                       self.settings.broadcast_fanout)):
                self.endpoint.send(peer.address, packet)
            self.relayed_broadcasts.append(block.block_id)

    def send_block_pair(self, block1, block2, address=None, ttl=1):
        """
        Send a half block pair to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.debug("Sending block pair to (%s:%d) (%s and %s)", address[0], address[1], block1, block2)
            payload = HalfBlockPairPayload.from_half_blocks(block1, block2).to_pack_list()
            packet = self._ez_pack(self._prefix, 4, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:
            self.logger.debug("Broadcasting blocks %s and %s", block1, block2)
            payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            for peer in random.sample(self.network.verified_peers, min(len(self.network.verified_peers),
                                                                       self.settings.broadcast_fanout)):
                self.endpoint.send(peer.address, packet)
            self.relayed_broadcasts.append(block1.block_id)

    def self_sign_block(self, block_type=b'unknown', transaction=None):
        self.sign_block(self.my_peer, block_type=block_type, transaction=transaction)

    def create_source_block(self, block_type=b'unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: None
        """
        self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK, block_type=block_type, transaction=transaction)

    def create_link(self, source, block_type=b'unknown', additional_info=None, public_key=None):
        """
        Create a Link Block to a source block

        :param source: The source block which had no initial counterpary to sign
        :param block_type: The type of the block to be constructed, as a string
        :param additional_info: a dictionary with supplementary information concerning the transaction
        :param public_key: The public key of the counterparty (usually of the source's owner)
        :return: None
        """
        public_key = source.public_key if public_key is None else public_key

        self.sign_block(self.my_peer, linked=source, public_key=public_key, block_type=block_type,
                        additional_info=additional_info)

    @synchronized
    def sign_block(self, peer, public_key=EMPTY_PK, block_type=b'unknown', transaction=None, linked=None,
                   additional_info=None):
        """
        Create, sign, persist and send a block signed message
        :param peer: The peer with whom you have interacted, as a IPv8 peer
        :param public_key: The public key of the other party you transact with
        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :param linked: The block that the requester is asking us to sign
        :param additional_info: Stores additional information, on the transaction
        """
        # NOTE to the future: This method reads from the database, increments and then writes back. If in some future
        # this method is allowed to execute in parallel, be sure to lock from before .create up to after .add_block

        # In this particular case there must be an implicit transaction due to the following assert
        assert peer is not None or peer is None and linked is None and public_key == ANY_COUNTERPARTY_PK, \
            "Peer, linked block should not be provided when creating a no counterparty source block. Public key " \
            "should be that reserved for any counterpary."
        assert transaction is None and linked is not None or transaction is not None and linked is None, \
            "Either provide a linked block or a transaction, not both %s, %s" % (peer, self.my_peer)
        assert additional_info is None or additional_info is not None and linked is not None and \
               transaction is None and peer == self.my_peer and public_key == linked.public_key, \
            "Either no additional info is provided or one provides it for a linked block"
        assert linked is None or linked.link_public_key == self.my_peer.public_key.key_to_bin() or \
               linked.link_public_key == ANY_COUNTERPARTY_PK, "Cannot counter sign block not addressed to self"
        assert linked is None or linked.link_sequence_number == UNKNOWN_SEQ, \
            "Cannot counter sign block that is not a request"
        assert transaction is None or isinstance(transaction, dict), "Transaction should be a dictionary"
        assert additional_info is None or isinstance(additional_info, dict), "Additional info should be a dictionary"

        self.persistence_integrity_check()
        block_type = linked.type if linked else block_type
        block = self.get_block_class(block_type).create(block_type, transaction, self.persistence,
                                                        self.my_peer.public_key.key_to_bin(),
                                                        link=linked, additional_info=additional_info,
                                                        link_pk=public_key)
        block.sign(self.my_peer.key)

        validation = block.validate(self.persistence)
        self.logger.info("Signed block to %s (%s) validation result %s",
                         hexlify(block.link_public_key)[-8:], block, validation)
        if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
            self.logger.error("Signed block did not validate?! Result %s", repr(validation))
            return fail(RuntimeError("Signed block did not validate."))

        if not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        # This is a source block with no counterparty
        if not peer and public_key == ANY_COUNTERPARTY_PK:
            if self.settings.broadcast_blocks:
                self.send_block(block)
            return

        # If there is a counterparty to sign, we send it
        self.send_block(block, address=peer.address)

        # We broadcast the block in the network if we initiated a transaction
        if self.settings.broadcast_blocks and not linked:
            self.send_block(block)

        if peer == self.my_peer:
            # We created a self-signed block
            if self.settings.broadcast_blocks:
                self.send_block(block)

            return succeed((block, None)) if public_key == ANY_COUNTERPARTY_PK else succeed((block, linked))
        elif not linked:
            # We keep track of this outstanding sign request.
            sign_deferred = Deferred()
            self.request_cache.add(HalfBlockSignCache(self, block, sign_deferred))
            return sign_deferred
        else:
            # We return a deferred that fires immediately with both half blocks.
            if self.settings.broadcast_blocks:
                self.send_block_pair(linked, block)

            return succeed((linked, block))

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPayload)
    def received_half_block(self, source_address, dist, payload):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        """
        peer = Peer(payload.public_key, source_address)
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.process_half_block(block, peer)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockBroadcastPayload)
    def received_half_block_broadcast(self, source_address, dist, payload):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.validate_persist_block(block)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            self.send_block(block, ttl=payload.ttl - 1)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairPayload)
    def received_half_block_pair(self, source_address, dist, payload):
        """
        We received a block pair message.
        """
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairBroadcastPayload)
    def received_half_block_pair_broadcast(self, source_address, dist, payload):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        payload.ttl -= 1
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

        if block1.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            self.send_block_pair(block1, block2, ttl=payload.ttl - 1)

    def validate_persist_block(self, block):
        """
        Validate a block and if it's valid, persist it. Return the validation result.
        :param block: The block to validate and persist.
        :return: [ValidationResult]
        """
        validation = block.validate(self.persistence)
        if validation[0] == ValidationResult.invalid:
            pass
        elif not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        return validation

    def notify_listeners(self, block):
        """
        Notify listeners of a specific new block.
        """
        if block.type not in self.listeners_map or self.shutting_down:
            return

        for listener in self.listeners_map[block.type]:
            listener.received_block(block)

    @synchronized
    def process_half_block(self, blk, peer):
        """
        Process a received half block.
        """
        validation = self.validate_persist_block(blk)
        self.logger.info("Block validation result %s, %s, (%s)", validation[0], validation[1], blk)
        if validation[0] == ValidationResult.invalid:
            return

        # Check if we are waiting for this signature response
        link_block_id_int = int(hexlify(blk.linked_block_id), 16) % 100000000
        if self.request_cache.has(u'sign', link_block_id_int):
            cache = self.request_cache.pop(u'sign', link_block_id_int)

            # We cannot guarantee that we're on a reactor thread so make sure we do this Twisted stuff on the reactor.
            reactor.callFromThread(cache.sign_deferred.callback, (blk, self.persistence.get_linked(blk)))

        # Is this a request, addressed to us, and have we not signed it already?
        if blk.link_sequence_number != UNKNOWN_SEQ or \
                        blk.link_public_key != self.my_peer.public_key.key_to_bin() or \
                        self.persistence.get_linked(blk) is not None:
            return

        self.logger.info("Received request block addressed to us (%s)", blk)

        # determine if we want to sign this block
        if not self.should_sign(blk):
            self.logger.info("Not signing block %s", blk)
            return

        # It is important that the request matches up with its previous block, gaps cannot be tolerated at
        # this point. We already dropped invalids, so here we delay this message if the result is partial,
        # partial_previous or no-info. We send a crawl request to the requester to (hopefully) close the gap
        if (validation[0] == ValidationResult.partial_previous or validation[0] == ValidationResult.partial or \
                        validation[0] == ValidationResult.no_info) and self.settings.validation_range > 0:
            self.logger.info("Request block could not be validated sufficiently, crawling requester. %s",
                             validation)
            # Note that this code does not cover the scenario where we obtain this block indirectly.
            if not self.request_cache.has(u"crawl", blk.hash_number):
                self.send_crawl_request(peer,
                                        blk.public_key,
                                        max(GENESIS_SEQ, blk.sequence_number - self.settings.validation_range),
                                        max(GENESIS_SEQ, blk.sequence_number - 1),
                                        for_half_block=blk).addCallback(lambda _: self.process_half_block(blk, peer))
        else:
            self.sign_block(peer, linked=blk)

    def crawl_chain(self, peer, latest_block_num=None):
        """
        Crawl the whole chain of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available.
        """
        cache = ChainCrawlCache(self, peer, known_chain_length=latest_block_num)
        self.request_cache.add(cache)
        reactor.callFromThread(self.send_next_partial_chain_crawl_request, cache)

    def crawl_lowest_unknown(self, peer, latest_block_num=None):
        """
        Crawl the lowest unknown block of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available
        """
        sq = self.persistence.get_lowest_sequence_number_unknown(peer.public_key.key_to_bin())
        if latest_block_num and sq == latest_block_num + 1:
            return succeed([])  # We don't have to crawl this node since we have its whole chain
        return self.send_crawl_request(peer, peer.public_key.key_to_bin(), sq, sq)

    def send_crawl_request(self, peer, public_key, start_seq_num, end_seq_num, for_half_block=None):
        """
        Send a crawl request to a specific peer.
        """
        crawl_id = for_half_block.hash_number if for_half_block else \
            RandomNumberCache.find_unclaimed_identifier(self.request_cache, u"crawl")
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred))
        self.logger.info("Requesting crawl of node %s (blocks %d to %d) with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], start_seq_num, end_seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = CrawlRequestPayload(public_key, start_seq_num, end_seq_num, crawl_id).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

        return crawl_deferred

    def perform_partial_chain_crawl(self, cache, start, stop):
        """
        Perform a partial crawl request for a specific range, when crawling a chain.
        :param cache: The cache that stores progress regarding the chain crawl.
        :param start: The sequence number of the first block to be requested.
        :param stop: The sequence number of the last block to be requested.
        """
        if cache.current_request_range != (start, stop):
            # We are performing a new request
            cache.current_request_range = start, stop
            cache.current_request_attempts = 0
        elif cache.current_request_attempts == 3:
            # We already tried the same request three times, bail out
            self.request_cache.pop(u"chaincrawl", cache.number)
            return

        cache.current_request_attempts += 1
        cache.current_crawl_deferred = self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(),
                                                               start, stop)
        cache.current_crawl_deferred.addCallback(lambda _: self.send_next_partial_chain_crawl_request(cache))

    def send_next_partial_chain_crawl_request(self, cache):
        """
        Send the next partial crawl request, if we are not done yet.
        :param cache: The cache that stores progress regarding the chain crawl.
        """
        lowest_unknown = self.persistence.get_lowest_sequence_number_unknown(cache.peer.public_key.key_to_bin())
        if cache.known_chain_length >= 0 and cache.known_chain_length == lowest_unknown - 1:
            self.request_cache.pop(u"chaincrawl", cache.number)
            return

        latest_block = self.persistence.get_latest(cache.peer.public_key.key_to_bin())
        if not latest_block and cache.known_chain_length > 0:
            # We have no knowledge of this peer, simply send a request from the genesis block to known chain length
            self.perform_partial_chain_crawl(cache, 1, cache.known_chain_length)
            return
        elif latest_block and lowest_unknown == latest_block.sequence_number + 1:
            # It seems that we filled all gaps in the database; check whether we can do one final request
            if latest_block.sequence_number < cache.known_chain_length:
                self.perform_partial_chain_crawl(cache, latest_block.sequence_number + 1, cache.known_chain_length)
                return
            else:
                self.request_cache.pop(u"chaincrawl", cache.number)
                return

        start, stop = self.persistence.get_lowest_range_unknown(cache.peer.public_key.key_to_bin())
        self.perform_partial_chain_crawl(cache, start, stop)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, CrawlRequestPayload)
    def received_crawl_request(self, peer, dist, payload):
        self.logger.info("Received crawl request from node %s for range %d-%d",
                         hexlify(peer.public_key.key_to_bin())[-8:], payload.start_seq_num, payload.end_seq_num)
        start_seq_num = payload.start_seq_num
        end_seq_num = payload.end_seq_num

        # It could be that our start_seq_num and end_seq_num are negative. If so, convert them to positive numbers,
        # based on the last block of ones chain.
        if start_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            start_seq_num = max(GENESIS_SEQ, last_block.sequence_number + start_seq_num + 1) \
                if last_block else GENESIS_SEQ
        if end_seq_num < 0:
            last_block = self.persistence.get_latest(payload.public_key)
            end_seq_num = max(GENESIS_SEQ, last_block.sequence_number + end_seq_num + 1) \
                if last_block else GENESIS_SEQ

        blocks = self.persistence.crawl(payload.public_key, start_seq_num, end_seq_num, limit=10)
        total_count = len(blocks)

        if total_count == 0:
            global_time = self.claim_global_time()
            response_payload = EmptyCrawlResponsePayload(payload.crawl_id).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
            packet = self._ez_pack(self._prefix, 7, [dist, response_payload], False)
            self.endpoint.send(peer.address, packet)
        else:
            self.send_crawl_responses(blocks, peer, payload.crawl_id)

    def send_crawl_responses(self, blocks, peer, crawl_id):
        """
        Answer a peer with crawl responses.
        """
        for ind, block in enumerate(blocks):
            self.send_crawl_response(block, crawl_id, ind + 1, len(blocks), peer)
        self.logger.info("Sent %d blocks", len(blocks))

    @synchronized
    def sanitize_database(self):
        """
        DANGER! USING THIS MAY CAUSE DOUBLE SPENDING IN THE NETWORK.
                ONLY USE IF YOU KNOW WHAT YOU ARE DOING.

        This method removes all of the invalid blocks in our own chain.
        """
        self.logger.error("Attempting to recover %s", self.DB_CLASS.__name__)
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            # There is nothing to corrupt, we're at the genesis block.
            self.logger.debug("No latest block found when trying to recover database!")
            return
        validation = self.validate_persist_block(block)
        while validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
            # The latest block is invalid, remove it.
            self.persistence.remove_block(block)
            self.logger.error("Removed invalid block %d from our chain", block.sequence_number)
            block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            if not block:
                # Back to the genesis
                break
            validation = self.validate_persist_block(block)
        self.logger.error("Recovered database, our last block is now %d", block.sequence_number if block else 0)

    def persistence_integrity_check(self):
        """
        Perform an integrity check of our own chain. Recover it if needed.
        """
        block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        if not block:
            return
        validation = self.validate_persist_block(block)
        if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
            self.logger.error("Our chain did not validate. Result %s", repr(validation))
            self.sanitize_database()

    def send_crawl_response(self, block, crawl_id, index, total_count, peer):
        self.logger.debug("Sending block for crawl request to %s (%s)", peer, block)

        # Don't answer with any invalid blocks.
        validation = self.validate_persist_block(block)
        if validation[0] == ValidationResult.invalid and total_count > 0:
            # We send an empty block to the crawl requester if no blocks should be sent back
            self.logger.error("Not sending crawl response, the block is invalid. Result %s", repr(validation))
            self.persistence_integrity_check()
            return

        global_time = self.claim_global_time()
        payload = CrawlResponsePayload.from_crawl(block, crawl_id, index, total_count).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 3, [dist, payload], False)
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, CrawlResponsePayload)
    def received_crawl_response(self, source_address, dist, payload, data):
        self.received_half_block(source_address, data[:-12])  # We cut off a few bytes to make it a BlockPayload

        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            cache.received_block(block, payload.total_count)

    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, EmptyCrawlResponsePayload)
    def received_empty_crawl_response(self, source_address, dist, payload, data):
        cache = self.request_cache.get(u"crawl", payload.crawl_id)
        if cache:
            self.logger.info("Received empty crawl response for crawl with ID %d", payload.crawl_id)
            cache.received_empty_response()

    def get_trust(self, peer):
        """
        Return the trust score for a specific peer. For the basic Trustchain, this is the length of their chain.
        """
        block = self.persistence.get_latest(peer.public_key.key_to_bin())
        if block:
            return block.sequence_number
        else:
            # We need a minimum of 1 trust to have a chance to be selected in the categorical distribution.
            return 1

    def get_peer_for_introduction(self, exclude=None):
        """
        Choose a trusted peer to introduce you to someone else.
        The more trust you have for someone, the higher the chance is to forward them.
        """
        eligible = [p for p in self.get_peers() if p != exclude]
        if not eligible:
            return None

        total_trust = sum([self.get_trust(peer) for peer in eligible])
        random_trust_i = random.randint(0, total_trust - 1)
        current_trust_i = 0
        for i in grange(0, len(eligible)):
            next_trust_i = self.get_trust(eligible[i])
            if current_trust_i + next_trust_i > random_trust_i:
                return eligible[i]
            else:
                current_trust_i += next_trust_i

        return eligible[-1]

    def get_chain_length(self):
        """
        Return the length of your own chain.
        """
        latest_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        return 0 if not latest_block else latest_block.sequence_number

    @synchronized
    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_bytes = struct.pack('>H', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_request(socket_address, extra_bytes)

    @synchronized
    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_bytes = struct.pack('>H', self.get_chain_length())
        return super(TrustChainCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                             identifier, introduction, extra_bytes)

    @synchronized
    def introduction_response_callback(self, peer, dist, payload):
        chain_length = None
        if payload.extra_bytes:
            chain_length = struct.unpack('>H', payload.extra_bytes)[0]

        if peer.address in self.network.blacklist:  # Do not crawl addresses in our blacklist (trackers)
            return

        # Check if we have pending crawl requests for this peer
        has_intro_crawl = self.request_cache.has(u"introcrawltimeout", IntroCrawlTimeout.get_number_for(peer))
        has_chain_crawl = self.request_cache.has(u"chaincrawl", ChainCrawlCache.get_number_for(peer))
        if has_intro_crawl or has_chain_crawl:
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return

        if self.settings.crawler:
            self.crawl_chain(peer, latest_block_num=chain_length)
        else:
            known_blocks = self.persistence.get_number_of_known_blocks(public_key=peer.public_key.key_to_bin())
            if known_blocks < 1000 or random.random() > 0.5:
                self.request_cache.add(IntroCrawlTimeout(self, peer))
                self.crawl_lowest_unknown(peer, latest_block_num=chain_length)

    def unload(self):
        self.logger.debug("Unloading the TrustChain Community.")
        self.shutting_down = True

        self.request_cache.shutdown()

        super(TrustChainCommunity, self).unload()

        # Close the persistence layer
        self.persistence.close()


class TrustChainTestnetCommunity(TrustChainCommunity):
    """
    This community defines the testnet for TrustChain
    """
    DB_NAME = 'trustchain_testnet'

    master_peer = Peer(unhexlify("3081a7301006072a8648ce3d020106052b81040027038192000404494ce33365dbf1e9b93647b7ff8c"
                                 "979ba4d883421928ac7f7130900605e4fdece109d6ec3a1716537cb1ab284aa307f1dfc2aebe2e2d03"
                                 "7d27cd68ccc6b3dc560c20e4fc8a670500fb8e653bd286ce0be52b1d43d53041bb74204e5af9662eca"
                                 "b890ae518caeb11a7ef1510cf79c7b22e72529923b8f1cb08e518adb49a0da131a51c1254e49cd657b"
                                 "60fd7ddd8e19"))
