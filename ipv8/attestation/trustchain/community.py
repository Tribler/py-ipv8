"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
import logging
import random
from threading import RLock

from twisted.internet import reactor
from twisted.internet.defer import Deferred, succeed, fail

from .block import TrustChainBlock, ValidationResult, EMPTY_PK, GENESIS_SEQ, UNKNOWN_SEQ, ANY_COUNTERPARTY_PK
from .caches import CrawlRequestCache, HalfBlockSignCache, IntroCrawlTimeout
from .database import TrustChainDB
from ...deprecated.community import Community
from ...deprecated.payload import IntroductionResponsePayload
from ...deprecated.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .payload import *
from ...peer import Peer
from ...requestcache import RandomNumberCache, RequestCache

HALF_BLOCK = "half_block"
CRAWL = "crawl"
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
    master_peer = Peer(bytes.fromhex("3081a7301006072a8648ce3d020106052b810400270381920004057a1c4c4f8422b328209d99724bd30cf08d1f8"
                        "1a2961b003affd2964f92c457572f2f79de0968c42698e2d1cfb371dd71b275332a0a4c19f35f16166272baae8e"
                        "230bba377cc5c40643b83206088075559ec2f13a090e8786d04d84802268bef12e52983978da360589a2b7e293c"
                        "e4f16d02f37da2c3256f4703b9623d3750f7af437befebc8935c0f0726f58c1c1e9"))

    DB_CLASS = TrustChainDB
    DB_NAME = 'trustchain'
    BROADCAST_FANOUT = 10
    version = b'\x02'

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        db_name = kwargs.pop('db_name', self.DB_NAME)
        super(TrustChainCommunity, self).__init__(*args, **kwargs)
        self.request_cache = RequestCache()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.persistence = self.DB_CLASS(working_directory, db_name)
        self.relayed_broadcasts = []
        self.logger.debug("The trustchain community started with Public Key: %s",
                          self.my_peer.public_key.key_to_bin().hex())
        self.broadcast_block = True  # Whether we broadcast a full block after constructing it
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]

        self.decode_map.update({
            1: self.received_half_block,
            2: self.received_crawl_request,
            3: self.received_crawl_response,
            4: self.received_half_block_pair,
            5: self.received_half_block_broadcast,
            6: self.received_half_block_pair_broadcast
        })

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

    def send_block(self, block, address=None, ttl=2):
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
                                                                       self.BROADCAST_FANOUT)):
                self.endpoint.send(peer.address, packet)
            self.relayed_broadcasts.append(block.block_id)

    def send_block_pair(self, block1, block2, address=None, ttl=2):
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
                                                                       self.BROADCAST_FANOUT)):
                self.endpoint.send(peer.address, packet)
            self.relayed_broadcasts.append(block1.block_id)

    def self_sign_block(self, block_type='unknown', transaction=None):
        self.sign_block(self.my_peer, block_type=block_type, transaction=transaction)

    def create_source_block(self, block_type='unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: None
        """
        self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK, block_type=block_type, transaction=transaction)

    def create_link(self, source, block_type='unknown', additional_info=None, public_key=None):
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

    def sign_block(self, peer, public_key=EMPTY_PK, block_type='unknown', transaction=None, linked=None,
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
                         block.link_public_key.hex()[-8:], block, validation)
        if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
            self.logger.error("Signed block did not validate?! Result %s", repr(validation))
            return fail(RuntimeError("Signed block did not validate."))

        if not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        # This is a source block with no counterparty
        if not peer and public_key == ANY_COUNTERPARTY_PK:
            if self.broadcast_block:
                self.send_block(block)
            return

        # If there is a counterparty to sign
        self.send_block(block, address=peer.address)

        if peer == self.my_peer:
            # We created a half-signed block
            if self.broadcast_block:
                self.send_block(block)

            return succeed((block, None)) if public_key == ANY_COUNTERPARTY_PK else succeed((block, linked))
        elif not linked:
            # We keep track of this outstanding sign request.
            sign_deferred = Deferred()
            self.request_cache.add(HalfBlockSignCache(self, block, sign_deferred))
            return sign_deferred
        else:
            # We return a deferred that fires immediately with both half blocks.
            if self.broadcast_block:
                self.send_block_pair(linked, block)

            # See https://github.com/Tribler/py-ipv8/issues/160
            # If we receive responses from received_crawl_request out of order we can desync:
            #  1. We need to sign block 2, but can't as we are still missing block 1.
            #  2. We receive block 1 and sign it.
            #  3.a. Nothing will happen until the next time we randomly encounter block 2.
            #  3.b. The counterparty is still waiting for block 2 to be signed.
            self.send_crawl_request(peer,
                                    linked.public_key,
                                    linked.sequence_number + 1)

            return succeed((linked, block))

    @synchronized
    def received_half_block(self, source_address, data):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        """
        dist, payload = self._ez_unpack_noauth(HalfBlockPayload, data)
        peer = Peer(payload.public_key, source_address)
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.process_half_block(block, peer)

    @synchronized
    def received_half_block_broadcast(self, source, data):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        dist, payload = self._ez_unpack_noauth(HalfBlockBroadcastPayload, data)
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.validate_persist_block(block)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 0:
            self.send_block(block, ttl=payload.ttl - 1)

    @synchronized
    def received_half_block_pair(self, source_address, data):
        """
        We received a block pair message.
        """
        dist, payload = self._ez_unpack_noauth(HalfBlockPairPayload, data)
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

    @synchronized
    def received_half_block_pair_broadcast(self, source, data):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        dist, payload = self._ez_unpack_noauth(HalfBlockPairBroadcastPayload, data)
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
        link_block_id_int = int(blk.linked_block_id.encode().hex(), 16) % 100000000
        if self.request_cache.has('sign', link_block_id_int):
            cache = self.request_cache.pop('sign', link_block_id_int)

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
            return

        # It is important that the request matches up with its previous block, gaps cannot be tolerated at
        # this point. We already dropped invalids, so here we delay this message if the result is partial,
        # partial_previous or no-info. We send a crawl request to the requester to (hopefully) close the gap
        if validation[0] == ValidationResult.partial_previous or validation[0] == ValidationResult.partial or \
                        validation[0] == ValidationResult.no_info:
            self.logger.info("Request block could not be validated sufficiently, crawling requester. %s",
                             validation)
            # Note that this code does not cover the scenario where we obtain this block indirectly.
            if not self.request_cache.has("crawl", blk.hash_number):
                self.send_crawl_request(peer,
                                        blk.public_key,
                                        max(GENESIS_SEQ, blk.sequence_number - 5),
                                        for_half_block=blk)
        else:
            self.sign_block(peer, linked=blk)

    def crawl_lowest_unknown(self, peer):
        """
        Crawl the lowest unknown block of a specific peer.
        """
        sq = self.persistence.get_lowest_sequence_number_unknown(peer.public_key.key_to_bin())
        return self.send_crawl_request(peer, peer.public_key.key_to_bin(), sequence_number=sq)

    def send_crawl_request(self, peer, public_key, sequence_number=None, for_half_block=None):
        """
        Send a crawl request to a specific peer.
        """
        sq = sequence_number
        if sequence_number is None:
            blk = self.persistence.get_latest(public_key)
            sq = blk.sequence_number if blk else GENESIS_SEQ
        sq = max(GENESIS_SEQ, sq) if sq >= 0 else sq

        crawl_id = for_half_block.hash_number if for_half_block else \
            RandomNumberCache.find_unclaimed_identifier(self.request_cache, "crawl")
        crawl_deferred = Deferred()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_deferred))
        self.logger.info("Requesting crawl of node %s:%d with id %d", public_key.hex()[-8:], sq, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = CrawlRequestPayload(sq, crawl_id).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

        return crawl_deferred

    @synchronized
    def received_crawl_request(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(CrawlRequestPayload, data)
        peer = Peer(auth.public_key_bin, source_address)

        self.logger.info("Received crawl request from node %s for sequence number %d",
                         peer.public_key.key_to_bin().hex()[-8:],
                         payload.requested_sequence_number)
        sq = payload.requested_sequence_number
        if sq < 0:
            last_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
            # The -1 element is the last_block.seq_nr
            # The -2 element is the last_block.seq_nr - 1
            # Etc. until the genesis seq_nr
            sq = max(GENESIS_SEQ, last_block.sequence_number + (sq + 1)) if last_block else GENESIS_SEQ
        blocks = self.persistence.crawl(self.my_peer.public_key.key_to_bin(), sq, limit=10)
        total_count = len(blocks)

        if total_count == 0:
            # If there are no blocks to send, send a dummy block back with an empty transaction.
            # This is to inform the requester that he can't expect any blocks.
            block = self.get_block_class("unknown").create('noblocks', {}, self.persistence,
                                                           self.my_peer.public_key.key_to_bin(), link_pk=EMPTY_PK)
            self.send_crawl_response(block, payload.crawl_id, 0, 0, peer)

        for ind in range(len(blocks)):
            self.send_crawl_response(blocks[ind], payload.crawl_id, ind + 1, total_count, peer)
        self.logger.info("Sent %d blocks", total_count)

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
        if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid \
                and total_count > 0:  # We send an empty block to the crawl requester if no blocks should be sent back
            self.logger.error("Not sending crawl response, the block is invalid. Result %s", repr(validation))
            self.persistence_integrity_check()
            return

        global_time = self.claim_global_time()
        payload = CrawlResponsePayload.from_crawl(block, crawl_id, index, total_count).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 3, [dist, payload], False)
        self.endpoint.send(peer.address, packet)

    @synchronized
    def received_crawl_response(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(CrawlResponsePayload, data)
        self.received_half_block(source_address, data[:-12])  # We cut off a few bytes to make it a BlockPayload

        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        cache = self.request_cache.get("crawl", payload.crawl_id)
        if cache:
            cache.received_block(block, payload.total_count)

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
        for i in range(0, len(eligible)):
            next_trust_i = self.get_trust(eligible[i])
            if current_trust_i + next_trust_i > random_trust_i:
                return eligible[i]
            else:
                current_trust_i += next_trust_i

        return eligible[-1]

    @synchronized
    def on_introduction_response(self, source_address, data):
        super(TrustChainCommunity, self).on_introduction_response(source_address, data)

        auth, _, _ = self._ez_unpack_auth(IntroductionResponsePayload, data)
        peer = Peer(auth.public_key_bin, source_address)
        if self.request_cache.has("introcrawltimeout", IntroCrawlTimeout.get_number_for(peer)):
            self.logger.debug("Not crawling %s, as we have already crawled it in the last %d seconds!",
                              peer.mid.encode('hex'), IntroCrawlTimeout.__new__(IntroCrawlTimeout).timeout_delay)
        elif source_address not in self.network.blacklist:
            # Do not crawl addresses in our blacklist (trackers)
            self.request_cache.add(IntroCrawlTimeout(self, peer))
            self.crawl_lowest_unknown(peer)

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

    master_peer = Peer(bytes.fromhex("3081a7301006072a8648ce3d020106052b810400270381920004017aa18185c6c8a3741aed970f5476d50932980"
                        "66670c6557f9d2519a77c2abe293f9438444fdb73d9e36d0b43a4a254f96c563c0da7915def980270d88da4079e"
                        "83a6039ce97f2205528c69087f88a6d6f35d83b93b3fb8a360260114729d4cfb5acc4b190e067695b4ae5e240a3"
                        "939a1f45520e87a459ed0f358bf5e66371a748daa041997da69cab227596948bffd"))
