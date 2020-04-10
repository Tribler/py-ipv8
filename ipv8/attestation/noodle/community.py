"""
The Noodle community.
"""
import logging
import random
import struct
from asyncio import Future, Queue, ensure_future, get_event_loop, sleep
from binascii import hexlify, unhexlify
from collections import deque
from functools import wraps
from threading import RLock

import networkx as nx

import orjson as json

from .block import ANY_COUNTERPARTY_PK, EMPTY_PK, GENESIS_SEQ, NoodleBlock, UNKNOWN_SEQ, ValidationResult
from .caches import AuditProofRequestCache, ChainCrawlCache, CrawlRequestCache, HalfBlockSignCache, IntroCrawlTimeout, \
    NoodleCrawlRequestCache, PingRequestCache, AuditRequestCache
from .database import NoodleDB
from .exceptions import InsufficientBalanceException, NoPathFoundException
from .listener import BlockListener
from .memory_database import NoodleMemoryDatabase
from .payload import *
from .settings import SecurityMode, NoodleSettings
from ...community import Community
from ...keyvault.crypto import default_eccrypto
from ...lazy_community import lazy_wrapper, lazy_wrapper_unsigned, lazy_wrapper_unsigned_wd
from ...messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ...peer import Peer
from ...peerdiscovery.discovery import RandomWalk
from ...peerdiscovery.network import Network
from ...requestcache import RandomNumberCache, RequestCache
from ...taskmanager import task
from ...util import fail, maybe_coroutine, succeed


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with self.receive_block_lock:
            return f(self, *args, **kwargs)
    return wrapper


class SubTrustCommunity(Community):

    def __init__(self, *args, **kwargs):
        self.master_peer = kwargs.pop('master_peer')
        self._prefix = b'\x00' + self.version + self.master_peer.mid
        super(SubTrustCommunity, self).__init__(*args, **kwargs)


class NoodleBlockListener(BlockListener):
    """
    This block listener simply signs all blocks it receives.
    """
    BLOCK_CLASS = NoodleBlock

    def should_sign(self, block):
        return True

    def received_block(self, block):
        pass


class NoodleCommunity(Community):
    """
    Community for secure payments.
    """
    master_peer = Peer(unhexlify("4c69624e61434c504b3a062780beaeb40e70fca4cfc1b7751d734f361cf8d815db24dbb8a99fc98af4"
                                 "39fc977d84f71a431f8825ba885a5cf86b2498c6b473f33dd20dbdcffd199048fc"))

    UNIVERSAL_BLOCK_LISTENER = b'UNIVERSAL_BLOCK_LISTENER'
    DB_CLASS = NoodleDB
    DB_NAME = 'noodle'
    version = b'\x02'

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        self.persistence = kwargs.pop('persistence', None)
        db_name = kwargs.pop('db_name', self.DB_NAME)
        self.settings = kwargs.pop('settings', NoodleSettings())
        self.receive_block_lock = RLock()
        self.ipv8 = kwargs.pop('ipv8', None)
        super(NoodleCommunity, self).__init__(*args, **kwargs)
        self.request_cache = RequestCache()
        self.logger = logging.getLogger(self.__class__.__name__)

        if not self.persistence:
            self.persistence = self.DB_CLASS(working_directory, db_name, self.my_peer.public_key.key_to_bin())
        self.relayed_broadcasts = set()
        self.relayed_broadcasts_order = deque()
        self.logger.debug("The Noodle community started with Public Key: %s",
                          hexlify(self.my_peer.public_key.key_to_bin()))
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]

        self.known_graph = nx.Graph()
        self.periodic_sync_lc = {}
        self.transfer_queue = Queue()
        self.transfer_queue_task = ensure_future(self.evaluate_transfer_queue())
        self.incoming_block_queue = Queue()
        self.incoming_block_queue_task = ensure_future(self.evaluate_incoming_block_queue())
        self.audit_response_queue = Queue()
        self.audit_response_queue_task = ensure_future(self.evaluate_audit_response_queue())

        self.mem_db_flush_lc = None
        self.transfer_lc = None

        self.pex = {}
        self.bootstrap_master = None
        self.proof_requests = {}

        self.decode_map.update({
            chr(1): self.received_half_block,
            chr(2): self.received_crawl_request,
            chr(3): self.received_crawl_response,
            chr(4): self.received_half_block_pair,
            chr(5): self.received_half_block_broadcast,
            chr(6): self.received_half_block_pair_broadcast,
            chr(7): self.received_empty_crawl_response,
            chr(8): self.received_peer_crawl_request,
            chr(9): self.received_peer_crawl_response,
            chr(10): self.received_audit_proofs,
            chr(11): self.received_audit_proofs_request,
            chr(12): self.received_audit_request,
            chr(13): self.received_mint_request,
            chr(14): self.received_audit_proofs_response,
            chr(15): self.on_ping_request,
            chr(16): self.on_ping_response
        })

        # Add the listener
        self.add_listener(NoodleBlockListener(), [b'spend', b'claim'])

        # Enable the memory database
        orig_db = self.persistence
        self.persistence = NoodleMemoryDatabase(working_directory, db_name, orig_db)

        # Add the system minter(s)
        for minter_pk in self.settings.minters:
            self.known_graph.add_node(unhexlify(minter_pk), minter=True)

        # If we are the system minter, init the community
        if hexlify(self.my_peer.public_key.key_to_bin()) in self.settings.minters or not self.settings.minters:
            self._logger.info("I am the system minter - init our own community")
            self.init_minter_community()

            # Mint if needed
            my_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
            if self.persistence.get_balance(my_id) <= 0:
                self.mint(self.settings.initial_mint_value)

    def transfer(self, dest_peer, spend_value):
        if self.get_my_balance() < spend_value and not self.settings.is_hiding:
            return fail(InsufficientBalanceException("Insufficient balance."))

        future = Future()
        self.transfer_queue.put_nowait((future, dest_peer, spend_value))
        return future

    async def process_transfer_queue_item(self, future, dest_peer, spend_value):
        self._logger.debug("Making spend to peer %s (value: %f)", dest_peer, spend_value)
        if dest_peer == self.my_peer:
            # We are transferring something to ourselves
            my_pk = self.my_peer.public_key.key_to_bin()
            my_id = self.persistence.key_to_id(my_pk)
            peer_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
            pw_total = self.persistence.get_total_pairwise_spends(my_id, peer_id)
            tx = {"value": spend_value, "total_spend": pw_total + spend_value}

            block_tup = await self.sign_block(self.my_peer, self.my_peer.public_key.key_to_bin(),
                                              block_type=b'spend', transaction=tx)
            block_tup = await self.sign_block(self.my_peer, self.my_peer.public_key.key_to_bin(), block_type=b'claim',
                                              linked=block_tup[0])
            future.set_result(block_tup)
        else:
            try:
                next_hop_peer, tx = self.prepare_spend_transaction(dest_peer.public_key.key_to_bin(), spend_value)
                if next_hop_peer != dest_peer:
                    # Multi-hop payment, add condition + nonce
                    nonce = self.persistence.get_new_peer_nonce(dest_peer.public_key.key_to_bin())
                    condition = hexlify(dest_peer.public_key.key_to_bin()).decode()
                    tx.update({'nonce': nonce, 'condition': condition})

                result = await self.sign_block(next_hop_peer, next_hop_peer.public_key.key_to_bin(),
                                               block_type=b'spend', transaction=tx)
                future.set_result(result)
            except Exception as exc:
                future.set_exception(exc)

    async def evaluate_transfer_queue(self):
        while True:
            block_info = await self.transfer_queue.get()
            future, dest_peer, spend_value = block_info
            _ = ensure_future(self.process_transfer_queue_item(future, dest_peer, spend_value))
            await sleep(self.settings.transfer_queue_interval / 1000)

    def start_making_random_transfers(self):
        """
        Start to make random transfers to other peers.
        """
        self.transfer_lc = self.register_task("transfer_lc", self.make_random_transfer,
                                              interval=self.settings.transfer_interval)

    def get_peer(self, pub_key):
        for peer in self.get_peers():
            if peer.public_key.key_to_bin() == pub_key:
                return peer
        return None

    def ask_minters_for_funds(self, value=10000):
        """
        Ask the minters for funds.
        """
        self._logger.info("Asking minters for funds (%d)", value)
        known_minters = set(nx.get_node_attributes(self.known_graph, 'minter').keys())
        requests_sent = 0
        for minter in known_minters:
            minter_peer = self.get_peer(minter)
            if not minter_peer:
                continue

            global_time = self.claim_global_time()
            auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
            payload = MintRequestPayload(value).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

            packet = self._ez_pack(self._prefix, 13, [auth, dist, payload])
            self._logger.info("Sending mint request to peer %s:%d", *minter_peer.address)
            self.endpoint.send(minter_peer.address, packet)
            requests_sent += 1

        if requests_sent == 0:
            self._logger.info("No minters available!")

    def get_my_balance(self):
        my_pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_pk)
        return self.persistence.get_balance(my_id)

    def get_eligible_payment_peers(self):
        peers = self.get_peers()
        return [peer for peer in peers if hexlify(peer.public_key.key_to_bin()) not in self.settings.crawlers]

    async def ping(self, peer):
        self.logger.debug('Pinging peer %s', peer)

        cache = self.request_cache.add(PingRequestCache(self, u'ping', peer))

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PingPayload(cache.number).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 15, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

        await cache.future

    @lazy_wrapper(GlobalTimeDistributionPayload, PingPayload)
    def on_ping_request(self, peer, dist, payload):
        self.logger.debug('Got ping-request from %s', peer.address)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PingPayload(payload.identifier).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 16, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(GlobalTimeDistributionPayload, PingPayload)
    def on_ping_response(self, peer, dist, payload):
        if not self.request_cache.has(u'ping', payload.identifier):
            self.logger.error('Got ping-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got ping-response from %s', peer.address)
        cache = self.request_cache.pop(u'ping', payload.identifier)
        cache.future.set_result(None)

    async def make_random_transfer(self):
        """
        Transfer funds to a random peer.
        """
        if self.get_my_balance() <= 0:
            self.mint()
            return

        if not self.get_eligible_payment_peers():
            self._logger.info("No peers to make a payment to.")
            return

        rand_peer = random.choice(self.get_peers())

        try:
            await self.ping(rand_peer)
            await self.transfer(rand_peer, 1)
        except RuntimeError as exc:
            self._logger.info("Failed to make payment to peer: %s", str(exc))

    def init_mem_db_flush(self, flush_time):
        if not self.mem_db_flush_lc:
            self.mem_db_flush_lc = self.register_task("mem_db_flush", self.mem_db_flush, flush_time)

    def mem_db_flush(self):
        self.persistence.commit_block_times()

    def trustchain_sync(self, community_id):
        self.logger.info("Sync for the info peer with mid %s", hexlify(community_id))
        blk = self.persistence.get_latest_peer_block_by_mid(community_id)
        val = self.pex[community_id].get_peers()
        if blk:
            self.send_block(blk, address_set=val)
        # Send also the last claim done with this peer
        if community_id in self.persistence.peer_map:
            blk = self.persistence.get_last_pairwise_block(self.persistence.peer_map[community_id],
                                                           self.my_peer.public_key.key_to_bin())
            if blk:
                self.send_block_pair(blk[0], blk[1], address_set=val)

    def get_hop_to_peer(self, peer_pub_key):
        """
        Get next hop to peer
        :param peer_pub_key: public key of the destination
        :return: the next hop for the peer
        """
        p = self.get_peer_by_pub_key(peer_pub_key)
        if p:
            # Directly connected
            return p
        # Check if peer is part of any known community
        for p in self.get_all_communities_peers():
            if peer_pub_key == p.public_key.key_to_bin():
                self.logger.info("Choosing peer from community")
                return p
        # Look in the known_graph the path to the peer
        if peer_pub_key not in self.known_graph:
            self.logger.error("Target peer is not in known graph")
            return None
        else:
            source = self.my_peer.public_key.key_to_bin()
            target = peer_pub_key
            p = None
            while not p and len(self.known_graph[source]) > 0:
                paths = list(nx.all_shortest_paths(self.known_graph, source=source, target=target))
                random_path = random.choice(paths)
                if len(random_path) < 2:
                    self.logger.error("Path to key %s is less than 2 %s", peer_pub_key, str(random_path))
                else:
                    # Choose random path
                    p = self.get_peer_by_pub_key(random_path[1])
                    if not p:
                        # p is not connected !
                        self.logger.error("Got a path, but not connected! %s. Removing the edge ", random_path[1])
                        self.known_graph.remove_edge(source, random_path[1])
            return p

    def mint(self, value=None):
        self._logger.info("Minting initial value...")
        if not value:
            value = self.settings.initial_mint_value
        mint = self.prepare_mint_transaction(value)
        return self.self_sign_block(block_type=b'claim', transaction=mint)

    def prepare_spend_transaction(self, pub_key, spend_value, **kwargs):
        """
        Prepare a spend transaction.
        First check your own balance. Next, find a path to the target peer.
        """
        my_pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_pk)

        peer = self.get_hop_to_peer(pub_key)
        if not peer:
            raise NoPathFoundException("No path to target peer found.")
        peer_id = self.persistence.key_to_id(peer.public_key.key_to_bin())
        pw_total = self.persistence.get_total_pairwise_spends(my_id, peer_id)
        added = {"value": spend_value, "total_spend": pw_total + spend_value}
        added.update(**kwargs)
        return peer, added

    def prepare_mint_transaction(self, value):
        minter = self.persistence.key_to_id(EMPTY_PK)
        pk = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(pk)
        total = self.persistence.get_total_pairwise_spends(minter, my_id)
        transaction = {"value": value, "mint_proof": True, "total_spend": total + value}
        return transaction

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
            return NoodleBlock

        return self.listeners_map[block_type][0].BLOCK_CLASS

    async def should_sign(self, block):
        """
        Return whether we should sign the block in the passed message.
        @param block: the block we want to sign or not.
        """
        if block.type not in self.listeners_map:
            return False  # There are no listeners for this block

        for listener in self.listeners_map[block.type]:
            should_sign = await maybe_coroutine(listener.should_sign, block)
            if should_sign:
                return True

        return False

    def _add_broadcasted_blockid(self, block_id):
        self.relayed_broadcasts.add(block_id)
        self.relayed_broadcasts_order.append(block_id)
        if len(self.relayed_broadcasts) > self.settings.broadcast_history_size:
            to_remove = self.relayed_broadcasts_order.popleft()
            self.relayed_broadcasts.remove(to_remove)

    async def informed_send_block(self, block1, block2=None, ttl=None, fanout=None):
        """
        Spread block among your verified peers.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        if block2:
            if block1.link_sequence_number == UNKNOWN_SEQ:
                block = block1
            else:
                block = block2
        else:
            block = block1
        # Get information about the block counterparties
        if not ttl:
            ttl = self.settings.ttl
        know_neigh = self.network.known_network.get_neighbours(block.public_key)
        if not know_neigh:
            # No neighbours known, spread randomly
            if block2:
                self.send_block_pair(block1, block2, ttl=ttl)
            else:
                self.send_block(block1, ttl=ttl)
        else:
            next_peers = set()
            for neigh in know_neigh:
                paths = self.network.known_network.get_path_to_peer(self.my_peer.public_key.key_to_bin(), neigh,
                                                                    cutoff=ttl + 1)
                for p in paths:
                    next_peers.add(p[1])
            res_fanout = fanout if fanout else self.settings.broadcast_fanout
            if len(next_peers) < res_fanout:
                # There is not enough information to build paths - choose at random
                for peer in random.sample(self.get_peers(), min(len(self.get_peers()),
                                                                res_fanout)):
                    next_peers.add(peer.public_key.key_to_bin())
            if len(next_peers) > res_fanout:
                next_peers = random.sample(list(next_peers), res_fanout)

            if block2:
                payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            else:
                payload = HalfBlockBroadcastPayload.from_half_block(block, ttl).to_pack_list()
                packet = self._ez_pack(self._prefix, 5, [dist, payload], False)

            for peer_key in next_peers:
                peer = self.network.get_verified_by_public_key_bin(peer_key)
                self.logger.debug("Sending block to %s", peer)
                p = peer.address
                await sleep(random.random() * 0.1)
                self.endpoint.send(p, packet)

            self._add_broadcasted_blockid(block.block_id)

    def send_block(self, block, address=None, address_set=None, ttl=1):
        """
        Send a block to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        if ttl < 1:
            return
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

            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))
            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))

            self._add_broadcasted_blockid(block.block_id)

    def send_block_pair(self, block1, block2, address=None, address_set=None, ttl=1):
        """
        Send a half block pair to a specific address, or do a broadcast to known peers if no peer is specified.
        """
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if address:
            self.logger.info("Sending block pair to (%s:%d) (%s and %s)", address[0], address[1], block1, block2)
            payload = HalfBlockPairPayload.from_half_blocks(block1, block2).to_pack_list()
            packet = self._ez_pack(self._prefix, 4, [dist, payload], False)
            self.endpoint.send(address, packet)
        else:
            payload = HalfBlockPairBroadcastPayload.from_half_blocks(block1, block2, ttl).to_pack_list()
            packet = self._ez_pack(self._prefix, 6, [dist, payload], False)
            if address_set:
                f = min(len(address_set), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a back-channel  to %s peers", f)
                peers = (p.address for p in random.sample(address_set, f))
            else:
                f = min(len(self.get_peers()), self.settings.broadcast_fanout)
                self.logger.debug("Broadcasting block pair in a main-channel  to %s peers", f)
                peers = (p.address for p in random.sample(self.get_peers(), f))

            for p in peers:
                self.endpoint.send(p, packet)
                # self.register_anonymous_task("send_block_pair",
                #                             reactor.callLater(random.random() * 0.2, self.endpoint.send, p, packet))

            self._add_broadcasted_blockid(block1.block_id)

    def self_sign_block(self, block_type=b'unknown', transaction=None):
        return self.sign_block(self.my_peer, block_type=block_type, transaction=transaction)

    def create_source_block(self, block_type=b'unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: A future that fires with a (block, None) tuple
        """
        return self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK,
                               block_type=block_type, transaction=transaction)

    def create_link(self, source, block_type, additional_info=None, public_key=None):
        """
        Create a Link Block to a source block

        :param source: The source block which had no initial counterpary to sign
        :param block_type: The type of the block to be constructed, as a string
        :param additional_info: a dictionary with supplementary information concerning the transaction
        :param public_key: The public key of the counterparty (usually of the source's owner)
        :return: None
        """
        public_key = source.public_key if public_key is None else public_key

        return self.sign_block(self.my_peer, linked=source, public_key=public_key, block_type=block_type,
                               additional_info=additional_info)

    @synchronized
    def sign_block(self, peer, public_key=EMPTY_PK, block_type=b'unknown', transaction=None, linked=None,
                   additional_info=None, double_spend_block=None, from_peer=None, from_peer_seq_num=None):
        """
        Create, sign, persist and send a block signed message
        :param peer: The peer with whom you have interacted, as a IPv8 peer
        :param public_key: The public key of the other party you transact with
        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :param linked: The block that the requester is asking us to sign
        :param additional_info: Stores additional information, on the transaction
        :param double_spend_block: Number of block if you want to double sign
        :param from_peer:  Optional parameter for conditional chain payments
        :param from_peer_seq_num: Optional parameter for conditional chain payments
        """
        # NOTE to the future: This method reads from the database, increments and then writes back. If in some future
        # this method is allowed to execute in parallel, be sure to lock from before .create up to after .add_block

        # In this particular case there must be an implicit transaction due to the following assert
        assert peer is not None or peer is None and linked is None and public_key == ANY_COUNTERPARTY_PK, \
            "Peer, linked block should not be provided when creating a no counterparty source block. Public key " \
            "should be that reserved for any counterpary."
        assert transaction is None and linked is not None or transaction is not None and linked is None, \
            "Either provide a linked block or a transaction, not both %s, %s" % (peer, self.my_peer)
        assert (additional_info is None or linked is not None
                and transaction is None), \
            "Either no additional info is provided or one provides it for a linked block"
        assert (linked is None or linked.link_public_key == self.my_peer.public_key.key_to_bin()
                or linked.link_public_key == ANY_COUNTERPARTY_PK), "Cannot counter sign block not addressed to self"
        assert linked is None or linked.link_sequence_number == UNKNOWN_SEQ, \
            "Cannot counter sign block that is not a request"
        assert transaction is None or isinstance(transaction, dict), "Transaction should be a dictionary"
        assert additional_info is None or isinstance(additional_info, dict), "Additional info should be a dictionary"

        # self.persistence_integrity_check()

        # if linked and linked.link_public_key != ANY_COUNTERPARTY_PK:
        #     block_type = linked.type

        block = self.get_block_class(block_type).create(block_type, transaction, self.persistence,
                                                        self.my_peer.public_key.key_to_bin(),
                                                        link=linked, additional_info=additional_info,
                                                        link_pk=public_key,
                                                        double_spend_seq=double_spend_block)
        block.sign(self.my_peer.key)

        # validation = block.validate(self.persistence)
        # self.logger.info("Signed block to %s (%s) validation result %s",
        #                  hexlify(block.link_public_key)[-8:], block, validation)
        # if validation[0] != ValidationResult.partial_next and validation[0] != ValidationResult.valid:
        #     self.logger.error("Signed block did not validate?! Result %s", repr(validation))
        #     return fail(RuntimeError("Signed block did not validate."))

        if not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        if peer == self.my_peer:
            # We created a self-signed block / initial claim, send to the neighbours
            if block.type not in self.settings.block_types_bc_disabled and not self.settings.is_hiding:
                self.send_block(block)
            return succeed((block, None)) if public_key == ANY_COUNTERPARTY_PK else succeed((block, linked))

        # This is a source block with no counterparty
        if not peer and public_key == ANY_COUNTERPARTY_PK:
            if block.type not in self.settings.block_types_bc_disabled:
                self.send_block(block)
            return succeed((block, None))

        # If there is a counterparty to sign, we send it
        self.send_block(block, address=peer.address)

        # We broadcast the block in the network if we initiated a transaction
        if not linked:
            # We keep track of this outstanding sign request.
            sign_future = Future()
            # Check if we are waiting for this signature response
            block_id_int = int(hexlify(block.block_id), 16) % 100000000
            if not self.request_cache.has(u'sign', block_id_int):
                self.request_cache.add(HalfBlockSignCache(self, block, sign_future, peer.address,
                                                          from_peer=from_peer, seq_num=from_peer_seq_num))
                return sign_future
            return succeed((block, None))
        else:
            # This is a claim block, send block to the neighbours
            # self.send_block_pair(linked, block)
            return succeed((linked, block))

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPayload)
    async def received_half_block(self, source_address, dist, payload):
        """
        We've received a half block, either because we sent a SIGNED message to some one or we are crawling
        """
        peer = Peer(payload.public_key, source_address)
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        self.incoming_block_queue.put_nowait((peer, block))

    async def evaluate_incoming_block_queue(self):
        while True:
            block_info = await self.incoming_block_queue.get()
            peer, block = block_info

            await self.process_half_block(block, peer)
            await sleep(self.settings.block_queue_interval / 1000)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockBroadcastPayload)
    def received_half_block_broadcast(self, source_address, dist, payload):
        """
        We received a half block, part of a broadcast. Disseminate it further.
        """
        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        peer = Peer(payload.public_key, source_address)
        self.validate_persist_block(block, peer)

        if block.block_id not in self.relayed_broadcasts and payload.ttl > 1:
            if self.settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block, ttl=payload.ttl, fanout=fanout)
            else:
                self.send_block(block, ttl=payload.ttl)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairPayload)
    def received_half_block_pair(self, source_address, dist, payload):
        """
        We received a block pair message.
        """
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.logger.info("Received block pair %s, %s", block1, block2)
        peer = Peer(payload.public_key, source_address)
        self.validate_persist_block(block1, peer)
        self.validate_persist_block(block2, peer)

    @synchronized
    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, HalfBlockPairBroadcastPayload)
    async def received_half_block_pair_broadcast(self, source_address, dist, payload):
        """
        We received a half block pair, part of a broadcast. Disseminate it further.
        """
        block1, block2 = self.get_block_class(payload.type1).from_pair_payload(payload, self.serializer)
        self.validate_persist_block(block1)
        self.validate_persist_block(block2)

        if block1.block_id not in self.relayed_broadcasts and payload.ttl > 1:
            if self.settings.use_informed_broadcast:
                fanout = self.settings.broadcast_fanout - 1
                self.informed_send_block(block1, block2, ttl=payload.ttl, fanout=fanout)
            else:
                await sleep(0.5 * random.random())
                self.send_block_pair(block1, block2, ttl=payload.ttl)

    def check_local_state_wrt_block(self, block):
        if block.type == b'spend':
            # Verify the block
            peer_id = self.persistence.key_to_id(block.public_key)
            p = self.persistence.key_to_id(block.link_public_key)
            seq_num = block.sequence_number
            total_value = float(block.transaction["total_spend"])
        elif block.type == b'claim':
            peer_id = self.persistence.key_to_id(block.link_public_key)
            p = self.persistence.key_to_id(block.public_key)
            seq_num = block.link_sequence_number
            total_value = float(block.transaction["total_spend"])
        else:
            # Ignore for now
            return
        # There is status from the peer that is higher than this block, and the relationship is not known
        balance = self.persistence.get_total_pairwise_spends(peer_id, p)
        known_seq_num = self.persistence.get_last_pairwise_spend_num(peer_id, p)
        if self.persistence.get_peer_proofs(peer_id, seq_num) \
                and (balance < total_value or known_seq_num < seq_num):
            self.trigger_security_alert(peer_id, ["Hiding peer " + str(p)])

    def validate_persist_block(self, block, peer=None):
        """
        Validate a block and if it's valid, persist it. Return the validation result.
        :param block: The block to validate and persist.
        :return: [ValidationResult]
        """
        validation = block.validate(self.persistence)
        self.network.known_network.add_edge(block.public_key, block.link_public_key)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid:
            pass
        else:
            self.notify_listeners(block)
            if not self.persistence.contains(block):
                # verify the block according to the previously received status
                self.check_local_state_wrt_block(block)
                self.persistence.add_block(block)
                if peer:
                    self.persistence.add_peer(peer)
        return validation

    def notify_listeners(self, block):
        """
        Notify listeners of a specific new block.
        """
        # Call the listeners associated to the universal block, if there are any
        for listener in self.listeners_map.get(self.UNIVERSAL_BLOCK_LISTENER, []):
            listener.received_block(block)

        # Avoid proceeding any further if the type of the block coincides with the UNIVERSAL_BLOCK_LISTENER
        if block.type not in self.listeners_map or self.shutting_down or block.type == self.UNIVERSAL_BLOCK_LISTENER:
            return

        for listener in self.listeners_map[block.type]:
            listener.received_block(block)

    @synchronized
    async def process_half_block(self, blk, peer, status=None, audit_proofs=None):
        """
        Process a received half block.
        """
        validation = self.validate_persist_block(blk, peer)
        self.logger.info("Block validation result %s, %s, (%s)", validation[0], validation[1], blk)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid:
            raise RuntimeError(f"Block could not be validated: {validation[0]}, {validation[1]}")
        if status and audit_proofs:
            # validate status and audit proofs for the block
            if not self.validate_audit_proofs(status, audit_proofs, blk):
                raise RuntimeError("Block proofs are not valid, refusing to sign: %s", blk)

        # Check if we are waiting for this signature response
        link_block_id_int = int(hexlify(blk.linked_block_id), 16) % 100000000
        if self.request_cache.has('sign', link_block_id_int):
            cache = self.request_cache.pop('sign', link_block_id_int)

            # We cannot guarantee that we're on the event loop thread.
            get_event_loop().call_soon_threadsafe(cache.sign_future.set_result,
                                                  (blk, self.persistence.get_linked(blk)))

            # We are waiting for a conditional transaction
            if 'condition' in blk.transaction and cache.from_peer:
                # We need to answer to prev peer in the chain
                if 'proof' in blk.transaction:
                    orig_blk = self.persistence.get(cache.from_peer.public_key.key_to_bin(), cache.seq_num)
                    new_tx = orig_blk.transaction
                    new_tx['proof'] = blk.transaction['proof']
                    return self.sign_block(cache.from_peer, linked=orig_blk, block_type=b'claim',
                                           additional_info=new_tx)
                else:
                    self.logger.error("Got conditional block without a proof %s ", cache.from_peer)
                    raise RuntimeError("Block could not be validated: %s, %s" % (validation[0], validation[1]))

        linked = self.persistence.get_linked(blk)
        if blk.link_sequence_number == UNKNOWN_SEQ and blk.link_public_key == self.my_peer.public_key.key_to_bin() and linked:
            # Send the already created block back
            self.send_block(linked, address=peer.address)

        # Is this a request, addressed to us, and have we not signed it already?
        if (blk.link_sequence_number != UNKNOWN_SEQ
                or blk.link_public_key != self.my_peer.public_key.key_to_bin()
                or linked is not None):
            return

        self.logger.info("Received request block addressed to us (%s)", blk)

        try:
            should_sign = await maybe_coroutine(self.should_sign, blk)
        except Exception as e:
            self.logger.error("Error while determining whether to sign (error: %s)", e)
            return

        if not should_sign:
            self.logger.info("Not signing block %s", blk)
            return

        peer_id = self.persistence.key_to_id(blk.public_key)
        if blk.type == b'spend':
            # Request proofs from the peer if:
            #  1) If estimated balance less than zero
            #  2) If no proofs attached, no recent local proofs and depending on risk
            if self.persistence.get_balance(peer_id) < 0 or \
                    (not status and not audit_proofs and not self.persistence.get_peer_proofs(peer_id,
                                                                                              blk.sequence_number) and
                     random.random() > self.settings.risk):
                status_and_proofs = await self.validate_spend(blk, peer)
                return await self.process_half_block(blk, peer, *status_and_proofs)
            if 'condition' in blk.transaction:
                pub_key = unhexlify(blk.transaction['condition'])
                if self.my_peer.public_key.key_to_bin() != pub_key:
                    # This is a multi-hop conditional transaction, relay to next peer
                    # TODO: add to settings fees
                    fees = 0
                    spend_value = blk.transaction['value'] - fees
                    new_tx = blk.transaction
                    val = self.prepare_spend_transaction(pub_key, spend_value)
                    if not val:
                        # need to mint new values
                        mint = self.prepare_mint_transaction()
                        return addCallback(self.self_sign_block(block_type=b'claim', transaction=mint),
                                           lambda _: self.process_half_block(blk, peer))
                    next_peer, added = val
                    new_tx.update(added)
                    return self.sign_block(next_peer, next_peer.public_key.key_to_bin(), transaction=new_tx,
                                           block_type=blk.type, from_peer=peer,
                                           from_peer_seq_num=blk.sequence_number)
                else:
                    # Conditional block that terminates at our peer: add additional_info and send claim
                    sign = blk.crypto.create_signature(self.my_peer.key, blk.transaction['nonce'].encode())
                    new_tx = blk.transaction
                    new_tx['proof'] = hexlify(sign).decode()
                    return self.sign_block(peer, linked=blk, block_type=b'claim', additional_info=new_tx)

            self.sign_block(peer, linked=blk, block_type=b'claim')

    async def validate_spend(self, spend_block, peer):
        from_peer = self.persistence.key_to_id(spend_block.public_key)
        crawl_id = self.persistence.id_to_int(from_peer)
        cache = self.request_cache.get(u"proof-request", crawl_id)
        if not cache:
            # Need to get more information from the peer to verify the claim
            self.logger.info("Requesting the status and audit proofs %s:%d from peer %s:%d",
                             crawl_id, spend_block.sequence_number, peer.address[0], peer.address[1])
            except_pack = json.dumps(list())
            if self.settings.security_mode == SecurityMode.VANILLA:
                future = self.send_peer_crawl_request(crawl_id, peer, spend_block.sequence_number, except_pack)
            else:
                future = self.send_audit_proofs_request(peer, spend_block.sequence_number, crawl_id)
            return await future
        else:
            future = Future()
            cache.futures.append(future)
            return await future

    def verify_audit(self, status, audit):
        # This is a claim of a conditional transaction
        pub_key = default_eccrypto.key_from_public_bin(unhexlify(audit[0]))
        sign = unhexlify(audit[1])

        return default_eccrypto.is_valid_signature(pub_key, status, sign)

    def trigger_security_alert(self, peer_id, errors):
        tx = {'errors': errors, 'peer': peer_id}
        # TODO attach proof to transaction
        self.self_sign_block(block_type=b'alert', transaction=tx)

    def validate_audit_proofs(self, raw_status, raw_audit_proofs, block):
        self.logger.info("Received audit proofs for block %s", block)
        if self.settings.security_mode == SecurityMode.VANILLA:
            return True

        status = json.loads(raw_status)
        audit_proofs = json.loads(raw_audit_proofs)

        for v in audit_proofs.items():
            if not self.verify_audit(raw_status, v):
                self.logger.error("Audit did not validate %s %s", v, status)

        peer_id = self.persistence.key_to_id(block.public_key)
        # Put audit status into the local db
        result = self.verify_peer_status(peer_id, status)
        if result == ValidationResult.invalid:
            # Alert: Peer is provably hiding a transaction
            self.logger.error("Peer is hiding transactions %s", result.errors)
            self.trigger_security_alert(peer_id, result.errors)
            return False

        res = self.persistence.dump_peer_status(peer_id, status)
        self.persistence.add_peer_proofs(peer_id, status['seq_num'], status, raw_audit_proofs)
        return res

    def finalize_audits(self, audit_seq, status, audits):
        if not audits:
            self.logger.info("We did not receive any audit proof from others - not finalizing this audit!")
            return

        self.logger.info("Audit with sequence number %d finalized (audits: %d)", audit_seq, len(audits))
        full_audit = dict(audits)
        proofs = json.dumps(full_audit)
        # Update database audit proofs
        my_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
        self.persistence.add_peer_proofs(my_id, audit_seq, status, proofs)
        # Get peers requested
        processed_ids = set()
        responses_to_send = []
        for seq, peers_val in list(self.proof_requests.items()):
            if seq <= audit_seq:
                for p, audit_id in peers_val:
                    if (p, audit_id) not in processed_ids:
                        responses_to_send.append((p, audit_id, proofs, status))
                        processed_ids.add((p, audit_id))
                del self.proof_requests[seq]

        for p, audit_id, proofs, status in responses_to_send:
            self.audit_response_queue.put_nowait((p, audit_id, proofs, status))

    async def trustchain_active_sync(self, community_mid):
        # choose the peers
        self.logger.info("Active Sync asking in the community %s", hexlify(community_mid).decode())

        # Get own last block in the community
        peer_key = self.my_peer.public_key.key_to_bin()
        block = self.persistence.get_latest(peer_key)
        if not block:
            self.logger.info("Peer has no block for audit. Skipping audit for now.")
            return

        # Get the peer list for the community
        peer_list = self.pex[community_mid].get_peers()

        # Exclude crawlers - don't ask them for audits
        peer_list = [peer for peer in peer_list if hexlify(peer.public_key.key_to_bin()) not in self.settings.crawlers]

        seq_num = block.sequence_number
        seed = peer_key + bytes(seq_num)
        selected_peers = self.choose_community_peers(peer_list, seed, min(self.settings.com_size, len(peer_list)))
        if not selected_peers:
            self.logger.info("There are no peers in the community to ask for an audit, skipping audit for now.")
            return

        # Do we already have audit proofs for this sequence number? If so, don't ask for more proofs
        my_id = self.persistence.key_to_id(peer_key)
        if self.persistence.get_peer_proofs(my_id, seq_num):
            self.logger.info("Skipping audit since we already have proofs for our last block.")
            return

        peer_status = self.form_peer_status_response(peer_key, selected_peers)
        # Send an audit request for the block + seq num
        # Now we send status + seq_num
        crawl_id = self.persistence.id_to_int(self.persistence.key_to_id(peer_key))
        # Check if there are active audit requests for this peer
        if not self.request_cache.get(u'audit', crawl_id):
            audit_future = Future()
            self.request_cache.add(AuditRequestCache(self, crawl_id, audit_future,
                                                     total_expected_audits=len(selected_peers)))
            self.logger.info("Requesting an audit for sequence number %d from %d peers", seq_num, len(selected_peers))
            for peer in selected_peers:
                self.send_audit_request(peer, crawl_id, peer_status)
            # when enough audits received, finalize
            audits = await audit_future
            self.finalize_audits(seq_num, peer_status, audits)

    def choose_community_peers(self, com_peers, current_seed, commitee_size):
        rand = random.Random(current_seed)
        return rand.sample(com_peers, commitee_size)

    async def send_audit_proofs_request(self, peer, seq_num, audit_id):
        """
        Request audit proofs for some sequence number from a specific peer.
        """
        self._logger.debug("Sending audit proof request to peer %s:%d (seq num: %d, id: %s)",
                           peer.address[0], peer.address[1], seq_num, audit_id)
        request_future = Future()
        cache = AuditProofRequestCache(self, audit_id)
        cache.futures.append(request_future)
        self.request_cache.add(cache)

        global_time = self.claim_global_time()
        payload = AuditProofRequestPayload(seq_num, audit_id).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 11, [dist, payload], False)
        self.endpoint.send(peer.address, packet)
        return await request_future

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, AuditProofRequestPayload)
    def received_audit_proofs_request(self, source_address, dist, payload, data):
        # get the last collected audit proof and send it back
        my_id = self.persistence.key_to_id(self.my_peer.public_key.key_to_bin())
        pack = self.persistence.get_peer_proofs(my_id, int(payload.seq_num))
        if pack:
            seq_num, status, proofs = pack
            # There is an audit request peer can answer
            self.respond_with_audit_proof(source_address, payload.crawl_id, proofs, status)
        else:
            # There are no proofs that we can provide to this peer.
            # Remember the request and answer later, when we received enough proofs.
            self._logger.info("Adding audit proof request from %s:%d (id: %d) to cache",
                              source_address[0], source_address[1], payload.crawl_id)
            if payload.seq_num not in self.proof_requests:
                self.proof_requests[payload.seq_num] = []
            self.proof_requests[payload.seq_num].append((source_address, payload.crawl_id))

    def respond_with_audit_proof(self, address, audit_id, proofs, status):
        """
        Send audit proofs and status back to a specific peer, based on a request.
        """
        self.logger.info("Responding with audit proof %s to peer %s:%d", audit_id, address[0], address[1])
        for item in [proofs, status]:
            global_time = self.claim_global_time()
            payload = AuditProofResponsePayload(audit_id, item, item == proofs).to_pack_list()
            dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

            packet = self._ez_pack(self._prefix, 14, [dist, payload], False)
            self.endpoint.send(address, packet)

    async def evaluate_audit_response_queue(self):
        while True:
            audit_info = await self.audit_response_queue.get()
            address, audit_id, proofs, status = audit_info
            self.respond_with_audit_proof(address, audit_id, proofs, status)
            await sleep(self.settings.audit_response_queue_interval / 1000)

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, AuditProofResponsePayload)
    def received_audit_proofs_response(self, source_address, dist, payload, data):
        cache = self.request_cache.get(u'proof-request', payload.audit_id)
        if cache:
            if payload.is_proof:
                cache.received_audit_proof(payload.item)
            else:
                cache.received_peer_status(payload.item)
        else:
            self.logger.info("Received audit proof response for non-existent cache with id %s", payload.audit_id)

    @synchronized
    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, AuditProofPayload)
    def received_audit_proofs(self, source_address, dist, payload, data):
        cache = self.request_cache.get(u'audit', payload.audit_id)
        if cache:
            # status is known => This is audit collection initiated by my peer
            audit = json.loads(payload.audit_proof)
            # TODO: if audit not valid/resend with bigger peer set
            for v in audit.items():
                cache.received_audit_proof(v)
        else:
            self.logger.info("Received audit proof for non-existent cache with id %s", payload.audit_id)

    def send_audit_request(self, peer, crawl_id, peer_status):
        """
        Ask target peer for an audit of your chain.
        """
        self._logger.info("Sending audit request to peer %s:%d", peer.address[0], peer.address[1])
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = AuditRequestPayload(crawl_id, peer_status).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 12, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, AuditRequestPayload)
    def received_audit_request(self, peer, dist, payload):
        # TODO: Add DOS protection
        self.logger.info("Received audit request %s from peer %s:%d", payload.audit_id, peer.address[0],
                         peer.address[1])
        self.perform_audit(peer.address, payload)

    def perform_audit(self, source_address, audit_request):
        peer_id = self.persistence.int_to_id(audit_request.audit_id)
        # TODO: add verifications
        try:
            peer_status = json.loads(audit_request.peer_status)
            # Verify peer status
            result = self.verify_peer_status(peer_id, peer_status)
            if result.state == ValidationResult.invalid:
                # Alert: Peer is provably hiding a transaction
                self.logger.error("Peer is hiding transactions: %s", result.errors)
                self.trigger_security_alert(peer_id, result.errors)
            else:
                if self.persistence.dump_peer_status(peer_id, peer_status):
                    # Create an audit proof for the this sequence and send it back
                    seq_num = peer_status['seq_num']
                    self.persistence.add_peer_proofs(peer_id, seq_num, peer_status, None)
                    # Create an audit proof for the this sequence
                    signature = default_eccrypto.create_signature(self.my_peer.key, audit_request.peer_status)
                    # create an audit proof
                    audit = {}
                    my_id = hexlify(self.my_peer.public_key.key_to_bin()).decode()
                    audit[my_id] = hexlify(signature).decode()
                    self.send_audit_proofs(source_address, audit_request.audit_id, json.dumps(audit))
                else:
                    # This is invalid audit request, refusing to sign
                    self.logger.error("Received invalid audit request id %s", audit_request.crawl_id)
        except JSONDecodeError:
            self.logger.info("Invalid JSON received in audit request from peer %s:%d!",
                             source_address[0], source_address[1])

    def send_audit_proofs(self, address, audit_id, audit_proofs):
        """
        Send audit proofs back to a specific peer, based on a requested audit.
        """
        self.logger.info("Sending audit proof %s to peer %s:%d", audit_id, address[0], address[1])
        global_time = self.claim_global_time()
        payload = AuditProofPayload(audit_id, audit_proofs).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 10, [dist, payload], False)
        self.endpoint.send(address, packet)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, MintRequestPayload)
    def received_mint_request(self, peer, dist, payload):
        self._logger.info("Received mint request with value %d from peer %s", payload.mint_value, peer)
        self.mint(payload.mint_value)
        self.transfer(peer, payload.mint_value)

    def get_all_communities_peers(self):
        peers = set()
        for mid in self.pex:
            val = self.pex[mid].get_peers()
            if val:
                peers.update(val)
        return peers

    def verify_peer_status(self, peer_id, status):
        result = ValidationResult()
        if "seq_num" not in status or 'spends' not in status or 'claims' not in status:
            # Ignore peer status if it is old/ or ill formed
            result.state = ValidationResult.no_info
            return result

        # 1. Verify that peer included all known spenders
        all_verified = True
        for p in self.persistence.get_all_spend_peers(peer_id):
            balance = self.persistence.get_total_pairwise_spends(peer_id, p)
            seq_num = self.persistence.get_last_pairwise_spend_num(peer_id, p)
            if balance > 0 and seq_num <= status['seq_num']:
                if p not in status['spends'] or status['spends'][p][0] < balance:
                    # Alert, peer is hiding my transaction
                    result.err("Peer is hiding spend with peer {}".format(p))
            else:
                all_verified = False
        if result.state != ValidationResult.invalid and not all_verified:
            result.state = ValidationResult.partial
        # TODO: 2. Verify that there are no unknown holes
        return result

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlResponsePayload)
    def received_peer_crawl_response(self, peer, dist, payload):
        cache = self.request_cache.get(u"noodle-crawl", payload.crawl_id)
        if cache:
            peer_id = self.persistence.int_to_id(payload.crawl_id)
            prev_balance = self.persistence.get_balance(peer_id)
            self.logger.info("Dump chain for %s, balance before is %s", peer_id, prev_balance)
            status = json.loads(payload.chain)
            result = self.verify_peer_status(peer_id, status)
            if result == ValidationResult.invalid:
                # Alert: Peer is provably hiding a transaction
                self.logger.error("Peer is hiding transactions  %s", result.errors)
                self.trigger_security_alert(peer_id, result.errors)
                cache.received_empty_response()
            else:
                res = self.persistence.dump_peer_status(peer_id, status)
                seq_num = status['seq_num']
                self.persistence.add_peer_proofs(peer_id, seq_num, status, None)
                if not res:
                    self.logger.error("Status is ill-formed %s", status)
                after_balance = self.persistence.get_balance(peer_id)
                self.logger.info("Dump chain for %s, balance after is %s", peer_id, after_balance)
                if after_balance < 0:
                    self.logger.error("Balance is still negative! %s", status)
                cache.received_empty_response()

    def send_peer_crawl_response(self, peer, crawl_id, chain):
        """
        Send chain to response for the peer crawl
        """
        self._logger.info("Sending peer crawl response to peer %s:%d", peer.address[0], peer.address[1])
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlResponsePayload(crawl_id, chain).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 9, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

    def form_peer_status_response(self, public_key, exception_peer_list=None):
        status = self.persistence.get_peer_status(public_key)
        if self.settings.is_hiding:
            # Hide the top spend excluding the peer that asked it
            except_peers = set()
            for peer in exception_peer_list:
                peer_id = self.persistence.key_to_id(peer.public_key.key_to_bin())
                except_peers.add(peer_id)
            hiding = False
            for p in sorted(((v, k) for k, v in status['spends'].items()), reverse=True):
                if p[1] not in except_peers:
                    status['spends'].pop(p[1])
                    hiding = True
                    break
            if hiding:
                self.logger.warning("Hiding info in status")
            return json.dumps(status)
        return json.dumps(status)

    @synchronized
    @lazy_wrapper(GlobalTimeDistributionPayload, PeerCrawlRequestPayload)
    def received_peer_crawl_request(self, peer, dist, payload):
        # Need to convince peer with minimum number of blocks send
        # Get latest pairwise blocks/ including self claims
        my_key = self.my_peer.public_key.key_to_bin()
        my_id = self.persistence.key_to_id(my_key)
        peer_id = self.persistence.int_to_id(payload.crawl_id)
        if peer_id != my_id:
            self.logger.error("Peer requests not my peer status %s", peer_id)
        s1 = self.form_peer_status_response(my_key, [peer])
        self.logger.info("Received peer crawl from node %s for range, sending status len %s",
                         hexlify(peer.public_key.key_to_bin())[-8:], len(s1))
        self.send_peer_crawl_response(peer, payload.crawl_id, s1)

    async def send_peer_crawl_request(self, crawl_id, peer, seq_num, pack_except):
        """
        Send a crawl request to a specific peer.
        """
        crawl_future = Future()
        self.request_cache.add(NoodleCrawlRequestCache(self, crawl_id, crawl_future))
        self.logger.info("Requesting balance proof for peer %s at seq num %d with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = PeerCrawlRequestPayload(seq_num, crawl_id, pack_except).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 8, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)
        return await crawl_future

    def crawl_chain(self, peer, latest_block_num=0):
        """
        Crawl the whole chain of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available.
        """
        if self.request_cache.has("chaincrawl", ChainCrawlCache.get_number_for(peer)):
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return succeed(None)

        crawl_future = Future()
        cache = ChainCrawlCache(self, peer, crawl_future, known_chain_length=latest_block_num)
        self.request_cache.add(cache)
        get_event_loop().call_soon_threadsafe(ensure_future, self.send_next_partial_chain_crawl_request(cache))
        return crawl_future

    def crawl_lowest_unknown(self, peer, latest_block_num=None):
        """
        Crawl the lowest unknown block of a specific peer.
        :param latest_block_num: The latest block number of the peer in question, if available
        """
        sq = self.persistence.get_lowest_sequence_number_unknown(peer.public_key.key_to_bin())
        if latest_block_num and sq == latest_block_num + 1:
            return []  # We don't have to crawl this node since we have its whole chain
        return self.send_crawl_request(peer, peer.public_key.key_to_bin(), sq, sq)

    def send_crawl_request(self, peer, public_key, start_seq_num, end_seq_num, for_half_block=None):
        """
        Send a crawl request to a specific peer.
        """
        crawl_id = for_half_block.hash_number if for_half_block else \
            RandomNumberCache.find_unclaimed_identifier(self.request_cache, "crawl")
        crawl_future = Future()
        self.request_cache.add(CrawlRequestCache(self, crawl_id, crawl_future))
        self.logger.info("Requesting crawl of node %s (blocks %d to %d) with id %d",
                         hexlify(peer.public_key.key_to_bin())[-8:], start_seq_num, end_seq_num, crawl_id)

        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = CrawlRequestPayload(public_key, start_seq_num, end_seq_num, crawl_id).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        packet = self._ez_pack(self._prefix, 2, [auth, dist, payload])
        self.endpoint.send(peer.address, packet)

        return crawl_future

    @task
    async def perform_partial_chain_crawl(self, cache, start, stop):
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
            self.request_cache.pop("chaincrawl", cache.number)
            cache.crawl_future.set_result(None)
            return

        cache.current_request_attempts += 1
        await self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(), start, stop)
        await self.send_next_partial_chain_crawl_request(cache)

    async def send_next_partial_chain_crawl_request(self, cache):
        """
        Send the next partial crawl request, if we are not done yet.
        :param cache: The cache that stores progress regarding the chain crawl.
        """
        lowest_unknown = self.persistence.get_lowest_sequence_number_unknown(cache.peer.public_key.key_to_bin())
        if cache.known_chain_length and cache.known_chain_length == lowest_unknown - 1:
            # At this point, we have all the blocks we need
            self.request_cache.pop("chaincrawl", cache.number)
            cache.crawl_future.set_result(None)
            return

        if not cache.known_chain_length:
            # Do we know the chain length of the crawled peer? If not, make sure we get to know this first.
            blocks = await self.send_crawl_request(cache.peer, cache.peer.public_key.key_to_bin(), -1, -1)
            if not blocks:
                self.request_cache.pop("chaincrawl", cache.number)
                cache.crawl_future.set_result(None)
                return

            cache.known_chain_length = blocks[0].sequence_number
            await self.send_next_partial_chain_crawl_request(cache)
            return

        latest_block = self.persistence.get_latest(cache.peer.public_key.key_to_bin())
        if not latest_block:
            # We have no knowledge of this peer but we have the length of the chain.
            # Simply send a request from the genesis block to the known chain length.
            self.perform_partial_chain_crawl(cache, 1, cache.known_chain_length)
            return
        elif latest_block and lowest_unknown == latest_block.sequence_number + 1:
            # It seems that we filled all gaps in the database; check whether we can do one final request
            if latest_block.sequence_number < cache.known_chain_length:
                self.perform_partial_chain_crawl(cache, latest_block.sequence_number + 1, cache.known_chain_length)
            else:
                self.request_cache.pop("chaincrawl", cache.number)
                cache.crawl_future.set_result(None)
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

        blocks = self.persistence.crawl(payload.public_key, start_seq_num, end_seq_num,
                                        limit=self.settings.max_crawl_batch)
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
        while not self.settings.ignore_validation and validation[0] != ValidationResult.partial_next \
                and validation[0] != ValidationResult.valid:
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
        if not self.settings.ignore_validation and validation[0] != ValidationResult.partial_next \
                and validation[0] != ValidationResult.valid:
            self.logger.error("Our chain did not validate. Result %s", repr(validation))
            self.sanitize_database()

    def send_crawl_response(self, block, crawl_id, index, total_count, peer):
        self.logger.debug("Sending block for crawl request to %s (%s)", peer, block)

        # Don't answer with any invalid blocks.
        validation = self.validate_persist_block(block)
        if not self.settings.ignore_validation and validation[0] == ValidationResult.invalid and total_count > 0:
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
    async def received_crawl_response(self, source_address, dist, payload, data):
        await self.received_half_block(source_address, data[:-12])  # We cut off a few bytes to make it a BlockPayload

        block = self.get_block_class(payload.type).from_payload(payload, self.serializer)
        cache = self.request_cache.get("crawl", payload.crawl_id)
        if cache:
            cache.received_block(block, payload.total_count)

    @lazy_wrapper_unsigned_wd(GlobalTimeDistributionPayload, EmptyCrawlResponsePayload)
    def received_empty_crawl_response(self, source_address, dist, payload, data):
        cache = self.request_cache.get("crawl", payload.crawl_id)
        if cache:
            self.logger.info("Received empty crawl response for crawl with ID %d", payload.crawl_id)
            cache.received_empty_response()

    def get_chain_length(self):
        """
        Return the length of your own chain.
        """
        latest_block = self.persistence.get_latest(self.my_peer.public_key.key_to_bin())
        return 0 if not latest_block else latest_block.sequence_number

    @synchronized
    def create_introduction_request(self, socket_address, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(NoodleCommunity, self).create_introduction_request(socket_address, extra_bytes)

    @synchronized
    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b''):
        extra_bytes = struct.pack('>l', self.get_chain_length())
        return super(NoodleCommunity, self).create_introduction_response(lan_socket_address, socket_address,
                                                                             identifier, introduction, extra_bytes)

    def build_security_community(self, community_mid):
        # Start sync task after the discovery
        task = self.trustchain_sync \
            if self.settings.security_mode == SecurityMode.VANILLA \
            else self.trustchain_active_sync

        self.periodic_sync_lc[community_mid] = self.register_task("sync_" + str(community_mid), task, community_mid,
                                                                  delay=random.random(),
                                                                  interval=self.settings.sync_time)

    def init_minter_community(self):
        if self.my_peer.mid not in self.pex and hexlify(
                self.my_peer.public_key.key_to_bin()) not in self.settings.crawlers:
            self.logger.info('Creating own minter community')
            self.pex[self.my_peer.mid] = self
            self.build_security_community(self.my_peer.mid)

    @synchronized
    def introduction_response_callback(self, peer, dist, payload):
        chain_length = None
        if payload.extra_bytes:
            chain_length = struct.unpack('>l', payload.extra_bytes)[0]

        if peer.address in self.network.blacklist:  # Do not crawl addresses in our blacklist (trackers)
            return
        self.form_subtrust_community(peer)

        # Check if we have pending crawl requests for this peer
        has_intro_crawl = self.request_cache.has("introcrawltimeout", IntroCrawlTimeout.get_number_for(peer))
        has_chain_crawl = self.request_cache.has("chaincrawl", ChainCrawlCache.get_number_for(peer))
        if has_intro_crawl or has_chain_crawl:
            self.logger.debug("Skipping crawl of peer %s, another crawl is pending", peer)
            return

        if self.settings.crawler:
            self.crawl_chain(peer, latest_block_num=chain_length)

    def form_subtrust_community(self, peer):
        known_minters = set(nx.get_node_attributes(self.known_graph, 'minter').keys())
        if hexlify(self.my_peer.public_key.key_to_bin()) in self.settings.crawlers:
            self.logger.warning("I am a crawler - not forming subtrust community")
        elif not self.ipv8:
            self.logger.warning('No IPv8 service object available, cannot start SubTrustCommunity')
        elif (peer.public_key.key_to_bin() in known_minters or not self.settings.minters) and peer.mid not in self.pex:
            self.logger.info("Creating SubTrustCommunity around peer %s", peer)
            community = SubTrustCommunity(self.my_peer, self.ipv8.endpoint, Network(),
                                          master_peer=peer, max_peers=self.settings.max_peers_subtrust)
            self.ipv8.overlays.append(community)
            self.pex[peer.mid] = community

            if self.bootstrap_master:
                self.logger.info('Proceed with a bootstrap master')
                for k in self.bootstrap_master:
                    community.walk_to(k)
            else:
                self.ipv8.strategies.append((RandomWalk(community), self.settings.max_peers_subtrust))
            self.build_security_community(peer.mid)

    async def unload(self):
        self.logger.debug("Unloading the Noodle Community.")
        self.shutting_down = True

        await self.request_cache.shutdown()

        if self.mem_db_flush_lc and not self.transfer_lc.done():
            self.mem_db_flush_lc.cancel()
        for mid in self.pex:
            if mid in self.periodic_sync_lc and not self.periodic_sync_lc[mid].done():
                self.periodic_sync_lc[mid].cancel()
        if self.transfer_lc and not self.transfer_lc.done():
            self.transfer_lc.cancel()

        # Stop queues
        if not self.transfer_queue_task.done():
            self.transfer_queue_task.cancel()
        if not self.incoming_block_queue_task.done():
            self.incoming_block_queue_task.cancel()
        if not self.audit_response_queue_task.done():
            self.audit_response_queue_task.cancel()

        await super(NoodleCommunity, self).unload()

        # Close the persistence layer
        self.persistence.close()


class NoodleTestnetCommunity(NoodleCommunity):
    """
    This community defines the testnet for Noodle
    """
    DB_NAME = 'noodle_testnet'

    master_peer = Peer(unhexlify("4c69624e61434c504b3abaa09505b032231182217276fc355dc38fb8e4998a02f91d3ba00f6fbf648"
                                 "5116b8c8c212be783fc3171a529f50ce25feb6c4dcc8106f468e5401bf37e8129e2"))
