import hashlib
import os
import time
from asyncio import FIRST_COMPLETED, Future, gather, wait
from binascii import hexlify, unhexlify
from collections import defaultdict, deque
from itertools import zip_longest

from . import DHTError
from .churn import PingChurn
from .payload import (FindRequestPayload, FindResponsePayload, PingRequestPayload, PingResponsePayload,
                      SignedStrPayload, StoreRequestPayload, StoreResponsePayload, StrPayload)
from .routing import Node, RoutingTable, calc_node_id, distance
from .storage import Storage
from ..community import Community, _DEFAULT_ADDRESSES
from ..lazy_community import lazy_wrapper, lazy_wrapper_wd
from ..messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from ..peer import Peer
from ..peerdiscovery.network import Network
from ..requestcache import RandomNumberCache, RequestCache
from ..taskmanager import task
from ..util import cast_to_bin

PING_INTERVAL = 25

# Maximum number of seconds a token can remain valid
TOKEN_EXPIRATION_TIME = 600

DHT_ENTRY_STR = 0
DHT_ENTRY_STR_SIGNED = 1

MAX_ENTRY_SIZE = 170
MAX_ENTRY_AGE = 86400

# Maximum number of nodes to start a crawl with
MAX_CRAWL_NODES = 8
# Maximum number of find-requests a single crawl is allowed to make (excluding punctures)
MAX_CRAWL_REQUESTS = 24
# Maximum number of simultaneous outstanding find-requests per crawl
MAX_CRAWL_TASKS = 4

MAX_VALUES_IN_STORE = 8
MAX_VALUES_IN_FIND = 8
MAX_NODES_IN_FIND = 8

# Target number of nodes at which a key-value pair should be stored
TARGET_NODES = 8

MSG_PING = 7
MSG_PONG = 8
MSG_STORE_REQUEST = 9
MSG_STORE_RESPONSE = 10
MSG_FIND_REQUEST = 11
MSG_FIND_RESPONSE = 12


async def gather_without_errors(*futures):
    results = await gather(*futures, return_exceptions=True)
    return [r for r in results if not isinstance(r, Exception)]


class Request(RandomNumberCache):
    """
    This request cache keeps track of all outstanding requests within the DHTCommunity.
    """
    def __init__(self, community, msg_type, node, params=None, consume_errors=False, timeout=5.0):
        super(Request, self).__init__(community.request_cache, msg_type)
        self.msg_type = msg_type
        self.node = node
        self.params = params
        self.future = Future()
        self.start_time = time.time()
        self.consume_errors = consume_errors
        self.timeout = timeout

    @property
    def timeout_delay(self):
        return self.timeout

    def on_timeout(self):
        if not self.future.done():
            self._logger.debug('Timeout for %s to %s', self.msg_type, self.node)
            self.node.failed += 1
            if not self.consume_errors:
                self.future.set_exception(DHTError('Timeout for {} to {}'.format(self.msg_type, self.node)))
            else:
                self.future.set_result(None)

    def on_complete(self):
        self.node.last_response = time.time()
        self.node.failed = 0
        self.node.rtt = time.time() - self.start_time


class Crawl:

    def __init__(self, target, nodes, force_nodes=False, offset=0):
        self.target = target
        # Keep a list of nodes that still need to be contacted: [(node_to_contact, node_to_puncture)]
        self.nodes_todo = [[n, None] for n in nodes]
        self.nodes_tried = set()
        self.responses = []

        self.force_nodes = force_nodes
        self.offset = offset

    def add_response(self, sender, response):
        self.responses.append((sender, response))

        for index, node in enumerate(response.get('nodes', [])):
            if node in self.nodes_tried:
                continue

            # Only add nodes that are better than our current top-4
            if len(self.nodes_todo) >= 4 \
               and distance(node.id, self.target) > distance(self.nodes_todo[3][0].id, self.target):
                continue

            index_existing = next((i for i, t in enumerate(self.nodes_todo) if t[0] == node), None)
            if index_existing is not None:
                self.nodes_todo[index_existing][1] = None if index == 0 else sender
                continue

            self.nodes_todo.append([node, None if index == 0 else sender])
            self.nodes_todo.sort(key=lambda t: distance(t[0].id, self.target))

    @property
    def done(self):
        return len(self.nodes_tried) >= MAX_CRAWL_REQUESTS or not self.nodes_todo

    @property
    def cache_candidate(self):
        # Return closest node to the target that did not respond with values
        nodes_no_values = [sender for sender, response in self.responses if 'values' not in response]
        nodes_no_values.sort(key=lambda n: distance(n.id, self.target))
        return nodes_no_values[0] if nodes_no_values else None

    @property
    def values(self):
        # Merge all values received into one tuple. First pick the first value from each tuple, then the second, etc.
        value_responses = [response['values'] for _, response in self.responses if 'values' in response]
        values = sum(zip_longest(*value_responses), ())

        # Filter out duplicates while preserving order
        seen = set()
        return [v for v in values if v is not None and not (v in seen or seen.add(v))]

    @property
    def nodes(self):
        return sorted(self.nodes_tried, key=lambda n: distance(n.id, self.target))


class DHTCommunity(Community):
    """
    Community for storing/finding key-value pairs.
    """
    master_peer = Peer(unhexlify('4c69624e61434c504b3a4c99f04cef9ba4ca645401cd51b8ef634e63e2ad0d3209eca958ce0293d7cf668'
                                 '2059469c1a253e66191bd3b96a082a8e11cc35962b9b6f8434e21518a0344af'))

    def __init__(self, *args, **kwargs):
        super(DHTCommunity, self).__init__(*args, **kwargs)
        self.network = Network()
        self.network.blacklist_mids.append(self.my_peer.mid)
        self.network.blacklist.extend(_DEFAULT_ADDRESSES)

        self.routing_table = RoutingTable(self.my_node_id)
        self.storage = Storage()
        self.request_cache = RequestCache()
        self.tokens = {}
        self.token_secrets = deque(maxlen=2)
        # First call to token_maintenance should happen immediately, in case we get requests before it gets executed
        self.token_maintenance()
        self.register_task('token_maintenance', self.token_maintenance, interval=300)
        self.register_task('node_maintenance', self.node_maintenance, interval=60)

        # Register messages
        self.decode_map.update({
            chr(MSG_PING): self.on_ping_request,
            chr(MSG_PONG): self.on_ping_response,
            chr(MSG_STORE_REQUEST): self.on_store_request,
            chr(MSG_STORE_RESPONSE): self.on_store_response,
            chr(MSG_FIND_REQUEST): self.on_find_request,
            chr(MSG_FIND_RESPONSE): self.on_find_response,
        })

        self.logger.info('DHT community initialized (peer mid %s)', hexlify(self.my_peer.mid))

    def get_available_strategies(self):
        return {'PingChurn': PingChurn}

    async def unload(self):
        # Note that order matters here. First we unload the community, then we shutdown
        # the RequestCache. This prevents calls to RequestCache.add after
        # RequestCache.shutdown is called (which will return None after shutdown).
        await super(DHTCommunity, self).unload()
        await self.request_cache.shutdown()

    @property
    def my_node_id(self):
        return calc_node_id(self.my_peer.address[0], self.my_peer.mid)

    def send_message(self, address, message_id, payload_cls, payload_args):
        global_time = self.claim_global_time()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        payload = payload_cls(*payload_args).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        packet = self._ez_pack(self._prefix, message_id, [auth, dist, payload])
        return self.endpoint.send(address, packet)

    def get_requesting_node(self, peer):
        node = Node(peer.key, peer.address)

        if self.routing_table.has(node.id) and self.routing_table.get(node.id).blocked:
            self.logger.debug('Too many queries\'s, dropping packet')
            return

        node = self.routing_table.add(node) or node
        node.last_queries.append(time.time())
        return node

    def introduction_request_callback(self, peer, dist, payload):
        self.on_node_discovered(peer.public_key.key_to_bin(), peer.address)

    def introduction_response_callback(self, peer, dist, payload):
        self.on_node_discovered(peer.public_key.key_to_bin(), peer.address)

    def on_node_discovered(self, public_key_bin, source_address):
        # Filter out trackers
        if source_address not in self.network.blacklist:
            node = Node(public_key_bin, source_address)
            existed = self.routing_table.has(node.id)
            rt_node = self.routing_table.add(node)

            if not existed and rt_node:
                self.logger.debug('Added node %s to the routing table', node)
                # Ping the node in order to determine RTT
                self.ping(rt_node)

    def ping(self, node):
        self.logger.debug('Pinging node %s', node)
        cache = self.request_cache.add(Request(self, 'ping', node, consume_errors=True))
        self.send_message(node.address, MSG_PING, PingRequestPayload, (cache.number,))
        node.last_ping_sent = time.time()
        return cache.future

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingRequestPayload)
    def on_ping_request(self, peer, dist, payload, data):
        self.logger.debug('Got ping-request from %s', peer.address)

        node = self.get_requesting_node(peer)
        if not node:
            return

        self.send_message(peer.address, MSG_PONG, PingResponsePayload, (payload.identifier,))

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingResponsePayload)
    def on_ping_response(self, peer, dist, payload, data):
        if not self.request_cache.has('ping', payload.identifier):
            self.logger.error('Got ping-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got ping-response from %s', peer.address)
        cache = self.request_cache.pop('ping', payload.identifier)
        cache.on_complete()
        if not cache.future.done():
            cache.future.set_result(cache.node)

    def serialize_value(self, data, sign=True):
        if sign:
            payload = SignedStrPayload(data, int(time.time()), self.my_peer.public_key.key_to_bin())
            return self._ez_pack(b'', DHT_ENTRY_STR_SIGNED, [payload.to_pack_list()], sig=True)
        payload = StrPayload(data)
        return self._ez_pack(b'', DHT_ENTRY_STR, [payload.to_pack_list()], sig=False)

    def unserialize_value(self, value):
        if ord(value[0:1]) == DHT_ENTRY_STR:
            payload = self.serializer.unpack_to_serializables([StrPayload], value[1:])[0]
            return payload.data, None, 0
        elif ord(value[0:1]) == DHT_ENTRY_STR_SIGNED:
            payload = self.serializer.unpack_to_serializables([SignedStrPayload], value[1:])[0]
            public_key = self.crypto.key_from_public_bin(payload.public_key)
            sig_len = self.crypto.get_signature_length(public_key)
            sig = value[-sig_len:]
            if self.crypto.is_valid_signature(public_key, value[:-sig_len], sig):
                return payload.data, payload.public_key, payload.version

    def add_value(self, key, value, max_age=MAX_ENTRY_AGE):
        unserialized = self.unserialize_value(value)
        if unserialized:
            _, public_key, version = unserialized
            id_ = hashlib.sha1(public_key).digest() if public_key else None
            self.storage.put(key, value, id_=id_, version=version, max_age=max_age)
        else:
            self.logger.warning('Failed to store value %s', hexlify(value))

    async def store_value(self, key, data, sign=False):
        value = self.serialize_value(data, sign=sign)
        return await self._store(key, value)

    async def _store(self, key, value):
        if len(value) > MAX_ENTRY_SIZE:
            raise DHTError('Maximum length exceeded')

        nodes = await self.find_nodes(key)
        nodes = await self.store_on_nodes(key, [value], nodes[:TARGET_NODES])
        if len(nodes) < 1:
            raise DHTError('Failed to store value on DHT')
        return nodes

    @task
    async def store_on_nodes(self, key, values, nodes):
        if not nodes:
            raise DHTError('No nodes found for storing the key-value pairs')

        values = values[:MAX_VALUES_IN_STORE]

        # Check if we also need to store this key-value pair
        largest_distance = max([distance(node.id, key) for node in nodes])
        if len(nodes) < TARGET_NODES or distance(self.my_node_id, key) < largest_distance:
            for value in reversed(values):
                self.add_value(key, value)

        now = time.time()
        futures = []
        for node in nodes:
            if node in self.tokens and self.tokens[node][0] + TOKEN_EXPIRATION_TIME > now:
                cache = self.request_cache.add(Request(self, 'store', node))
                futures.append(cache.future)
                self.send_message(node.address, MSG_STORE_REQUEST, StoreRequestPayload,
                                  (cache.number, self.tokens[node][1], key, values))
            else:
                self.logger.debug('Not sending store-request to %s (no token available)', node)

        if not futures:
            raise DHTError('Value was not stored')
        return await gather_without_errors(*futures)

    @lazy_wrapper(GlobalTimeDistributionPayload, StoreRequestPayload)
    def on_store_request(self, peer, dist, payload):
        self.logger.debug('Got store-request from %s', peer.address)

        node = self.get_requesting_node(peer)
        if not node:
            return
        if any([len(value) > MAX_ENTRY_SIZE for value in payload.values]):
            self.logger.warning('Maximum length of value exceeded, dropping packet.')
            return
        if len(payload.values) > MAX_VALUES_IN_STORE:
            self.logger.warning('Too many values, dropping packet.')
            return
        # Note that even though we are preventing spoofing of source_address (by checking the token),
        # the value that is to be stored isn't checked. This should be done at a higher level.
        if not self.check_token(node, payload.token):
            self.logger.warning('Bad token, dropping packet.')
            return

        # How many nodes (that we know of) are closer to this value?
        num_closer = 0
        for node in self.routing_table.closest_nodes(payload.target, max_nodes=20):
            if distance(node.id, payload.target) < distance(self.my_node_id, payload.target):
                num_closer += 1

        # To prevent over-caching, the expiration time of an entry depends on the number
        # of nodes that are closer than us.
        max_age = MAX_ENTRY_AGE // 2 ** max(0, num_closer - TARGET_NODES + 1)
        for value in payload.values:
            self.add_value(payload.target, value, max_age)

        self.send_message(peer.address, MSG_STORE_RESPONSE, StoreResponsePayload, (payload.identifier,))

    @lazy_wrapper(GlobalTimeDistributionPayload, StoreResponsePayload)
    def on_store_response(self, peer, dist, payload):
        if not self.request_cache.has('store', payload.identifier):
            self.logger.error('Got store-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got store-response from %s', peer.address)
        cache = self.request_cache.pop('store', payload.identifier)
        cache.on_complete()
        if not cache.future.done():
            cache.future.set_result(cache.node)

    def _send_find_request(self, node, target, force_nodes, offset=0):
        cache = self.request_cache.add(Request(self, 'find', node, [force_nodes], consume_errors=True, timeout=2.0))
        self.send_message(node.address, MSG_FIND_REQUEST, FindRequestPayload,
                          (cache.number, self.my_estimated_lan, target, offset, force_nodes))
        return cache.future

    async def _contact_node(self, crawl, node, puncture_node):
        if puncture_node:
            await self._send_find_request(puncture_node, node.id, crawl.force_nodes)
        result = await self._send_find_request(node, crawl.target, crawl.force_nodes, crawl.offset)
        if result:
            self.routing_table.add(node)
            crawl.add_response(node, result)

    async def _find(self, target, force_nodes=False, offset=0, debug=False):
        nodes_closest = self.routing_table.closest_nodes(target, max_nodes=MAX_CRAWL_NODES)
        if not nodes_closest:
            raise DHTError('No nodes found in the routing table')

        crawl = Crawl(target, nodes_closest, force_nodes=force_nodes, offset=offset)
        tasks = set()
        while True:
            # Keep running tasks until work is done.
            while not crawl.done and len(tasks) < MAX_CRAWL_TASKS:
                node, puncture_node = crawl.nodes_todo.pop(0)
                tasks.add(self.register_anonymous_task('contact_node', self._contact_node, crawl, node, puncture_node))
                # Add to nodes_tried immediately to prevent sending multiple find-requests to the same node.
                crawl.nodes_tried.add(node)
            if not tasks:
                break
            _, tasks = await wait(tasks, return_when=FIRST_COMPLETED)

        if force_nodes:
            return crawl.nodes

        cache_candidate = crawl.cache_candidate
        values = crawl.values

        if cache_candidate and values:
            # Store the key-value pair on the most recently visited node that
            # did not have it (for caching purposes).
            self.store_on_nodes(target, values, [cache_candidate])

        if debug:
            return self.post_process_values(values), crawl
        return self.post_process_values(values)

    def post_process_values(self, values):
        # Unpack values and filter out duplicates
        unpacked = defaultdict(list)
        for value in values:
            unserialized = self.unserialize_value(value)
            if unserialized:
                data, public_key, version = unserialized
                unpacked[public_key].append((version, data))

        results = []

        # Signed data
        for public_key, data_list in unpacked.items():
            if public_key is not None:
                results.append((max(data_list, key=lambda t: t[0])[1], public_key))

        # Unsigned data
        for data in unpacked[None]:
            results.append((data[1], None))

        return results

    def find_values(self, target, offset=0, debug=False):
        return self._find(target, force_nodes=False, offset=offset, debug=debug)

    def find_nodes(self, target, debug=False):
        return self._find(target, force_nodes=True, debug=debug)

    @lazy_wrapper(GlobalTimeDistributionPayload, FindRequestPayload)
    def on_find_request(self, peer, dist, payload):
        self.logger.debug('Got find-request for %s from %s', hexlify(payload.target), peer.address)

        node = self.get_requesting_node(peer)
        if not node:
            return

        nodes = []
        values = self.storage.get(payload.target, starting_point=payload.offset, limit=MAX_VALUES_IN_FIND) \
            if not payload.force_nodes else []

        if payload.force_nodes or not values:
            nodes = self.routing_table.closest_nodes(payload.target, exclude_node=node, max_nodes=MAX_NODES_IN_FIND)
            # Send puncture request to the closest node
            if nodes:
                packet = self.create_puncture_request(payload.lan_address, peer.address, payload.identifier)
                self.endpoint.send(nodes[0].address, packet)

        self.send_message(peer.address, MSG_FIND_RESPONSE, FindResponsePayload,
                          (payload.identifier, self.generate_token(node), values, nodes))

    @lazy_wrapper(GlobalTimeDistributionPayload, FindResponsePayload)
    def on_find_response(self, peer, dist, payload):
        if not self.request_cache.has('find', payload.identifier):
            self.logger.error('Got find-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got find-response from %s', peer.address)
        cache = self.request_cache.pop('find', payload.identifier)
        cache.on_complete()

        self.tokens[cache.node] = (time.time(), payload.token)

        if cache.future.done():
            # The errback must already have been called (due to a timeout)
            return
        elif cache.params[0]:
            cache.future.set_result({'nodes': payload.nodes})
        else:
            cache.future.set_result({'values': payload.values} if payload.values else {'nodes': payload.nodes})

    async def node_maintenance(self):
        # Refresh buckets
        now = time.time()
        for bucket in self.routing_table.trie.values():
            if now - bucket.last_changed > 15 * 60:
                try:
                    await self.find_values(bucket.generate_id())
                except DHTError:
                    pass
                bucket.last_changed = now

    def token_maintenance(self):
        self.token_secrets.append(os.urandom(16))

        # Cleanup old tokens
        now = time.time()
        for node, (ts, _) in list(self.tokens.items()):
            if now > ts + TOKEN_EXPIRATION_TIME:
                self.tokens.pop(node, None)

    def generate_token(self, node):
        return hashlib.sha1(cast_to_bin(str(node)) + self.token_secrets[-1]).digest()

    def check_token(self, node, token):
        return any([hashlib.sha1(cast_to_bin(str(node)) + secret).digest() == token for secret in self.token_secrets])
