from __future__ import absolute_import
from __future__ import division

from binascii import hexlify, unhexlify
import os
import time
import hashlib

from collections import deque, defaultdict

from twisted.internet.defer import inlineCallbacks, Deferred, fail, DeferredList, returnValue
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure

from ..peer import Peer
from ..requestcache import RandomNumberCache, RequestCache
from ..deprecated.payload_headers import BinMemberAuthenticationPayload
from ..deprecated.payload_headers import GlobalTimeDistributionPayload
from ..deprecated.community import Community
from ..deprecated.lazy_community import lazy_wrapper, lazy_wrapper_wd

from .storage import Storage
from .routing import RoutingTable, Node, distance, calc_node_id
from .payload import PingRequestPayload, PingResponsePayload, StoreRequestPayload, \
                     StoreResponsePayload, FindRequestPayload, FindResponsePayload, \
                     SignedStrPayload, StrPayload
from ..util import cast_to_bin

PING_INTERVAL = 25

DHT_ENTRY_STR = 0
DHT_ENTRY_STR_SIGNED = 1

MAX_ENTRY_SIZE = 155
MAX_ENTRY_AGE = 86400

MAX_FIND_WALKS = 8
MAX_FIND_STEPS = 4

MAX_VALUES_IN_STORE = 9
MAX_VALUES_IN_FIND = 9
MAX_NODES_IN_FIND = 8

# Target number of nodes at which a key-value pair should be stored
TARGET_NODES = 8

MSG_PING = 7
MSG_PONG = 8
MSG_STORE_REQUEST = 9
MSG_STORE_RESPONSE = 10
MSG_FIND_REQUEST = 11
MSG_FIND_RESPONSE = 12


def gatherResponses(deferreds, **kwargs):
    def on_finished(results):
        return [x[1] for x in results if x[0]]
    return DeferredList(deferreds, **kwargs).addCallback(on_finished)


class Request(RandomNumberCache):
    """
    This request cache keeps track of all outstanding requests within the DHTCommunity.
    """
    def __init__(self, community, node, params=None, consume_errors=False):
        super(Request, self).__init__(community.request_cache, u'request')
        self.node = node
        self.params = params
        self.deferred = Deferred()
        self.start_time = time.time()
        self.consume_errors = consume_errors

    @property
    def timeout_delay(self):
        return 5.0

    def on_timeout(self):
        if not self.deferred.called:
            self._logger.warning('Request to %s timed out', self.node)
            self.node.failed += 1
            if not self.consume_errors:
                self.deferred.errback(Failure(RuntimeError('Node %s timeout' % self.node)))

    def on_complete(self):
        self.node.last_response = time.time()
        self.node.failed = 0
        self.node.rtt = time.time() - self.start_time


class DHTCommunity(Community):
    """
    Community for storing/finding key-value pairs.
    """
    master_peer = Peer(unhexlify('3081a7301006072a8648ce3d020106052b81040027038192000402b8dcc3bee358ff30b3bd00aa56a7f'
                                 '9100fe546fc7fb518f197f7c1bbadeb817d8e7a0dcc44c239cfc8906cf55781235dfe24179d0450bcdb'
                                 'dc49e851f3b03b12acbf0e7b0823e606e50e9c0c77a97af7e737ad749ff53c42fd9d636da4e71d3b7a7'
                                 'a291734fd64304be90c86e2268490332dfa9e8f01d953538f01c2fba73acd7fe7eec480098054610855'
                                 'b7918974'))

    def __init__(self, *args, **kwargs):
        super(DHTCommunity, self).__init__(*args, **kwargs)
        self.routing_table = RoutingTable(self.my_node_id)
        self.storage = Storage()
        self.request_cache = RequestCache()
        self.tokens = {}
        self.token_secrets = deque(maxlen=2)
        self.register_task('ping_all', LoopingCall(self.ping_all)).start(10, now=False)
        self.register_task('value_maintenance', LoopingCall(self.value_maintenance)).start(3600, now=False)
        self.register_task('token_maintenance', LoopingCall(self.token_maintenance)).start(300, now=True)

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

    def unload(self):
        self.request_cache.shutdown()
        super(DHTCommunity, self).unload()

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
            self.logger.warning('Too many queries\'s, dropping packet')
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
                self.ping(rt_node).addErrback(lambda _: None)

    def ping_all(self):
        self.routing_table.remove_bad_nodes()

        pinged = []
        now = time.time()
        for bucket in self.routing_table.trie.values():
            for node in bucket.nodes.values():
                if node.last_response + PING_INTERVAL <= now:
                    self.ping(node).addErrback(lambda _: None)
                    pinged.append(node)
        return pinged

    def ping(self, node):
        self.logger.debug('Pinging node %s', node)

        cache = self.request_cache.add(Request(self, node))
        self.send_message(node.address, MSG_PING, PingRequestPayload, (cache.number,))
        return cache.deferred

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingRequestPayload)
    def on_ping_request(self, peer, dist, payload, data):
        self.logger.debug('Got ping-request from %s', peer.address)

        node = self.get_requesting_node(peer)
        if not node:
            return

        self.send_message(peer.address, MSG_PONG, PingResponsePayload, (payload.identifier,))

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingResponsePayload)
    def on_ping_response(self, peer, dist, payload, data):
        if not self.request_cache.has(u'request', payload.identifier):
            self.logger.error('Got ping-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got ping-response from %s', peer.address)
        cache = self.request_cache.pop(u'request', payload.identifier)
        cache.on_complete()
        cache.deferred.callback(cache.node)

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

    def store_value(self, key, data, sign=False):
        value = self.serialize_value(data, sign=sign)
        return self._store(key, value)

    def _store(self, key, value):
        if len(value) > MAX_ENTRY_SIZE:
            return fail(Failure(RuntimeError('Maximum length exceeded')))

        return self.find_nodes(key).addCallback(lambda nodes, k=key, v=value:
                                                self.store_on_nodes(k, [v], nodes[:TARGET_NODES]))

    def store_on_nodes(self, key, values, nodes):
        if not nodes:
            return fail(Failure(RuntimeError('No nodes found for storing the key-value pairs')))

        values = values[:MAX_VALUES_IN_STORE]

        # Check if we also need to store this key-value pair
        largest_distance = max([distance(node.id, key) for node in nodes])
        if distance(self.my_node_id, key) < largest_distance:
            for value in values:
                self.add_value(key, value)

        deferreds = []
        for node in nodes:
            if node in self.tokens:
                cache = self.request_cache.add(Request(self, node))
                deferreds.append(cache.deferred)
                self.send_message(node.address, MSG_STORE_REQUEST, StoreRequestPayload,
                                  (cache.number, self.tokens[node][1], key, values))
            else:
                self.logger.debug('Not sending store-request to %s (no token available)', node)

        return gatherResponses(deferreds, consumeErrors=True) \
               if deferreds else fail(RuntimeError('Value was not stored'))

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
        if not self.request_cache.has(u'request', payload.identifier):
            self.logger.error('Got store-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got store-response from %s', peer.address)
        cache = self.request_cache.pop(u'request', payload.identifier)
        cache.on_complete()
        cache.deferred.callback(cache.node)

    def _send_find_request(self, node, target, force_nodes):
        cache = self.request_cache.add(Request(self, node, [force_nodes]))
        self.send_message(node.address, MSG_FIND_REQUEST, FindRequestPayload,
                          (cache.number, self.my_estimated_lan, target, force_nodes))
        return cache.deferred

    def _process_find_responses(self, responses, nodes_tried):
        values = set()
        nodes = set()
        to_puncture = {}

        for sender, response in responses:
            if 'values' in response:
                values |= set(response['values'])
            else:
                # Pick a node that we haven't tried yet.
                node = next((n for n in response['nodes']
                             if n not in nodes_tried and n not in list(to_puncture.values())), None)

                if node:
                    nodes.add(node)

                    # If we picked any node other than the first one, we will need to puncture.
                    if node != response['nodes'][0]:
                        to_puncture[sender] = node

        return values, nodes, to_puncture

    @inlineCallbacks
    def _find(self, target, force_nodes=False):
        nodes_closest = set(self.routing_table.closest_nodes(target, max_nodes=MAX_FIND_WALKS))
        if not nodes_closest:
            returnValue(Failure(RuntimeError('No nodes found in the routing table')))

        nodes_tried = set()
        values = set()
        recent = None

        for _ in range(MAX_FIND_STEPS):
            if not nodes_closest:
                break

            # Send closest nodes a find-node-request
            deferreds = [self._send_find_request(node, target, force_nodes) for node in nodes_closest]
            responses = yield gatherResponses(deferreds, consumeErrors=True)
            recent = next((sender for sender, response in responses if 'nodes' in response), recent)

            nodes_tried |= nodes_closest
            nodes_closest.clear()

            # Process responses and puncture nodes that we haven't tried yet
            new_values, new_nodes, to_puncture = self._process_find_responses(responses, nodes_tried)
            values |= new_values
            nodes_closest |= new_nodes

            deferreds = [self._send_find_request(sender, node.id, force_nodes)
                         for sender, node in to_puncture.items()]

            # Wait for punctures (if any)...
            yield DeferredList(deferreds, consumeErrors=True)

            # Ensure we haven't tried these nodes yet
            nodes_closest -= nodes_tried

        if force_nodes:
            returnValue(sorted(nodes_tried, key=lambda n: distance(n.id, target)))

        values = list(values)

        if recent and values:
            # Store the key-value pair on the most recently visited node that
            # did not have it (for caching purposes).
            self.store_on_nodes(target, values, [recent])

        returnValue(self.post_process_values(values))

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

    def find_values(self, target):
        return self._find(target, force_nodes=False)

    def find_nodes(self, target):
        return self._find(target, force_nodes=True)

    @lazy_wrapper(GlobalTimeDistributionPayload, FindRequestPayload)
    def on_find_request(self, peer, dist, payload):
        self.logger.debug('Got find-request for %s from %s', hexlify(payload.target), peer.address)

        node = self.get_requesting_node(peer)
        if not node:
            return

        nodes = []
        values = self.storage.get(payload.target, limit=MAX_VALUES_IN_FIND) if not payload.force_nodes else []

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
        if not self.request_cache.has(u'request', payload.identifier):
            self.logger.error('Got find-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got find-response from %s', peer.address)
        cache = self.request_cache.pop(u'request', payload.identifier)
        cache.on_complete()

        self.tokens[cache.node] = (time.time(), payload.token)

        if cache.deferred.called:
            # The errback must already have been called (due to a timeout)
            return
        elif cache.params[0]:
            cache.deferred.callback((cache.node, {'nodes': payload.nodes}))
        else:
            cache.deferred.callback((cache.node, {'values': payload.values} if payload.values else \
                                                 {'nodes': payload.nodes}))

    def value_maintenance(self):
        # Refresh buckets
        now = time.time()
        for bucket in self.routing_table.trie.values():
            if now - bucket.last_changed > 15 * 60:
                self.find_values(bucket.generate_id()).addErrback(lambda _: None)
                bucket.last_changed = now

        # Replicate keys older than one hour
        for key, value in self.storage.items_older_than(3600):
            self._store(key, value).addErrback(lambda _: None)

        # Also republish our own key-value pairs every 24h?

    def token_maintenance(self):
        self.token_secrets.append(os.urandom(16))

        # Cleanup old tokens
        now = time.time()
        for node, (ts, _) in self.tokens.items():
            if now > ts + 600:
                self.tokens.pop(node, None)

    def generate_token(self, node):
        return hashlib.sha1(cast_to_bin(str(node)) + self.token_secrets[-1]).digest()

    def check_token(self, node, token):
        return any([hashlib.sha1(cast_to_bin(str(node)) + secret).digest() == token for secret in self.token_secrets])
