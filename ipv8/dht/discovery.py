import time
from binascii import hexlify
from collections import defaultdict

from . import DHTError
from .community import DHTCommunity, MAX_NODES_IN_FIND, PING_INTERVAL, Request, TARGET_NODES, gather_without_errors
from .payload import (ConnectPeerRequestPayload, ConnectPeerResponsePayload, PingRequestPayload, PingResponsePayload,
                      StorePeerRequestPayload, StorePeerResponsePayload)
from .routing import NODE_STATUS_BAD, Node
from ..lazy_community import lazy_wrapper, lazy_wrapper_wd
from ..messaging.payload_headers import GlobalTimeDistributionPayload

MSG_STORE_PEER_REQUEST = 13
MSG_STORE_PEER_RESPONSE = 14
MSG_CONNECT_PEER_REQUEST = 15
MSG_CONNECT_PEER_RESPONSE = 16


class DHTDiscoveryCommunity(DHTCommunity):
    """
    Community for discovering peers that are behind NAT.
    """

    def __init__(self, *args, **kwargs):
        super(DHTDiscoveryCommunity, self).__init__(*args, **kwargs)

        self.store = defaultdict(list)
        self.store_for_me = defaultdict(list)

        self.decode_map.update({
            chr(MSG_STORE_PEER_REQUEST): self.on_store_peer_request,
            chr(MSG_STORE_PEER_RESPONSE): self.on_store_peer_response,
            chr(MSG_CONNECT_PEER_REQUEST): self.on_connect_peer_request,
            chr(MSG_CONNECT_PEER_RESPONSE): self.on_connect_peer_response,
        })

        self.register_task('store_peer', self.store_peer, interval=30)
        self.register_task('ping_all', self.ping_all, interval=10)

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingRequestPayload)
    def on_ping_request(self, peer, dist, payload, data):
        super(DHTDiscoveryCommunity, self).on_ping_request(peer.address, data)
        node = self.find_node_in_dict(peer.key.key_to_bin(), self.store)
        if node:
            node.last_queries.append(time.time())

    @lazy_wrapper_wd(GlobalTimeDistributionPayload, PingResponsePayload)
    def on_ping_response(self, peer, dist, payload, data):
        super(DHTDiscoveryCommunity, self).on_ping_response(peer.address, data)
        node = self.find_node_in_dict(peer.key.key_to_bin(), self.store_for_me)
        if node:
            node.last_response = time.time()

    def find_node_in_dict(self, public_key_bin, node_dict):
        for _, nodes in node_dict.items():
            for node in nodes:
                if node.public_key.key_to_bin() == public_key_bin:
                    return node

    async def store_peer(self):
        key = self.my_peer.mid

        # Do we already have enough peers storing our address?
        if len(self.store_for_me[key]) >= TARGET_NODES // 2:
            return []

        try:
            nodes = await self.find_nodes(key)
            return await self.send_store_peer_request(key, nodes[:TARGET_NODES])
        except DHTError:
            return []

    async def send_store_peer_request(self, key, nodes):
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes if node not in self.store_for_me[key]]

        if not nodes:
            return DHTError('No nodes found for storing peer')

        futures = []
        for node in nodes:
            if node in self.tokens:
                cache = self.request_cache.add(Request(self, 'store-peer', node, [key]))
                futures.append(cache.future)
                self.send_message(node.address, MSG_STORE_PEER_REQUEST, StorePeerRequestPayload,
                                  (cache.number, self.tokens[node][1], key))
            else:
                self.logger.debug('Not sending store-peer-request to %s (no token available)', node)

        if not futures:
            raise DHTError('Peer was not stored')
        return await gather_without_errors(*futures)

    async def connect_peer(self, mid, peer=None):
        if mid in self.store:
            return self.store[mid]

        # If a peer is provided, we will first try to ping the peer (to see if it's connectable).
        # This could potentially save an expensive DHT lookup.
        if peer:
            node = Node(peer.key, peer.address)
            try:
                await self.ping(node)
            except DHTError:
                pass
            else:
                return [node]

        nodes = await self.find_nodes(mid)
        nodes = await self.send_connect_peer_request(mid, nodes[:TARGET_NODES])
        if not nodes:
            raise DHTError('Failed to connect peer')
        return nodes

    async def send_connect_peer_request(self, key, nodes):
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes]

        if not nodes:
            raise DHTError('No nodes found for connecting to peer')

        futures = []
        for node in nodes:
            cache = self.request_cache.add(Request(self, 'connect-peer', node))
            futures.append(cache.future)
            self.send_message(node.address, MSG_CONNECT_PEER_REQUEST,
                              ConnectPeerRequestPayload, (cache.number, self.my_estimated_lan, key))

        node_lists = await gather_without_errors(*futures)
        return list(set(sum(node_lists, [])))

    @lazy_wrapper(GlobalTimeDistributionPayload, StorePeerRequestPayload)
    def on_store_peer_request(self, peer, dist, payload):
        self.logger.debug('Got store-peer-request from %s', peer.address)

        node = Node(peer.key, peer.address)
        node.last_queries.append(time.time())

        if not self.check_token(node, payload.token):
            self.logger.warning('Bad token, dropping packet.')
            return
        if payload.target != peer.mid:
            self.logger.warning('Not allowed to store under key %s, dropping packet.', hexlify(payload.target))
            return

        if node not in self.store[payload.target]:
            self.logger.debug('Storing peer %s (key %s)', node, hexlify(payload.target))
            self.store[payload.target].append(node)

        self.send_message(node.address, MSG_STORE_PEER_RESPONSE,
                          StorePeerResponsePayload, (payload.identifier,))

    @lazy_wrapper(GlobalTimeDistributionPayload, StorePeerResponsePayload)
    def on_store_peer_response(self, peer, dist, payload):
        if not self.request_cache.has('store-peer', payload.identifier):
            self.logger.error('Got store-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got store-peer-response from %s', peer.address)

        cache = self.request_cache.pop('store-peer', payload.identifier)

        key = cache.params[0]
        if cache.node not in self.store_for_me[key]:
            self.logger.debug('Peer %s storing us (key %s)', cache.node, hexlify(key))
            self.store_for_me[key].append(cache.node)

        cache.future.set_result(cache.node)

    @lazy_wrapper(GlobalTimeDistributionPayload, ConnectPeerRequestPayload)
    def on_connect_peer_request(self, peer, dist, payload):
        self.logger.debug('Got connect-peer-request from %s', peer.address)

        nodes = self.store[payload.target][:MAX_NODES_IN_FIND]
        for node in nodes:
            packet = self.create_puncture_request(payload.lan_address, peer.address, payload.identifier)
            self.endpoint.send(node.address, packet)

        self.logger.debug('Returning peers %s (key %s)', nodes, hexlify(payload.target))
        self.send_message(peer.address, MSG_CONNECT_PEER_RESPONSE,
                          ConnectPeerResponsePayload, (payload.identifier, nodes))

    @lazy_wrapper(GlobalTimeDistributionPayload, ConnectPeerResponsePayload)
    def on_connect_peer_response(self, peer, dist, payload):
        if not self.request_cache.has('connect-peer', payload.identifier):
            self.logger.error('Got connect-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got connect-peer-response from %s', peer.address)
        cache = self.request_cache.pop('connect-peer', payload.identifier)
        cache.future.set_result(payload.nodes)

    def ping_all(self):
        now = time.time()
        for key, nodes in self.store_for_me.items():
            for index in range(len(nodes) - 1, -1, -1):
                node = nodes[index]
                if node.status == NODE_STATUS_BAD:
                    self.store_for_me[key].pop(index)
                    self.logger.debug('Deleting peer %s that stored us (key %s)', node, hexlify(key))
                elif node.last_ping_sent + PING_INTERVAL <= now:
                    self.ping(node)

        for key, nodes in self.store.items():
            for index in range(len(nodes) - 1, -1, -1):
                node = nodes[index]
                if now > node.last_query + 60:
                    self.logger.debug('Deleting peer %s (key %s)', node, hexlify(key))
                    self.store[key].pop(index)
