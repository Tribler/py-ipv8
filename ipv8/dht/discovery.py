from __future__ import annotations

import time
from binascii import hexlify
from collections import defaultdict
from typing import TYPE_CHECKING, Callable, List, cast

from ..lazy_community import lazy_wrapper, lazy_wrapper_wd
from ..types import Address
from . import DHTError
from .community import MAX_NODES_IN_FIND, PING_INTERVAL, TARGET_NODES, DHTCommunity, Request, gather_without_errors
from .payload import (
    ConnectPeerRequestPayload,
    ConnectPeerResponsePayload,
    PingRequestPayload,
    PingResponsePayload,
    StorePeerRequestPayload,
    StorePeerResponsePayload,
)
from .routing import NODE_STATUS_BAD, Node

if TYPE_CHECKING:
    from ..community import CommunitySettings
    from ..types import Peer


class DHTDiscoveryCommunity(DHTCommunity):
    """
    Community for discovering peers that are behind NAT.
    """

    def __init__(self, settings: CommunitySettings) -> None:
        """
        Create a new dht-based discovery community.
        """
        super().__init__(settings)

        self.store: dict[bytes, list[Node]]  = defaultdict(list)
        self.store_for_me: dict[bytes, list[Node]] = defaultdict(list)

        self.add_message_handler(StorePeerRequestPayload, self.on_store_peer_request)
        self.add_message_handler(StorePeerResponsePayload, self.on_store_peer_response)
        self.add_message_handler(ConnectPeerRequestPayload, self.on_connect_peer_request)
        self.add_message_handler(ConnectPeerResponsePayload, self.on_connect_peer_response)

        self.register_task('store_peer', self.store_peer, interval=30)
        self.register_task('ping_all', self.ping_all, interval=10)

    @lazy_wrapper_wd(PingRequestPayload)
    def on_ping_request(self, peer: Peer, payload: PingRequestPayload, data: bytes) -> None:
        """
        When a ping comes in and we store it, update its metrics.
        """
        cast(Callable[[Address, bytes], None], super().on_ping_request)(peer.address, data)
        node = self.find_node_in_dict(peer.key.key_to_bin(), self.store)
        if node:
            node.last_queries.append(time.time())

    @lazy_wrapper_wd(PingResponsePayload)
    def on_ping_response(self, peer: Peer, payload: PingResponsePayload, data: bytes) -> None:
        """
        When a ping response comes in and we store it, update its metrics.
        """
        cast(Callable[[Address, bytes], None], super().on_ping_response)(peer.address, data)
        node = self.find_node_in_dict(peer.key.key_to_bin(), self.store_for_me)
        if node:
            node.last_response = time.time()

    def find_node_in_dict(self, public_key_bin: bytes, node_dict: dict[bytes, list[Node]]) -> Node | None:
        """
        Get the Node instance belonging to the public key in the given dictionary.
        """
        for nodes in node_dict.values():
            for node in nodes:
                if node.public_key.key_to_bin() == public_key_bin:
                    return node
        return None

    async def store_peer(self) -> list[Node]:
        """
        Store ourselves.
        """
        key = self.my_peer.mid

        # Do we already have enough peers storing our address?
        if len(self.store_for_me[key]) >= TARGET_NODES // 2:
            return []

        try:
            nodes = cast(List[Node], await self.find_nodes(key))
            return await self.send_store_peer_request(key, nodes[:TARGET_NODES])
        except DHTError:
            return []

    async def send_store_peer_request(self, key: bytes, nodes: list[Node]) -> list[Node]:
        """
        Send a request for storage to the given nodes.
        """
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes if node not in self.store_for_me[key]]

        if not nodes:
            msg = "No nodes found for storing peer"
            raise DHTError(msg)

        futures = []
        for node in nodes:
            if node.id in self.tokens:
                cache = Request(self, 'store-peer', node, [key])
                self.request_cache.add(cache)
                futures.append(cache.future)
                self.ez_send(node, StorePeerRequestPayload(cache.number, self.tokens[node.id][1], key))
            else:
                self.logger.debug('Not sending store-peer-request to %s (no token available)', node)

        if not futures:
            msg = "Peer was not stored"
            raise DHTError(msg)
        return await gather_without_errors(*futures)

    async def connect_peer(self, mid: bytes, peer: Peer | None = None) -> list[Node]:
        """
        Attempt to connect to a peer with the given mid, at first without a DHT lookup.
        """
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

        nodes = cast(List[Node], await self.find_nodes(mid))
        nodes = await self.send_connect_peer_request(mid, nodes[:TARGET_NODES])
        if not nodes:
            msg = "Failed to connect peer"
            raise DHTError(msg)
        return nodes

    async def send_connect_peer_request(self, key: bytes, nodes: list[Node]) -> list[Node]:
        """
        Send a request for connection to the given nodes.
        """
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes]

        if not nodes:
            msg = "No nodes found for connecting to peer"
            raise DHTError(msg)

        futures = []
        for node in nodes:
            cache = Request(self, 'connect-peer', node)
            self.request_cache.add(cache)
            futures.append(cache.future)
            self.ez_send(node, ConnectPeerRequestPayload(cache.number, self.my_estimated_lan, key))

        node_lists = await gather_without_errors(*futures)
        return list(set(sum(node_lists, [])))

    @lazy_wrapper(StorePeerRequestPayload)
    def on_store_peer_request(self, peer: Peer, payload: StorePeerRequestPayload) -> None:
        """
        When we receive a request to store a peer, attempt to add it.
        """
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

        self.ez_send(node, StorePeerResponsePayload(payload.identifier))

    @lazy_wrapper(StorePeerResponsePayload)
    def on_store_peer_response(self, peer: Peer, payload: StorePeerResponsePayload) -> None:
        """
        When a peer signals storage is complete, pop it from our cache.
        """
        if not self.request_cache.has('store-peer', payload.identifier):
            self.logger.warning('Got store-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got store-peer-response from %s', peer.address)

        cache = cast(Request, self.request_cache.pop('store-peer', payload.identifier))

        key = cast(List[bytes], cache.params)[0]
        if cache.node not in self.store_for_me[key]:
            self.logger.debug('Peer %s storing us (key %s)', cache.node, hexlify(key))
            self.store_for_me[key].append(cache.node)

        cache.future.set_result(cache.node)

    @lazy_wrapper(ConnectPeerRequestPayload)
    def on_connect_peer_request(self, peer: Peer, payload: ConnectPeerRequestPayload) -> None:
        """
        When a peer wants to connect to another peer, try to puncture the requested "other" peer.
        """
        self.logger.debug('Got connect-peer-request from %s', peer.address)

        nodes = self.store[payload.target][:MAX_NODES_IN_FIND]
        for node in nodes:
            packet = self.create_puncture_request(payload.lan_address, peer.address, payload.identifier)
            self.endpoint.send(node.address, packet)

        self.logger.debug('Returning peers %s (key %s)', nodes, hexlify(payload.target))
        self.ez_send(peer, ConnectPeerResponsePayload(payload.identifier, nodes))

    @lazy_wrapper(ConnectPeerResponsePayload)
    def on_connect_peer_response(self, peer: Peer, payload: ConnectPeerResponsePayload) -> None:
        """
        Handle responses of peers that performed punctures for us.
        """
        if not self.request_cache.has('connect-peer', payload.identifier):
            self.logger.warning('Got connect-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got connect-peer-response from %s', peer.address)
        cache = cast(Request, self.request_cache.pop('connect-peer', payload.identifier))
        cache.future.set_result(payload.nodes)

    def ping_all(self) -> None:
        """
        Send a ping to all known nodes.
        """
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
