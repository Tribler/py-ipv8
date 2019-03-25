from __future__ import absolute_import
from __future__ import division

import time
from binascii import hexlify
from collections import defaultdict

from six.moves import xrange

from twisted.internet.defer import fail, succeed
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure

from .community import DHTCommunity, MAX_NODES_IN_FIND, PING_INTERVAL, Request, TARGET_NODES, gatherResponses
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

        self.register_task('store_peer', LoopingCall(self.store_peer)).start(30, now=False)

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

    def store_peer(self):
        # Do we already have enough peers storing our address?
        if len(self.store_for_me) >= TARGET_NODES // 2:
            return

        key = self.my_peer.mid
        return self.find_nodes(key).addCallback(lambda nodes: self.send_store_peer_request(key, nodes[:TARGET_NODES])) \
                                   .addErrback(lambda _: None)

    def send_store_peer_request(self, key, nodes):
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes if node not in self.store_for_me[key]]

        if not nodes:
            return fail(Failure(RuntimeError('No nodes found for storing peer')))

        deferreds = []
        for node in nodes:
            if node in self.tokens:
                cache = self.request_cache.add(Request(self, u'store-peer', node, [key]))
                deferreds.append(cache.deferred)
                self.send_message(node.address, MSG_STORE_PEER_REQUEST, StorePeerRequestPayload,
                                  (cache.number, self.tokens[node][1], key))
            else:
                self.logger.debug('Not sending store-peer-request to %s (no token available)', node)

        return (gatherResponses(deferreds, consumeErrors=True) if deferreds
                else fail(RuntimeError('Peer was not stored')))

    def connect_peer(self, mid):
        if mid in self.store:
            return succeed(self.store[mid])
        return self.find_nodes(mid).addCallback(lambda nodes, mid=mid:
                                                self.send_connect_peer_request(mid, nodes[:TARGET_NODES]))

    def send_connect_peer_request(self, key, nodes):
        # Create new objects to avoid problem with the nodes also being in the routing table
        nodes = [Node(node.key, node.address) for node in nodes]

        if not nodes:
            return fail(Failure(RuntimeError('No nodes found for connecting to peer')))

        deferreds = []
        for node in nodes:
            cache = self.request_cache.add(Request(self, u'connect-peer', node))
            deferreds.append(cache.deferred)
            self.send_message(node.address, MSG_CONNECT_PEER_REQUEST,
                              ConnectPeerRequestPayload, (cache.number, self.my_estimated_lan, key))

        return gatherResponses(deferreds, consumeErrors=True).addCallback(lambda node_lists:
                                                                          list(set(sum(node_lists, []))))

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
        if not self.request_cache.has(u'store-peer', payload.identifier):
            self.logger.error('Got store-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got store-peer-response from %s', peer.address)

        cache = self.request_cache.pop(u'store-peer', payload.identifier)

        key = cache.params[0]
        if cache.node not in self.store_for_me[key]:
            self.logger.debug('Peer %s storing us (key %s)', cache.node, hexlify(key))
            self.store_for_me[key].append(cache.node)

        cache.deferred.callback(cache.node)

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
        if not self.request_cache.has(u'connect-peer', payload.identifier):
            self.logger.error('Got connect-peer-response with unknown identifier, dropping packet')
            return

        self.logger.debug('Got connect-peer-response from %s', peer.address)
        cache = self.request_cache.pop(u'connect-peer', payload.identifier)
        cache.deferred.callback(payload.nodes)

    def ping_all(self):
        pinged = self.get_available_strategies()['PingChurn'](self).take_step()

        now = time.time()
        for key, nodes in self.store_for_me.items():
            for index in xrange(len(nodes) - 1, -1, -1):
                node = nodes[index]
                if node.status == NODE_STATUS_BAD:
                    del self.store_for_me[key][index]
                    self.logger.debug('Deleting peer %s that stored us (key %s)', node, hexlify(key))
                elif node not in pinged and now > node.last_response + PING_INTERVAL:
                    self.ping(node).addErrback(lambda _: None)

        for key, nodes in self.store.items():
            for index in xrange(len(nodes) - 1, -1, -1):
                node = nodes[index]
                if now > node.last_query + 60:
                    self.logger.debug('Deleting peer %s (key %s)', node, hexlify(key))
                    del self.store[key][index]
