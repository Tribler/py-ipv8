from __future__ import absolute_import

from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from hashlib import sha1
import json

from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web import http, resource
from twisted.web.server import NOT_DONE_YET

from ..dht.community import DHTCommunity, MAX_ENTRY_SIZE
from ..attestation.trustchain.community import TrustChainCommunity
from ..dht.discovery import DHTDiscoveryCommunity
from ..attestation.trustchain.listener import BlockListener
from ..attestation.trustchain.payload import DHTBlockPayload
from ..messaging.serialization import Serializer
from ..keyvault.public.libnaclkey import LibNaCLPK


class DHTEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)

        dht_overlays = [overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)]
        tc_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if dht_overlays:
            self.putChild(b"statistics", DHTStatisticsEndpoint(dht_overlays[0]))
            self.putChild(b"values", DHTValuesEndpoint(dht_overlays[0]))
            self.putChild(b"peers", DHTPeersEndpoint(dht_overlays[0]))
            self.putChild(b"block", DHTBlockEndpoint(dht_overlays[0], tc_overlays[0]))


class DHTBlockEndpoint(resource.Resource, BlockListener):
    """
    This endpoint is responsible for returning the latest Trustchain block of a peer. Additionally, it ensures
    this peer's latest TC block is available
    """

    def received_block(self, block):
        """
        Wrapper callback method, inherited from the BlockListener abstract class, which will publish the latest
        TrustChain block to the DHT

        :param block: the latest block added to the Database. This is not actually used by the inner method
        :return: None
        """
        self.publish_latest_block()

    def should_sign(self, block):
        pass

    KEY_SUFFIX = b'_BLOCK'
    CHUNK_SIZE = MAX_ENTRY_SIZE - DHTBlockPayload.PREAMBLE_OVERHEAD - 1

    def __init__(self, dht, trustchain):
        resource.Resource.__init__(self)
        self.dht = dht
        self.trustchain = trustchain
        self.block_version = 0
        self.serializer = Serializer()

        self._hashed_dht_key = sha1(self.trustchain.my_peer.public_key.key_to_bin() + self.KEY_SUFFIX).digest()

        trustchain.add_listener(self, [trustchain.UNIVERSAL_BLOCK_LISTENER])

    def reconstruct_all_blocks(self, block_chunks, public_key):
        """
        Given a list of block chunks, reconstruct all the blocks in a dictionary indexed by their version

        :param block_chunks: the list of block chunks
        :param public_key: the public key of the publishing node, which will be used for verifying the chunks
        :return: a dictionary of reconstructed blocks (in packed format), indexed by the version of the blocks,
                 and the maximal version
        """
        new_blocks = {}
        max_version = 0

        for entry in block_chunks:
            package = self.serializer.unpack_to_serializables([DHTBlockPayload, ], entry[1:])[0]

            if public_key.verify(package.signature, str(package.version).encode('utf-8') + package.payload):
                max_version = max_version if max_version > package.version else package.version

                new_blocks[package.version] = package.payload + new_blocks[package.version] \
                    if package.version in new_blocks else package.payload

        return new_blocks, max_version

    def _is_duplicate(self, latest_block, public_key):
        """
        Checks to see if this block has already been published to the DHT

        :param latest_block: the PACKED version of the latest block
        :param public_key: the public key of the publishing node, which will be used for verifying the chunks
        :return: True if the block has indeed been published before, False otherwise
        """
        block_chunks = self.dht.storage.get(self._hashed_dht_key)
        new_blocks, _ = self.reconstruct_all_blocks(block_chunks, public_key)

        for val in new_blocks.values():
            if val == latest_block:
                return True

        return False

    @inlineCallbacks
    def publish_latest_block(self):
        """
        Publish the latest block of this node's TrustChain to the DHT
        """
        latest_block = self.trustchain.persistence.get_latest(self.trustchain.my_peer.public_key.key_to_bin())

        if latest_block:
            # Get all the previously published blocks for this peer from the DHT, and check if this is a duplicate
            latest_block = latest_block.pack()
            if self._is_duplicate(latest_block, self.trustchain.my_peer.public_key):
                returnValue(None)

            my_private_key = self.trustchain.my_peer.key

            for i in range(0, len(latest_block), self.CHUNK_SIZE):
                chunk = latest_block[i: i + self.CHUNK_SIZE]
                signature = my_private_key.signature(str(self.block_version).encode('utf-8') + chunk)
                blob_chunk = self.serializer.pack_multiple(
                    DHTBlockPayload(signature, self.block_version, chunk).to_pack_list())

                yield self.dht.store_value(self._hashed_dht_key, blob_chunk[0])

            self.block_version += 1

    def render_GET(self, request):
        """
        Return the latest TC block of a peer, as identified in the request

        :param request: the request for retrieving the latest TC block of a peer. It must contain the peer's
        public key of the peer
        :return: the latest block of the peer, if found
        """
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"}).encode('utf-8')

        if not request.args or b'public_key' not in request.args:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"error": "Must specify the peer's public key"}).encode('utf-8')

        raw_public_key = b64decode(request.args[b'public_key'][0])
        hash_key = sha1(raw_public_key + self.KEY_SUFFIX).digest()
        block_chunks = self.dht.storage.get(hash_key)

        if not block_chunks:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "Could not find a block for the specified key."}).encode('utf-8')

        target_public_key = LibNaCLPK(binarykey=raw_public_key[10:])
        new_blocks, max_version = self.reconstruct_all_blocks(block_chunks, target_public_key)

        return json.dumps({"block": b64encode(new_blocks[max_version]).decode('utf-8')}).encode('utf-8')


class DHTStatisticsEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning statistics about the DHT.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        buckets = self.dht.routing_table.trie.values()
        stats = {"node_id": hexlify(self.dht.my_node_id),
                 "peer_id": hexlify(self.dht.my_peer.mid),
                 "routing_table_size": sum([len(bucket.nodes) for bucket in buckets]),
                 "routing_table_buckets": len(buckets),
                 "num_keys_in_store": len(self.dht.storage.items),
                 "num_tokens": len(self.dht.tokens)}

        if isinstance(self.dht, DHTDiscoveryCommunity):
            stats.update({
                "num_peers_in_store": {hexlify(key): len(peers) for key, peers in self.dht.store.items()},
                "num_store_for_me": {hexlify(key): len(peers) for key, peers in self.dht.store_for_me.items()}
            })

        return json.dumps({"statistics": stats})


class DHTPeersEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT peers.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTPeerEndpoint(self.dht, path)


class SpecificDHTPeerEndpoint(resource.Resource):
    """
    This class handles requests for a specific DHT peer.
    """

    def __init__(self, dht, key):
        resource.Resource.__init__(self)
        self.mid = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(nodes):
            node_dicts = []
            for node in nodes:
                node_dicts.append({'public_key': b64encode(node.public_key.key_to_bin()),
                                   'address': node.address})
            request.write(json.dumps({"peers": node_dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        deferred = self.dht.connect_peer(self.mid)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET


class DHTValuesEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT values.
    """

    def __init__(self, dht):
        resource.Resource.__init__(self)
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTValueEndpoint(self.dht, path)


class SpecificDHTValueEndpoint(resource.Resource):
    """
    This class handles requests for a specific DHT value.
    """

    def __init__(self, dht, key):
        resource.Resource.__init__(self)
        self.key = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(values):
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({'public_key': b64encode(public_key) if public_key else None,
                              'value': hexlify(data)})
            request.write(json.dumps({"values": dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        deferred = self.dht.find_values(self.key)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET

    def render_PUT(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(values):
            request.write(json.dumps({"stored": True}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(json.dumps({
                u"error": {
                    u"handled": True,
                    u"code": failure.value.__class__.__name__,
                    u"message": failure.value.message
                }
            }))

        parameters = http.parse_qs(request.content.read(), 1)
        if 'value' not in parameters:
            request.setResponseCode(http.BAD_REQUEST)
            return json.dumps({"error": "incorrect parameters"})

        deferred = self.dht.store_value(self.key, unhexlify(parameters['value'][0]), sign=True)
        deferred.addCallback(on_success)
        deferred.addErrback(on_failure)

        return NOT_DONE_YET
