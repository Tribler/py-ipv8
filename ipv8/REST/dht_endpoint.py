from __future__ import absolute_import

import logging
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
from hashlib import sha1

from twisted.internet import reactor
from twisted.internet.task import LoopingCall, deferLater
from twisted.web import http
from twisted.web.server import NOT_DONE_YET

from .base_endpoint import BaseEndpoint
from ..attestation.trustchain.community import TrustChainCommunity
from ..attestation.trustchain.listener import BlockListener
from ..attestation.trustchain.payload import DHTBlockPayload
from ..dht.community import DHTCommunity, MAX_ENTRY_SIZE, MAX_VALUES_IN_FIND
from ..dht.discovery import DHTDiscoveryCommunity
from ..keyvault.public.libnaclkey import LibNaCLPK
from ..messaging.serialization import PackError, Serializer

# The period of the block maintenance looping call
BLOCK_REFRESH_PERIOD = 60 * 60  # 1 hour


class DHTEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        super(DHTEndpoint, self).__init__()
        dht_overlays = [overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)]
        tc_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TrustChainCommunity)]
        if dht_overlays:
            self.putChild(b"statistics", DHTStatisticsEndpoint(dht_overlays[0]))
            self.putChild(b"values", DHTValuesEndpoint(dht_overlays[0]))
            self.putChild(b"peers", DHTPeersEndpoint(dht_overlays[0]))
        if dht_overlays and tc_overlays:
            self.putChild(b"block", DHTBlockEndpoint(dht_overlays[0], tc_overlays[0]))


class DHTBlockEndpoint(BaseEndpoint, BlockListener):
    """
    This endpoint is responsible for returning the latest Trustchain block of a peer. Additionally, it ensures
    this peer's latest TC block is available
    """

    KEY_SUFFIX = b'_BLOCK'
    CHUNK_SIZE = MAX_ENTRY_SIZE - DHTBlockPayload.PREAMBLE_OVERHEAD - 1
    ATTEMPT_LIMIT = 3

    def received_block(self, block):
        """
        Wrapper callback method, inherited from the BlockListener abstract class, which will publish the latest
        TrustChain block to the DHT

        :param block: the latest block added to the Database. This is not actually used by the inner method
        """
        # Check if the block is not null, and if it belongs to this peer
        if block and block.public_key == self.trustchain.my_peer.public_key.key_to_bin():
            deferLater(reactor, 0, self.publish_block, block)

    def should_sign(self, block):
        pass

    def __init__(self, dht, trustchain):
        super(DHTBlockEndpoint, self).__init__()
        self.dht = dht
        self.trustchain = trustchain
        self.block_version = 0
        self.serializer = Serializer()

        self._hashed_dht_key = sha1(self.trustchain.my_peer.public_key.key_to_bin() + self.KEY_SUFFIX).digest()

        # Register a LoopingCall, get it's deferred, and start it.
        self.block_maintenance_task = self.trustchain.register_task('block_maintenance', LoopingCall(
            self.publish_latest_block))
        self.block_maintenance_task.start(BLOCK_REFRESH_PERIOD, now=False)

        trustchain.add_listener(self, [trustchain.UNIVERSAL_BLOCK_LISTENER])

    def publish_latest_block(self):
        """
        Republish the latest TrustChain block under this peer's key
        """
        block = self.trustchain.persistence.get_latest(self.trustchain.my_peer.public_key.key_to_bin())
        if block:
            self.publish_block(block, republish=True)

    def reconstruct_all_blocks(self, new_chunks, public_key, chunk_dict=None, counts=None):
        """
        Given a list of block chunks, reconstruct all the blocks in a dictionary indexed by their version

        :param new_chunks: the list of block chunks
        :param public_key: the public key of the publishing node, which will be used for verifying the chunks
        :param chunk_dict: a dictionary containing previously (partially) built blocks, or None
        :param counts: a dictionary from block version to the number of missing chunks
        :return: a dictionary from block version to a list of block chunks, the maximum block version,
                 a dictionary from version to count (where the count represents the number of missing chunks)
        """
        assert (chunk_dict and counts) or (not chunk_dict and not counts), "Must either provide both new_blocks " \
                                                                           "and counter dicts or None for both"

        if not chunk_dict:
            chunk_dict = {}

        if not counts:
            counts = {}

        max_version = 0

        for entry in new_chunks:
            try:
                package = self.serializer.unpack_to_serializables([DHTBlockPayload, ], entry)[0]

                pre_signed_content = self.serializer.pack_multiple([('H', package.version),
                                                                    ('H', package.block_position),
                                                                    ('H', package.block_count),
                                                                    ('raw', package.payload)])[0]

                if public_key.verify(package.signature, pre_signed_content):
                    max_version = max(max_version, package.version)

                    if package.version not in chunk_dict:
                        chunk_dict[package.version] = [b''] * package.block_count
                        counts[package.version] = package.block_count

                    chunk_dict[package.version][package.block_position] = package.payload
                    counts[package.version] -= 1
            except PackError:
                logging.error("PackError: Found a clandestine entry in the DHT when reconstructing TC blocks: %s",
                              entry)

        return chunk_dict, max_version, counts

    def publish_block(self, block, republish=False):
        """
        Publishes a block to the DHT, by splitting it in chunks.

        :param block: the block to be published to the DHT
        :param republish: boolean which indicates whether the published block has already been published again
        """
        if block:
            latest_block = block.pack()

            # Get the total number of chunks in this blocks
            total_chunks = len(latest_block) // self.CHUNK_SIZE
            total_chunks += 1 if len(latest_block) % self.CHUNK_SIZE != 0 else 0

            # The actual version of the block may vary based on whether the block is being published or republished
            actual_version = max(self.block_version if not republish else (self.block_version - 1), 0)

            def publish_chunk(_, slice_pointer, chunk_idx, chunk_attempt=1):
                # If we've reached the end of the block, we stop the chain, and increment the block version
                if chunk_idx >= total_chunks:
                    if not republish:
                        self.block_maintenance_task.reset()
                        self.block_version += 1
                    return

                # If we've attempted to publish this block more times than allowed, give up on the chunk and the block
                if chunk_attempt > self.ATTEMPT_LIMIT:
                    logging.error("Publishing latest block failed after %d attempts on chunk %d", self.ATTEMPT_LIMIT,
                                  chunk_idx)
                    return

                # Prepare and pack the chunk for publishing to the DHT
                my_private_key = self.trustchain.my_peer.key
                chunk = latest_block[slice_pointer: slice_pointer + self.CHUNK_SIZE]

                pre_signed_content = self.serializer.pack_multiple([('H', actual_version), ('H', chunk_idx),
                                                                    ('H', total_chunks), ('raw', chunk)])[0]

                signature = my_private_key.signature(pre_signed_content)
                blob_chunk = self.serializer.pack_multiple(
                    DHTBlockPayload(signature, actual_version, chunk_idx, total_chunks, chunk).to_pack_list())

                # Try to add the current chunk to the DHT; if it works, move to the next, otherwise retry
                d = self.dht.store_value(self._hashed_dht_key, blob_chunk[0])
                d.addCallback(publish_chunk, slice_pointer + self.CHUNK_SIZE, chunk_idx + 1, 1)
                d.addErrback(publish_chunk, slice_pointer, chunk_idx, chunk_attempt + 1)

            # On the off chance that the block is actually empty, avoid publishing it
            if total_chunks > 0:
                deferLater(reactor, 0, publish_chunk, None, 0, 0)

    def render_GET(self, request):
        """
        Return the latest TC block of a peer, as identified in the request

        :param request: the request for retrieving the latest TC block of a peer. It must contain the peer's
                        public key of the peer
        :return: the latest block of the peer, if found
        """
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        if not request.args or b'public_key' not in request.args:
            request.setResponseCode(http.BAD_REQUEST)
            return self.twisted_dumps({"error": "Must specify the peer's public key"})

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(self.twisted_dumps({
                "error": {
                    "handled": True,
                    "code": failure.value.__class__.__name__,
                    "message": str(failure.value)
                }
            }))
            request.finish()

        def on_success(new_chunks, chunk_dict, counts, start_idx, target_public_key):

            if not new_chunks:
                # If we're here it means that there are no more chunks to be retrieved
                max_version_block = None

                if chunk_dict and counts:
                    # Try to find a complete block which has the greatest version
                    for version in sorted(list(chunk_dict.keys()), reverse=True):
                        if version in counts and counts[version] == 0:
                            max_version_block = b''.join(chunk_dict[version])
                            break

                if max_version_block:
                    request.write(self.twisted_dumps({"block": b64encode(max_version_block).decode('utf-8')}))
                else:
                    # If start_idx is different from 0, then this means all the chunks have been consumed
                    request.setResponseCode(http.NOT_FOUND)
                    request.write(self.twisted_dumps({
                        u"error": {
                            u"handled": True,
                            u"message": "Could not reconstruct any block successfully." if start_idx != 0 else
                                        u"Could not find any blocks for the specified key."
                        }
                    }))

                request.finish()
            else:
                # Given the new chunks, we will continue to build the blocks we have so far
                chunk_dict, max_version, counts = self.reconstruct_all_blocks([x[0] for x in new_chunks],
                                                                              target_public_key, chunk_dict, counts)

                # If a block has been successfully constructed, we build and return it, otherwise we'll keep searching
                if counts.get(max_version, -1) == 0:
                    request.write(self.twisted_dumps(
                        {"block": b64encode(b''.join(chunk_dict[max_version])).decode('utf-8')}))
                    request.finish()
                else:
                    # Continue the search from the next blocks
                    start_idx += MAX_VALUES_IN_FIND
                    self.dht.find_values(hash_key, start_idx=start_idx).addCallback(
                        on_success, chunk_dict, counts, start_idx, target_public_key).addErrback(on_failure)

        raw_public_key = b64decode(request.args[b'public_key'][0])
        hash_key = sha1(raw_public_key + self.KEY_SUFFIX).digest()

        target_public_key_master = LibNaCLPK(binarykey=raw_public_key[10:])

        self.dht.find_values(hash_key).addCallback(on_success, None, None, 0, target_public_key_master) \
            .addErrback(on_failure)

        return NOT_DONE_YET


class DHTStatisticsEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for returning statistics about the DHT.
    """

    def __init__(self, dht):
        super(DHTStatisticsEndpoint, self).__init__()
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        buckets = self.dht.routing_table.trie.values()
        stats = {"node_id": hexlify(self.dht.my_node_id).decode('utf-8'),
                 "peer_id": hexlify(self.dht.my_peer.mid).decode('utf-8'),
                 "routing_table_size": sum([len(bucket.nodes) for bucket in buckets]),
                 "routing_table_buckets": len(buckets),
                 "num_keys_in_store": len(self.dht.storage.items),
                 "num_tokens": len(self.dht.tokens)}

        if isinstance(self.dht, DHTDiscoveryCommunity):
            stats.update({
                "num_peers_in_store": {hexlify(key).decode('utf-8'): len(peers)
                                       for key, peers in self.dht.store.items()},
                "num_store_for_me": {hexlify(key).decode('utf-8'): len(peers)
                                     for key, peers in self.dht.store_for_me.items()}
            })

        return self.twisted_dumps({"statistics": stats})


class DHTPeersEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT peers.
    """

    def __init__(self, dht):
        super(DHTPeersEndpoint, self).__init__()
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTPeerEndpoint(self.dht, path)


class SpecificDHTPeerEndpoint(BaseEndpoint):
    """
    This class handles requests for a specific DHT peer.
    """

    def __init__(self, dht, key):
        super(SpecificDHTPeerEndpoint, self).__init__()
        self.mid = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        def on_success(nodes):
            node_dicts = []
            for node in nodes:
                node_dicts.append({
                    'public_key': b64encode(node.public_key.key_to_bin()).decode('utf-8'),
                    'address': node.address
                })
            request.write(self.twisted_dumps({"peers": node_dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(self.twisted_dumps({
                "error": {
                    "handled": True,
                    "code": failure.value.__class__.__name__,
                    "message": str(failure.value)
                }
            }))
            request.finish()

        self.dht.connect_peer(self.mid).addCallbacks(on_success, on_failure)

        return NOT_DONE_YET


class DHTValuesEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT values.
    """

    def __init__(self, dht):
        super(DHTValuesEndpoint, self).__init__()
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        results = {}
        for key, raw_values in self.dht.storage.items.items():
            values = self.dht.post_process_values([v.data for v in raw_values])
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({
                    'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                    'value': hexlify(data).decode('utf-8')
                })
            results[hexlify(key)] = dicts

        return self.twisted_dumps(results)

    def getChild(self, path, request):
        return SpecificDHTValueEndpoint(self.dht, path)


class SpecificDHTValueEndpoint(BaseEndpoint):
    """
    This class handles requests for a specific DHT value.
    """

    def __init__(self, dht, key):
        super(SpecificDHTValueEndpoint, self).__init__()
        self.key = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        def on_success(values):
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({
                    'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                    'value': hexlify(data).decode('utf-8')
                })
            request.write(self.twisted_dumps({"values": dicts}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(self.twisted_dumps({
                "error": {
                    "handled": True,
                    "code": failure.value.__class__.__name__,
                    "message": str(failure.value)
                }
            }))
            request.finish()

        self.dht.find_values(self.key).addCallbacks(on_success, on_failure)

        return NOT_DONE_YET

    def render_PUT(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        def on_success(_):
            request.write(self.twisted_dumps({"stored": True}))
            request.finish()

        def on_failure(failure):
            request.setResponseCode(http.INTERNAL_SERVER_ERROR)
            request.write(self.twisted_dumps({
                "error": {
                    "handled": True,
                    "code": failure.value.__class__.__name__,
                    "message": str(failure.value)
                }
            }))
            request.finish()

        parameters = http.parse_qs(request.content.read(), 1)
        if 'value' not in parameters:
            request.setResponseCode(http.BAD_REQUEST)
            return self.twisted_dumps({"error": "incorrect parameters"})

        self.dht.store_value(self.key, unhexlify(parameters['value'][0]), sign=True).addCallbacks(on_success,
                                                                                                  on_failure)

        return NOT_DONE_YET
