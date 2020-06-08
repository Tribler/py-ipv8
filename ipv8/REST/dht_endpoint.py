import logging
from asyncio import ensure_future
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
from hashlib import sha1

from aiohttp import web

from aiohttp_apispec import docs, json_schema

from marshmallow.fields import Integer, String

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_NOT_FOUND, Response
from .schema import DHTValueSchema, DefaultResponseSchema, schema
from ..attestation.trustchain.community import TrustChainCommunity
from ..attestation.trustchain.listener import BlockListener
from ..attestation.trustchain.payload import DHTBlockPayload
from ..dht import DHTError
from ..dht.community import DHTCommunity, MAX_ENTRY_SIZE, MAX_VALUES_IN_FIND
from ..dht.discovery import DHTDiscoveryCommunity
from ..keyvault.public.libnaclkey import LibNaCLPK
from ..messaging.serialization import PackError, Serializer


class DHTEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self):
        super(DHTEndpoint, self).__init__()
        self.dht = self.publisher = None

    def setup_routes(self):
        self.app.add_routes([web.get('/statistics', self.get_statistics),
                             web.get('/values', self.get_stored_values),
                             web.get('/values/{key}', self.get_values),
                             web.put('/values/{key}', self.put_value),
                             web.get('/peers/{mid}', self.get_peer),
                             web.get('/buckets', self.get_buckets),
                             web.get('/buckets/{prefix:\\w*}/refresh', self.refresh_bucket),
                             web.get('/block', self.get_block)])

    def initialize(self, session):
        super(DHTEndpoint, self).initialize(session)
        self.dht = session.get_overlay(DHTCommunity)
        tc = session.get_overlay(TrustChainCommunity)
        self.publisher = DHTBlockPublisher(self.dht, tc) if self.dht and tc else None

    @docs(
        tags=["DHT"],
        summary="Return DHT statistics.",
        responses={
            200: {
                "schema": schema(DHTStatsResponse={
                    "statistics": schema(DHTStats={
                        "node_id": String,
                        "peer_id": String,
                        "routing_table_size": Integer,
                        "routing_table_buckets": Integer,
                        "num_keys_in_store": Integer,
                        "num_tokens": Integer,
                        "num_peers_in_store": Integer,
                        "num_store_for_me": Integer
                    })
                })
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    async def get_statistics(self, _):
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

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

        return Response({"statistics": stats})

    @docs(
        tags=["DHT"],
        summary="Connect to a peer using the DHT.",
        responses={
            200: {
                "schema": schema(DHTPeerResponse={
                    "peers": [schema(DHTPeer={
                        "public_key": String,
                        "address": String
                    })]
                })
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    async def get_peer(self, request):
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        mid = unhexlify(request.match_info['mid'])
        nodes = await self.dht.connect_peer(mid)
        return Response({"peers": [{'public_key': b64encode(node.public_key.key_to_bin()).decode('utf-8'),
                                    'address': node.address} for node in nodes]})

    @docs(
        tags=["DHT"],
        summary="Get a list of locally stored key-value pairs from the DHT.",
        responses={
            200: {
                "schema": schema(DHTStoredValuesResponse={
                    "values": [DHTValueSchema]
                })
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    async def get_stored_values(self, _):
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        results = {}
        for key, raw_values in self.dht.storage.items.items():
            values = self.dht.post_process_values([v.data for v in raw_values])
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({
                    'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                    'key': hexlify(key).decode('utf-8'),
                    'value': hexlify(data).decode('utf-8')
                })
            results[hexlify(key)] = dicts
        return Response(results)

    @docs(
        tags=["DHT"],
        summary="Lookup the values for a specific key on the DHT.",
        responses={
            200: {
                "schema": schema(DHTValuesResponse={
                    "values": [DHTValueSchema]
                })
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    async def get_values(self, request):
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        key = unhexlify(request.match_info['key'])
        values = await self.dht.find_values(key)

        return Response({"values": [{'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                                     'key': hexlify(key).decode('utf-8'),
                                     'value': hexlify(data).decode('utf-8')} for data, public_key in values]})

    @docs(
        tags=["DHT"],
        summary="Store a key-value pair on the DHT.",
        parameters=[{
            'in': 'path',
            'name': 'key',
            'description': 'The key under which to store the value',
            'type': 'string',
            'required': True
        }],
        responses={
            200: {"schema": DefaultResponseSchema},
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    @json_schema(schema(DHTStoreRequest={
        'value*': String
    }))
    async def put_value(self, request):
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        parameters = await request.json()
        if 'value' not in parameters:
            return Response({"success": False, "error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        key = unhexlify(request.match_info['key'])
        await self.dht.store_value(key, unhexlify(parameters['value']), sign=True)
        return Response({"success": True})

    @docs(
        tags=["DHT"],
        summary="Return a list of all buckets in the routing table of the DHT community.",
        responses={
            200: {
                "schema": schema(BucketsResponse={
                    "buckets": [schema(Bucket={
                        "prefix": String,
                        "peers": [schema(BucketPeer={
                            "ip": String,
                            "port": Integer,
                            "mid": String,
                            "id": String,
                            "failed": Integer,
                            "last_contact": Integer,
                            "distance": Integer
                        })]
                    })]
                })
            }
        }
    )
    async def get_buckets(self, _):
        return Response({"buckets": [{
            "prefix": bucket.prefix_id,
            "peers": [{
                "ip": peer.address[0],
                "port": peer.address[1],
                "mid": hexlify(peer.mid).decode('utf-8'),
                "id": hexlify(peer.id).decode('utf-8'),
                "failed": peer.failed,
                "last_contact": peer.last_contact,
                "distance": peer.distance(self.dht.my_node_id),
            } for peer in bucket.nodes.values()]
        } for bucket in self.dht.routing_table.trie.values()]})

    @docs(
        tags=["DHT"],
        summary="Refresh a specific bucket in the DHT community.",
        parameters=[{
            'in': 'path',
            'name': 'prefix',
            'description': 'Prefix of the bucket which to refresh.',
            'type': 'string',
            'required': True
        }],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Unknown bucket': {"success": False, "error": "no such bucket"}}
            }
        }
    )
    async def refresh_bucket(self, request):
        prefix = request.match_info['prefix']

        try:
            bucket = self.dht.routing_table.trie[prefix]
        except KeyError:
            return Response({"success": False, "error": "no such bucket"}, status=HTTP_BAD_REQUEST)

        try:
            await self.dht.find_values(bucket.generate_id())
        except DHTError as e:
            return Response({"success": False, "error": str(e)})
        else:
            return Response({"success": True})

    @docs(
        tags=["DHT"],
        summary="Find the most recent TrustChain block for a specific user on the DHT.",
        parameters=[{
            'in': 'query',
            'name': 'public_key',
            'description': 'Public key of the users for which to find the most recent block',
            'type': 'string',
            'required': True
        }],
        responses={
            200: {"schema": schema(DHTBlockResponse={"block": (String, 'Bencoded block')})},
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT disabled': {"success": False, "error": "DHT community not found."}}
            }
        }
    )
    async def get_block(self, request):
        """
        Return the latest TC block of a peer, as identified in the request

        :param request: the request for retrieving the latest TC block of a peer. It must contain the peer's
        public key of the peer
        :return: the latest block of the peer, if found
        """
        if not self.dht:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)
        if not self.publisher:
            return Response({"success": False, "error": "DHT publisher not found"}, status=HTTP_NOT_FOUND)

        parameters = request.query
        if 'public_key' not in parameters:
            return Response({"success": False, "error": "Must specify the peer's public key"}, status=HTTP_BAD_REQUEST)

        raw_public_key = b64decode(parameters['public_key'])
        block = await self.publisher.retrieve_block(raw_public_key)

        if not block:
            return Response({"success": False, "error": "No block found"}, status=HTTP_NOT_FOUND)

        return Response({"block": b64encode(block).decode('utf-8')})


class DHTBlockPublisher(BlockListener):
    """
    This class is responsible for publishing the latest Trustchain block of a peer on the DHT.
    """

    # The period of the block maintenance task
    BLOCK_REFRESH_PERIOD = 60 * 60  # 1 hour
    KEY_SUFFIX = b'_BLOCK'
    CHUNK_SIZE = MAX_ENTRY_SIZE - DHTBlockPayload.PREAMBLE_OVERHEAD - 1
    ATTEMPT_LIMIT = 3

    def __init__(self, dht, trustchain):
        self.dht = dht
        self.trustchain = trustchain
        self.block_version = 0
        self.serializer = Serializer()

        self._hashed_dht_key = sha1(self.trustchain.my_peer.public_key.key_to_bin() + self.KEY_SUFFIX).digest()

        self.trustchain.register_task('block_maintenance', self.publish_latest_block,
                                      interval=self.BLOCK_REFRESH_PERIOD)

        trustchain.add_listener(self, [trustchain.UNIVERSAL_BLOCK_LISTENER])

    def received_block(self, block):
        """
        Wrapper callback method, inherited from the BlockListener abstract class, which will publish the latest
        TrustChain block to the DHT

        :param block: the latest block added to the Database. This is not actually used by the inner method
        """
        # Check if the block is not null, and if it belongs to this peer
        if block and block.public_key == self.trustchain.my_peer.public_key.key_to_bin():
            ensure_future(self.publish_block(block))

    def should_sign(self, block):
        pass

    async def publish_latest_block(self):
        """
        Republish the latest TrustChain block under this peer's key
        """
        block = self.trustchain.persistence.get_latest(self.trustchain.my_peer.public_key.key_to_bin())
        if block:
            await self.publish_block(block, republish=True)

    async def publish_block(self, block, republish=False):
        """
        Publishes a block to the DHT, by splitting it in chunks.

        :param block: the block to be published to the DHT
        :param republish: boolean which indicates whether the published block has already been published again
        """
        latest_block = block.pack()

        # Get the total number of chunks in this blocks
        total_chunks = len(latest_block) // self.CHUNK_SIZE
        total_chunks += 1 if len(latest_block) % self.CHUNK_SIZE != 0 else 0

        # The actual version of the block may vary based on whether the block is being published or republished
        actual_version = max(self.block_version if not republish else (self.block_version - 1), 0)

        # On the off chance that the block is actually empty, avoid publishing it
        if total_chunks > 0:
            slice_pointer = chunk_idx = 0
            chunk_attempt = 1

            while chunk_attempt <= self.ATTEMPT_LIMIT:
                # If we've reached the end of the block, we stop the chain, and increment the block version
                if chunk_idx >= total_chunks:
                    if not republish:
                        # Restart the maintenance loop
                        self.trustchain.cancel_pending_task('block_maintenance')
                        self.trustchain.register_task('block_maintenance', self.publish_latest_block,
                                                      interval=self.BLOCK_REFRESH_PERIOD)
                        self.block_version += 1
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
                try:
                    await self.dht.store_value(self._hashed_dht_key, blob_chunk[0])
                except (DHTError, PackError):
                    chunk_attempt += 1
                else:
                    slice_pointer += self.CHUNK_SIZE
                    chunk_idx += 1
                    chunk_attempt = 1

            # If we've attempted to publish this block more times than allowed, give up on the chunk and the block
            if chunk_attempt > self.ATTEMPT_LIMIT:
                logging.error("Publishing latest block failed after %d attempts on chunk %d",
                              self.ATTEMPT_LIMIT, chunk_idx)

    async def retrieve_block(self, raw_public_key):
        target_public_key = LibNaCLPK(binarykey=raw_public_key[10:])

        chunk_dict = None
        counts = None
        start_idx = 0

        hash_key = sha1(raw_public_key + self.KEY_SUFFIX).digest()
        new_chunks = await self.dht.find_values(hash_key)
        while new_chunks:
            # Given the new chunks, we will continue to build the blocks we have so far
            chunk_dict, max_version, counts = self.reconstruct_all_blocks([x[0] for x in new_chunks],
                                                                          target_public_key, chunk_dict, counts)

            # If a block has been successfully constructed, we build and return it, otherwise we'll keep searching
            if counts.get(max_version, -1) == 0:
                return b''.join(chunk_dict[max_version])
            else:
                # Continue the search from the next blocks
                start_idx += MAX_VALUES_IN_FIND
                new_chunks = await self.dht.find_values(hash_key, start_idx=start_idx)

        # If we're here it means that there are no more chunks to be retrieved
        max_version_block = None

        if chunk_dict and counts:
            # Try to find a complete block which has the greatest version
            for version in sorted(list(chunk_dict.keys()), reverse=True):
                if version in counts and counts[version] == 0:
                    max_version_block = b''.join(chunk_dict[version])
                    break

        if max_version_block:
            return max_version_block
        else:
            err_msg = "Could not reconstruct any block successfully." if start_idx != 0 \
                      else "Could not find any blocks for the specified key."
            raise RuntimeError(err_msg)

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

                    if not chunk_dict[package.version][package.block_position]:
                        chunk_dict[package.version][package.block_position] = package.payload
                        counts[package.version] -= 1
            except PackError:
                logging.error("PackError: Found a clandestine entry in the DHT when reconstructing TC blocks: %s",
                              entry)

        return chunk_dict, max_version, counts
