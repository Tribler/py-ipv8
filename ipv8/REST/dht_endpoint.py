from __future__ import annotations

from base64 import b64encode
from binascii import hexlify, unhexlify
from timeit import default_timer
from typing import TYPE_CHECKING, List, Optional, Sequence, Tuple, cast

from aiohttp import web
from aiohttp_apispec import docs, json_schema
from marshmallow.fields import Integer, String

from ..dht import DHTError
from ..dht.community import Crawl, DHTCommunity
from ..dht.discovery import DHTDiscoveryCommunity
from ..dht.routing import Node, calc_node_id
from ..dht.storage import Storage
from ..messaging.interfaces.dispatcher.endpoint import FAST_ADDR_TO_INTERFACE
from ..types import IPv8
from .base_endpoint import HTTP_BAD_REQUEST, HTTP_NOT_FOUND, BaseEndpoint, Response
from .schema import DefaultResponseSchema, DHTValueSchema, schema

if TYPE_CHECKING:
    from aiohttp.abc import Request


class DHTEndpoint(BaseEndpoint[IPv8]):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self) -> None:
        """
        Create new unregistered and uninitialized REST endpoint.
        """
        super().__init__()
        self.dht: DHTCommunity | None = None
        self.publisher = None

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('/statistics', self.get_statistics),
                             web.get('/values', self.get_stored_values),
                             web.get('/values/{key}', self.get_values),
                             web.put('/values/{key}', self.put_value),
                             web.get('/peers/{mid}', self.get_peer),
                             web.get('/buckets', self.get_buckets),
                             web.get('/buckets/{prefix:\\w*}/refresh', self.refresh_bucket)])

    def initialize(self, session: IPv8) -> None:
        """
        Initialize this endpoint for the given session instance.
        """
        super().initialize(session)
        self.dht = session.get_overlay(DHTCommunity)

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
    async def get_statistics(self, _: Request) -> Response:
        """
        Return DHT statistics.
        """
        if self.dht is None:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        stats = {
            "peer_id": hexlify(self.dht.my_peer.mid).decode('utf-8'),
            "num_tokens": len(self.dht.tokens),
            "endpoints": []
        }

        for address_cls, routing_table in self.dht.routing_tables.items():
            buckets = routing_table.trie.values()
            address = self.dht.my_peer.addresses.get(address_cls, self.dht.my_estimated_wan)
            endpoints = cast(List, stats["endpoints"])
            endpoints.append({
                "endpoint": FAST_ADDR_TO_INTERFACE[address_cls],
                "node_id": hexlify(calc_node_id(address, self.dht.my_peer.mid)).decode('utf-8'),
                "routing_table_size": sum([len(bucket.nodes) for bucket in buckets]),
                "routing_table_buckets": len(buckets),
                "num_keys_in_store":
                    len(cast(Storage, self.dht.storages.get(address_cls)).items) if self.dht.storages.get(address_cls)
                    else 0,
            })

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
    async def get_peer(self, request: Request) -> Response:
        """
        Connect to a peer using the DHT.
        """
        if self.dht is None or not isinstance(self.dht, DHTDiscoveryCommunity):
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
    async def get_stored_values(self, _: Request) -> Response:
        """
        Get a list of locally stored key-value pairs from the DHT.
        """
        if self.dht is None:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        results = {}
        for address_cls, storage in self.dht.storages.items():
            for key, raw_values in storage.items.items():
                values = self.dht.post_process_values([v.data for v in raw_values])
                dicts = []
                for value in values:
                    data, public_key = value
                    dicts.append({
                        'endpoint': FAST_ADDR_TO_INTERFACE[address_cls],
                        'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                        'key': hexlify(key).decode('utf-8'),
                        'value': hexlify(data).decode('utf-8')
                    })
                results[hexlify(key).decode()] = dicts
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
    async def get_values(self, request: Request) -> Response:
        """
        Lookup the values for a specific key on the DHT.
        """
        if self.dht is None:
            return Response({"success": False, "error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        key = unhexlify(request.match_info['key'])

        start = default_timer()
        values, crawls = cast(Tuple[Sequence[Tuple[bytes, Optional[bytes]]], List[Crawl]],
                              await self.dht.find_values(key, debug=True))
        nodes_tried = set().union(*[crawl.nodes_tried for crawl in crawls])
        responses: list[tuple[Node, dict]] = sum([crawl.responses for crawl in crawls], [])
        stop = default_timer()

        return Response({
            "values": [{'public_key': b64encode(public_key).decode('utf-8') if public_key else None,
                        'key': hexlify(key).decode('utf-8'),
                        'value': hexlify(data).decode('utf-8')} for data, public_key in values],
            "debug": {
                "requests": len(nodes_tried),
                "responses": len(responses),
                "responses_with_nodes": len([r for s, r in responses if 'nodes' in r]),
                "responses_with_values": len([r for s, r in responses if 'values' in r]),
                "time": stop - start
            }
        })

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
    async def put_value(self, request: Request) -> Response:
        """
        Store a key-value pair on the DHT.
        """
        if self.dht is None:
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
                        "last_changed": Integer,
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
    async def get_buckets(self, _: Request) -> Response:
        """
        Return a list of all buckets in the routing table of the DHT community.
        """
        if self.dht is None:
            return Response({"buckets": []})
        self.dht = cast(DHTCommunity, self.dht)

        return Response({"buckets": [{
            "prefix": bucket.prefix_id,
            "last_changed": bucket.last_changed,
            "endpoint": FAST_ADDR_TO_INTERFACE[address_cls],
            "peers": [{
                "ip": peer.address[0],
                "port": peer.address[1],
                "mid": hexlify(peer.mid).decode('utf-8'),
                "id": hexlify(peer.id).decode('utf-8'),
                "failed": peer.failed,
                "last_contact": peer.last_contact,
                "distance": peer.distance(self.dht.get_my_node_id(peer)),
            } for peer in bucket.nodes.values()]
        } for address_cls, routing_table in self.dht.routing_tables.items() for bucket in routing_table.trie.values()]})

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
    async def refresh_bucket(self, request: Request) -> Response:
        """
        Prefix of the bucket which to refresh.
        """
        if self.dht is None:
            return Response({"success": False, "error": "DHT community is not loaded"}, status=HTTP_BAD_REQUEST)
        self.dht = cast(DHTCommunity, self.dht)

        prefix = request.match_info['prefix']
        success = False
        error = None
        for routing_table in list(self.dht.routing_tables.values()):
            try:
                await self.dht.find_values(routing_table.trie[prefix].generate_id())
                success = True
            except KeyError:
                pass
            except DHTError as e:
                error = e

        if not error and not success:
            return Response({"success": False, "error": "no such bucket"}, status=HTTP_BAD_REQUEST)
        if error and not success:
            return Response({"success": False, "error": str(error)})
        return Response({"success": True})
