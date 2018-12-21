from __future__ import absolute_import

from base64 import b64encode
from binascii import hexlify, unhexlify
import json

from twisted.web import http
from twisted.web.server import NOT_DONE_YET

from ..dht.community import DHTCommunity
from ..dht.discovery import DHTDiscoveryCommunity
from .formal_endpoint import FormalEndpoint
from .validation.annotations import RESTInput, RESTOutput
from .validation.types import BOOLEAN_TYPE, NUMBER_TYPE, OptionalKey, STR_TYPE, TUPLE_TYPE


class DHTEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        super(DHTEndpoint, self).__init__()

        dht_overlays = [overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)]
        if dht_overlays:
            self.putChild("statistics", DHTStatisticsEndpoint(dht_overlays[0]))
            self.putChild("values", DHTValuesEndpoint(dht_overlays[0]))
            self.putChild("peers", DHTPeersEndpoint(dht_overlays[0]))


class DHTStatisticsEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for returning statistics about the DHT.
    """

    def __init__(self, dht):
        super(DHTStatisticsEndpoint, self).__init__()
        self.dht = dht

    @RESTOutput(lambda request: True,
                {
                    "statistics": {
                        "node_id": STR_TYPE["HEX"],
                        "peer_id": STR_TYPE["HEX"],
                        "routing_table_size": NUMBER_TYPE,
                        "routing_table_buckets": NUMBER_TYPE,
                        "num_keys_in_store": NUMBER_TYPE,
                        "num_tokens": NUMBER_TYPE,
                        OptionalKey("num_peers_in_store"): {
                            STR_TYPE["HEX"]: NUMBER_TYPE
                        },
                        OptionalKey("num_store_for_me"): {
                            STR_TYPE["HEX"]: NUMBER_TYPE
                        }
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
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


class DHTPeersEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handling requests for DHT peers.
    """

    def __init__(self, dht):
        super(DHTPeersEndpoint, self).__init__()
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTPeerEndpoint(self.dht, path)

    def generate_documentation(self, absolute_path=[]):
        super(DHTPeersEndpoint, self).generate_documentation(absolute_path)
        SpecificDHTPeerEndpoint(None, "").generate_documentation(absolute_path + ["%s"])


class SpecificDHTPeerEndpoint(FormalEndpoint):
    """
    This class handles requests for a specific DHT peer.
    """

    def __init__(self, dht, key):
        super(SpecificDHTPeerEndpoint, self).__init__()
        self.mid = bytes(unhexlify(key))
        self.dht = dht

    @RESTOutput(lambda request: True,
                {
                    "peers": {
                        "public_key": STR_TYPE["BASE64"],
                        "address": TUPLE_TYPE(STR_TYPE["ASCII"], NUMBER_TYPE)
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
    @RESTOutput(lambda request: True,
                {
                    "error": {
                        "handled": BOOLEAN_TYPE,
                        "code": STR_TYPE["ASCII"],
                        "message": STR_TYPE["ASCII"]
                    }
                },
                http.INTERNAL_SERVER_ERROR)
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


class DHTValuesEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handling requests for DHT values.
    """

    def __init__(self, dht):
        super(DHTValuesEndpoint, self).__init__()
        self.dht = dht

    def getChild(self, path, request):
        return SpecificDHTValueEndpoint(self.dht, path)

    def generate_documentation(self, absolute_path=[]):
        super(DHTValuesEndpoint, self).generate_documentation(absolute_path)
        SpecificDHTValueEndpoint(None, "").generate_documentation(absolute_path + ["%s"])


class SpecificDHTValueEndpoint(FormalEndpoint):
    """
    This class handles requests for a specific DHT value.
    """

    def __init__(self, dht, key):
        super(SpecificDHTValueEndpoint, self).__init__()
        self.key = bytes(unhexlify(key))
        self.dht = dht

    @RESTOutput(lambda request: True,
                {
                    "values": {
                        "public_key": STR_TYPE["BASE64"],
                        "value": STR_TYPE["HEX"]
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
    @RESTOutput(lambda request: True,
                {
                    "error": {
                        "handled": BOOLEAN_TYPE,
                        "code": STR_TYPE["ASCII"],
                        "message": STR_TYPE["ASCII"]
                    }
                },
                http.INTERNAL_SERVER_ERROR)
    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "DHT community not found"})

        def on_success(values):
            dicts = []
            for value in values:
                data, public_key = value
                dicts.append({'public_key': b64encode(public_key) if public_key else "",
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

    @RESTInput("value", (STR_TYPE["HEX"], "The value to store."))
    @RESTOutput(lambda request: True,
                {
                    "stored": BOOLEAN_TYPE
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                [http.BAD_REQUEST, http.NOT_FOUND])
    @RESTOutput(lambda request: True,
                {
                    "error": {
                        "handled": BOOLEAN_TYPE,
                        "code": STR_TYPE["ASCII"],
                        "message": STR_TYPE["ASCII"]
                    }
                },
                http.INTERNAL_SERVER_ERROR)
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
