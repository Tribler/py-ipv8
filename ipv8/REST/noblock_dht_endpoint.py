from __future__ import absolute_import

import logging
from binascii import hexlify, unhexlify

from twisted.web import http

from .base_endpoint import BaseEndpoint
from ..dht.community import DHTCommunity


class NoBlockDHTEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data, non-blocking.
    """

    def __init__(self, session):
        super(NoBlockDHTEndpoint, self).__init__()
        dht_overlays = [overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)]
        if dht_overlays:
            self.putChild(b"peers", NoBlockDHTPeersEndpoint(dht_overlays[0]))


class NoBlockDHTPeersEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT peers, non-blocking.
    """

    def __init__(self, dht):
        super(NoBlockDHTPeersEndpoint, self).__init__()
        self.dht = dht

    def getChild(self, path, request):
        return NoBlockSpecificDHTPeerEndpoint(self.dht, path)


class NoBlockSpecificDHTPeerEndpoint(BaseEndpoint):
    """
    This class handles requests for a specific DHT peer, non-blocking.
    """

    def __init__(self, dht, key):
        super(NoBlockSpecificDHTPeerEndpoint, self).__init__()
        self.mid = bytes(unhexlify(key))
        self.dht = dht

    def render_GET(self, request):
        if not self.dht:
            request.setResponseCode(http.NOT_FOUND)
            return self.twisted_dumps({"error": "DHT community not found"})

        def on_success(nodes):
            logging.error("DHT connected to %s", hexlify(self.mid))

        def on_failure(failure):
            logging.error("DHT Failed to connect to %s", hexlify(self.mid))

        self.dht.connect_peer(self.mid).addCallbacks(on_success, on_failure)

        return self.twisted_dumps({"success": True})
