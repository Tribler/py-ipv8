from __future__ import absolute_import

import logging
from asyncio import ensure_future
from binascii import hexlify, unhexlify

from aiohttp import web

from .base_endpoint import BaseEndpoint, Response, HTTP_NOT_FOUND
from ..dht.community import DHTCommunity


class NoBlockDHTEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data, non-blocking.
    """

    def __init__(self):
        super(NoBlockDHTEndpoint, self).__init__()
        self.dht = None

    def setup_routes(self):
        self.app.add_routes([web.get('/{mid}', self.handle_get)])

    def initialize(self, session):
        super(NoBlockDHTEndpoint, self).initialize(session)
        self.dht = next((overlay for overlay in session.overlays if isinstance(overlay, DHTCommunity)), None)

    def handle_get(self, request):
        if not self.dht:
            return Response({"error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        mid = unhexlify(request.match_info['mid'])
        async def connect_peer():
            try:
                self.dht.connect_peer(mid)
            except:
                logging.error("DHT Failed to connect to %s", hexlify(mid))
            else:
                logging.error("DHT connected to %s", hexlify(mid))

        ensure_future(connect_peer())
        return Response({"success": True})
