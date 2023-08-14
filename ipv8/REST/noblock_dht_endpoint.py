import logging
from asyncio import ensure_future
from binascii import hexlify, unhexlify

from aiohttp import web
from aiohttp.abc import Request
from aiohttp_apispec import docs

from ..dht import DHTError
from ..dht.community import DHTCommunity
from ..types import IPv8
from .base_endpoint import HTTP_NOT_FOUND, BaseEndpoint, Response
from .schema import DefaultResponseSchema


class NoBlockDHTEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data, non-blocking.
    """

    def __init__(self) -> None:
        """
        Create a REST endpoint for all non-blocking calls to the DHT overlay.
        """
        super().__init__()
        self.dht = None

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('/{mid}', self.handle_get)])

    def initialize(self, session: IPv8) -> None:
        """
        Initialize this endpoint.
        """
        super().initialize(session)
        self.dht = session.get_overlay(DHTCommunity)

    @docs(
        tags=["DHT"],
        summary="Connect to a peer through the DHT.",
        parameters=[{
            'in': 'path',
            'name': 'mid',
            'description': 'The mid (i.e., sha1(public_key)) of the peer to connect to.',
            'type': 'string',
            'required': True
        }],
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "examples": {'Success': {"success": True}}
            },
            HTTP_NOT_FOUND: {
                "schema": DefaultResponseSchema,
                "examples": {'DHT not loaded': {"success": False, "error": "DHT community not found"}}
            }
        }
    )
    async def handle_get(self, request: Request) -> Response:
        """
        Handle a GET request.
        """
        if not self.dht:
            return Response({"error": "DHT community not found"}, status=HTTP_NOT_FOUND)

        mid = unhexlify(request.match_info['mid'])

        async def connect_peer() -> None:
            try:
                self.dht.connect_peer(mid)
            except DHTError:
                logging.exception("DHT Failed to connect to %s", hexlify(mid))
            else:
                logging.exception("DHT connected to %s", hexlify(mid))

        ensure_future(connect_peer())  # noqa: RUF006
        return Response({"success": True})
