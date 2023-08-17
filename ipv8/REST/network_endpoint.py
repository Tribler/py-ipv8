from base64 import b64encode
from typing import cast

from aiohttp import web
from aiohttp.abc import Request
from aiohttp_apispec import docs
from marshmallow.fields import Integer, List, String

from ..types import IPv8
from .base_endpoint import BaseEndpoint, Response
from .schema import schema


class NetworkEndpoint(BaseEndpoint[IPv8]):
    """
    This endpoint is responsible for handing all requests regarding the state of the network.
    """

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('', self.retrieve_peers)])

    @docs(
        tags=["Network"],
        summary="Return a list of all known peers.",
        responses={
            200: {
                "schema": schema(PeersResponse={
                    "peers": [schema(Peer={
                        "ip": String,
                        "port": Integer,
                        "public_key": String,
                        "services": List(String),
                    })]
                })
            }
        }
    )
    async def retrieve_peers(self, _: Request) -> Response:
        """
        Return a list of all known peers.
        """
        if self.session is None:
            return Response({"peers": {}})
        self.session = cast(IPv8, self.session)

        network = self.session.network
        peer_list = network.verified_peers
        return Response({"peers": {
            b64encode(peer.mid).decode('utf-8'): {
                "ip": peer.address[0],
                "port": peer.address[1],
                "public_key": b64encode(peer.public_key.key_to_bin()).decode('utf-8'),
                "services": [b64encode(s).decode('utf-8') for s in network.get_services_for_peer(peer)]
            }
            for peer in peer_list
        }})
