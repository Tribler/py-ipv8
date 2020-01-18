from aiohttp import web

from aiohttp_apispec import docs, json_schema

from marshmallow.fields import Boolean, Integer, String

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, Response
from .schema import DefaultResponseSchema, schema
from ..community import _DEFAULT_ADDRESSES
from ..messaging.anonymization.community import TunnelCommunity
from ..util import cast_to_chr


class IsolationEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for on-demand adding of addresses for different services.
    """

    def setup_routes(self):
        self.app.add_routes([web.post('', self.handle_post)])

    def add_exit_node(self, address):
        for overlay in self.session.overlays:
            if isinstance(overlay, TunnelCommunity):
                overlay.walk_to(address)

    def add_bootstrap_server(self, address):
        _DEFAULT_ADDRESSES.append(address)
        for overlay in self.session.overlays:
            overlay.walk_to(address)

    @docs(
        tags=["Isolation"],
        summary="Add an address to a specific IPv8 service.",
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "examples": {'Success': {"success": True}}
            },
            HTTP_BAD_REQUEST: {
                "schema": DefaultResponseSchema,
                "examples": {'Bad IPv4 address': {"success": False, "error": "Traceback (most recent call last): ..."}}
            }
        }
    )
    @json_schema(schema(IsolationRequest={
        'ip*': String,
        'port*': Integer,
        'bootstrapnode': Boolean,
        'exitnode': Boolean
    }))
    async def handle_post(self, request):
        # Check if we have arguments, containing an address and the type of address to add.
        args = await request.json()
        if not args or 'ip' not in args or 'port' not in args:
            return Response({"success": False, "error": "Parameters 'ip' and 'port' are required"},
                            status=HTTP_BAD_REQUEST)
        if 'exitnode' not in args and 'bootstrapnode' not in args:
            return Response({"success": False, "error": "Parameter 'exitnode' or 'bootstrapnode' is required"},
                            status=HTTP_BAD_REQUEST)
        # Attempt to decode the address
        try:
            address_str = cast_to_chr(args['ip'])
            port_str = cast_to_chr(args['port'])
            fmt_address = (address_str, int(port_str))
        except Exception:
            import traceback
            return Response({"success": False, "error": traceback.format_exc()}, status=HTTP_BAD_REQUEST)
        # Actually add the address to the requested service
        if 'exitnode' in args:
            self.add_exit_node(fmt_address)
        else:
            self.add_bootstrap_server(fmt_address)
        return Response({"success": True})
