from __future__ import absolute_import

from twisted.web import http

from .base_endpoint import BaseEndpoint
from ..community import _DEFAULT_ADDRESSES
from ..messaging.anonymization.community import TunnelCommunity
from ..util import cast_to_chr


class IsolationEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for on-demand adding of addresses for different services.

    We support:
     - POST: /isolation?ip=<IP>&port=<PORT>&bootstrapnode=1
     - POST: /isolation?ip=<IP>&port=<PORT>&exitnode=1

    These commands add a bootstrap node and an exit node respectively.
    The IP is a period-seperated string.
    An example call would be:

    curl -X POST "http://localhost:8085/isolation?ip=127.0.0.1&port=9999&bootstrapnode=1"
    """

    def __init__(self, session):
        super(IsolationEndpoint, self).__init__()
        self.session = session

    def add_exit_node(self, address):
        for overlay in self.session.overlays:
            if isinstance(overlay, TunnelCommunity):
                overlay.walk_to(address)

    def add_bootstrap_server(self, address):
        _DEFAULT_ADDRESSES.append(address)
        for overlay in self.session.overlays:
            overlay.walk_to(address)

    def render_POST(self, request):
        # Check if we have arguments, containing an address and the type of address to add.
        if not request.args or b'ip' not in request.args or b'port' not in request.args:
            request.setResponseCode(http.BAD_REQUEST)
            return self.twisted_dumps({"success": False, "error": "Parameters 'ip' and 'port' are required"})
        if b'exitnode' not in request.args and b'bootstrapnode' not in request.args:
            request.setResponseCode(http.BAD_REQUEST)
            return self.twisted_dumps({"success": False,
                                       "error": "Parameter 'exitnode' or 'bootstrapnode' is required"})
        # Attempt to decode the address
        try:
            address_str = cast_to_chr(request.args[b'ip'][0])
            port_str = cast_to_chr(request.args[b'port'][0])
            fmt_address = (address_str, int(port_str))
        except:
            import traceback
            request.setResponseCode(http.BAD_REQUEST)
            return self.twisted_dumps({"success": False, "error": traceback.format_exc()})
        # Actually add the address to the requested service
        if b'exitnode' in request.args:
            self.add_exit_node(fmt_address)
        else:
            self.add_bootstrap_server(fmt_address)
        return self.twisted_dumps({"success": True})
