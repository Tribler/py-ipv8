from __future__ import absolute_import

import json

from twisted.web import http

from .formal_endpoint import FormalEndpoint
from ..messaging.anonymization.community import TunnelCommunity
from .validation.annotations import RESTOutput
from .validation.types import BOOLEAN_TYPE, NUMBER_TYPE, STR_TYPE


class TunnelEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        super(TunnelEndpoint, self).__init__()

        tunnel_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TunnelCommunity)]
        if tunnel_overlays:
            self.putChild("circuits", TunnelCircuitsEndpoint(tunnel_overlays[0]))
            self.putChild("relays", TunnelRelaysEndpoint(tunnel_overlays[0]))
            self.putChild("exits", TunnelExitsEndpoint(tunnel_overlays[0]))


class TunnelCircuitsEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for returning circuit information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelCircuitsEndpoint, self).__init__()
        self.tunnels = tunnels

    @RESTOutput(lambda request: True,
                {
                    "circuits": {
                        "circuit_id": NUMBER_TYPE,
                        "goal_hops": NUMBER_TYPE,
                        "actual_hops": NUMBER_TYPE,
                        "type": STR_TYPE["ASCII"],
                        "state": STR_TYPE["ASCII"],
                        "bytes_up": NUMBER_TYPE,
                        "bytes_down": NUMBER_TYPE
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
    def render_GET(self, request):
        if not self.tunnels:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "tunnel community not found"})

        return json.dumps({"circuits": [
            {
                "circuit_id": circuit.circuit_id,
                "goal_hops": circuit.goal_hops,
                "actual_hops": len(circuit.hops),
                "type": circuit.ctype,
                "state": circuit.state,
                "bytes_up": circuit.bytes_up,
                "bytes_down": circuit.bytes_down
            } for circuit in self.tunnels.circuits.itervalues()]})


class TunnelRelaysEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for returning relay information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelRelaysEndpoint, self).__init__()
        self.tunnels = tunnels

    @RESTOutput(lambda request: True,
                {
                    "circuits": {
                        "circuit_from": NUMBER_TYPE,
                        "circuit_to": NUMBER_TYPE,
                        "is_rendezvous": BOOLEAN_TYPE,
                        "bytes_up": NUMBER_TYPE,
                        "bytes_down": NUMBER_TYPE
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
    def render_GET(self, request):
        if not self.tunnels:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "tunnel community not found"})

        return json.dumps({"relays": [
            {
                "circuit_from": circuit_from,
                "circuit_to": relay.circuit_id,
                "is_rendezvous": relay.rendezvous_relay,
                "bytes_up": relay.bytes_up,
                "bytes_down": relay.bytes_down
            } for circuit_from, relay in self.tunnels.relay_from_to.iteritems()]})


class TunnelExitsEndpoint(FormalEndpoint):
    """
    This endpoint is responsible for returning exit socket information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelExitsEndpoint, self).__init__()
        self.tunnels = tunnels

    @RESTOutput(lambda request: True,
                {
                    "circuits": {
                        "circuit_from": NUMBER_TYPE,
                        "enabled": BOOLEAN_TYPE,
                        "bytes_up": NUMBER_TYPE,
                        "bytes_down": NUMBER_TYPE
                    }
                },
                http.OK)
    @RESTOutput(lambda request: True,
                {
                    "error": (STR_TYPE["ASCII"], "The available information in case of no success.")
                },
                http.NOT_FOUND)
    def render_GET(self, request):
        if not self.tunnels:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "tunnel community not found"})

        return json.dumps({"exits": [
            {
                "circuit_from": circuit_from,
                "enabled": exit_socket.enabled,
                "bytes_up": exit_socket.bytes_up,
                "bytes_down": exit_socket.bytes_down
            } for circuit_from, exit_socket in self.tunnels.exit_sockets.iteritems()]})
