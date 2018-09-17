from __future__ import absolute_import

import json

from twisted.web import http, resource

from ..messaging.anonymization.community import TunnelCommunity


class TunnelEndpoint(resource.Resource):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self, session):
        resource.Resource.__init__(self)

        tunnel_overlays = [overlay for overlay in session.overlays if isinstance(overlay, TunnelCommunity)]
        if tunnel_overlays:
            self.putChild("circuits", TunnelCircuitsEndpoint(tunnel_overlays[0]))
            self.putChild("relays", TunnelRelaysEndpoint(tunnel_overlays[0]))
            self.putChild("exits", TunnelExitsEndpoint(tunnel_overlays[0]))


class TunnelCircuitsEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning circuit information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        resource.Resource.__init__(self)
        self.tunnels = tunnels

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


class TunnelRelaysEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning relay information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        resource.Resource.__init__(self)
        self.tunnels = tunnels

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


class TunnelExitsEndpoint(resource.Resource):
    """
    This endpoint is responsible for returning exit socket information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        resource.Resource.__init__(self)
        self.tunnels = tunnels

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
