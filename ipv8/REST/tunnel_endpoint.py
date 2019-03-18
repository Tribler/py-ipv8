from __future__ import absolute_import

import json
from binascii import hexlify

from twisted.web import http

from .base_endpoint import BaseEndpoint
from ..messaging.anonymization.community import TunnelCommunity


class TunnelEndpoint(BaseEndpoint):
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
            self.putChild("swarms", TunnelSwarmsEndpoint(tunnel_overlays[0]))


class TunnelCircuitsEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for returning circuit information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelCircuitsEndpoint, self).__init__()
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
                "verified_hops": [hexlify(hop.mid) for hop in circuit.hops],
                "unverified_hop": hexlify(circuit.unverified_hop.mid) if circuit.unverified_hop else '',
                "type": circuit.ctype,
                "state": circuit.state,
                "bytes_up": circuit.bytes_up,
                "bytes_down": circuit.bytes_down,
                "creation_time": circuit.creation_time
            } for circuit in self.tunnels.circuits.itervalues()]})


class TunnelRelaysEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for returning relay information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelRelaysEndpoint, self).__init__()
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
                "bytes_down": relay.bytes_down,
                "creation_time": relay.creation_time
            } for circuit_from, relay in self.tunnels.relay_from_to.iteritems()]})


class TunnelExitsEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for returning exit socket information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelExitsEndpoint, self).__init__()
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
                "bytes_down": exit_socket.bytes_down,
                "creation_time": exit_socket.creation_time
            } for circuit_from, exit_socket in self.tunnels.exit_sockets.iteritems()]})


class TunnelSwarmsEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for returning hidden swarm information from the TunnelCommunity.
    """

    def __init__(self, tunnels):
        super(TunnelSwarmsEndpoint, self).__init__()
        self.tunnels = tunnels

    def render_GET(self, request):
        if not self.tunnels:
            request.setResponseCode(http.NOT_FOUND)
            return json.dumps({"error": "tunnel community not found"})

        return json.dumps({"swarms": [
            {
                "info_hash": hexlify(swarm.info_hash),
                "num_seeders": swarm.get_num_seeders(),
                "num_connections": swarm.get_num_connections(),
                "num_connections_incomplete": swarm.get_num_connections_incomplete(),
                "seeding": swarm.seeding,
                "last_lookup": swarm.last_lookup
            } for swarm in self.tunnels.swarms.values()]})
