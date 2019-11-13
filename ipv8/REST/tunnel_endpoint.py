from binascii import hexlify

from aiohttp import web

from aiohttp_apispec import docs

from marshmallow.fields import Boolean, Integer, List, String

from .base_endpoint import BaseEndpoint, Response
from .schema import schema
from ..messaging.anonymization.community import TunnelCommunity


class TunnelEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self):
        super(TunnelEndpoint, self).__init__()
        self.tunnels = None

    def setup_routes(self):
        self.app.add_routes([web.get('/circuits', self.get_circuits),
                             web.get('/relays', self.get_relays),
                             web.get('/exits', self.get_exits),
                             web.get('/swarms', self.get_swarms)])

    def initialize(self, session):
        super(TunnelEndpoint, self).initialize(session)
        self.tunnels = next((o for o in session.overlays if isinstance(o, TunnelCommunity)), None)

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all current circuits.",
        responses={
            200: {
                "schema": schema(CircuitsResponse={
                    "circuits": [schema(Circuit={
                        "circuit_id": Integer,
                        "goal_hops": Integer,
                        "actual_hops": Integer,
                        "verified_hops": List(String),
                        "unverified_hop": List(String),
                        "type": String,
                        "state": String,
                        "bytes_up": Integer,
                        "bytes_down": Integer,
                        "creation_time": Integer
                    })]
                })
            }
        }
    )
    async def get_circuits(self, _):
        return Response({"circuits": [{
            "circuit_id": circuit.circuit_id,
            "goal_hops": circuit.goal_hops,
            "actual_hops": len(circuit.hops),
            "verified_hops": [hexlify(hop.mid).decode('utf-8') for hop in circuit.hops],
            "unverified_hop": hexlify(circuit.unverified_hop.mid).decode('utf-8') if circuit.unverified_hop else '',
            "type": circuit.ctype,
            "state": circuit.state,
            "bytes_up": circuit.bytes_up,
            "bytes_down": circuit.bytes_down,
            "creation_time": circuit.creation_time
        } for circuit in self.tunnels.circuits.values()]})

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all current relays.",
        responses={
            200: {
                "schema": schema(RelaysResponse={
                    "relays": [schema(Relay={
                        "circuit_from": Integer,
                        "circuit_to": Integer,
                        "is_rendezvous": Boolean,
                        "bytes_up": Integer,
                        "bytes_down": Integer,
                        "creation_time": Integer
                    })]
                })
            }
        }
    )
    async def get_relays(self, _):
        return Response({"relays": [{
            "circuit_from": circuit_from,
            "circuit_to": relay.circuit_id,
            "is_rendezvous": relay.rendezvous_relay,
            "bytes_up": relay.bytes_up,
            "bytes_down": relay.bytes_down,
            "creation_time": relay.creation_time
        } for circuit_from, relay in self.tunnels.relay_from_to.items()]})

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all current exits.",
        responses={
            200: {
                "schema": schema(ExitsResponse={
                    "exits": [schema(Exit={
                        "circuit_from": Integer,
                        "enabled": Boolean,
                        "bytes_up": Integer,
                        "bytes_down": Integer,
                        "creation_time": Integer
                    })]
                })
            }
        }
    )
    async def get_exits(self, _):
        return Response({"exits": [{
            "circuit_from": circuit_from,
            "enabled": exit_socket.enabled,
            "bytes_up": exit_socket.bytes_up,
            "bytes_down": exit_socket.bytes_down,
            "creation_time": exit_socket.creation_time
        } for circuit_from, exit_socket in self.tunnels.exit_sockets.items()]})

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all current hidden swarms.",
        responses={
            200: {
                "schema": schema(SwarmsResponse={
                    "swarms": [schema(Swarm={
                        "info_hash": String,
                        "num_seeders": Integer,
                        "num_connections": Integer,
                        "num_connections_incomplete": Integer,
                        "seeding": Boolean,
                        "last_lookup": Integer,
                        "bytes_up": Integer,
                        "bytes_down": Integer
                    })]
                })
            }
        }
    )
    async def get_swarms(self, _):
        return Response({"swarms": [{
            "info_hash": hexlify(swarm.info_hash).decode('utf-8'),
            "num_seeders": swarm.get_num_seeders(),
            "num_connections": swarm.get_num_connections(),
            "num_connections_incomplete": swarm.get_num_connections_incomplete(),
            "seeding": swarm.seeding,
            "last_lookup": swarm.last_lookup,
            "bytes_up": swarm.get_total_up(),
            "bytes_down": swarm.get_total_down()
        } for swarm in self.tunnels.swarms.values()]})
