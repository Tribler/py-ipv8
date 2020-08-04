from asyncio import FIRST_COMPLETED, wait
from binascii import hexlify, unhexlify
from statistics import mean, median
from timeit import default_timer

from aiohttp import web

from aiohttp_apispec import docs

from marshmallow.fields import Boolean, Float, Integer, List, String

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_INTERNAL_SERVER_ERROR, HTTP_NOT_FOUND, Response
from .schema import schema
from ..messaging.anonymization.community import (CIRCUIT_STATE_READY, CIRCUIT_TYPE_DATA,
                                                 PEER_FLAG_SPEED_TEST, TunnelCommunity)


SpeedTestResponseSchema = schema(SpeedTestResponse={
    "speed": (Float, 'Speed in MiB/s'),
    "messages_sent": Integer,
    "messages_received": Integer,
    "rtt_mean": Float,
    "rtt_median": Float
})


class TunnelEndpoint(BaseEndpoint):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self):
        super(TunnelEndpoint, self).__init__()
        self.tunnels = None

    def setup_routes(self):
        self.app.add_routes([web.get('/circuits', self.get_circuits),
                             web.get('/circuits/test', self.speed_test_new_circuit),
                             web.get('/circuits/{circuit_id}/test', self.speed_test_existing_circuit),
                             web.get('/relays', self.get_relays),
                             web.get('/exits', self.get_exits),
                             web.get('/swarms', self.get_swarms),
                             web.get('/swarms/{infohash}/size', self.get_swarm_size),
                             web.get('/peers', self.get_peers)])

    def initialize(self, session):
        super(TunnelEndpoint, self).initialize(session)
        self.tunnels = session.get_overlay(TunnelCommunity)

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
            "state": f'{circuit.state} ({circuit.closing_info})' if circuit.closing_info else circuit.state,
            "bytes_up": circuit.bytes_up,
            "bytes_down": circuit.bytes_down,
            "creation_time": circuit.creation_time,
            "exit_flags": circuit.exit_flags
        } for circuit in self.tunnels.circuits.values()]})

    @docs(
        tags=["Tunnels"],
        summary="Test the upload or download speed of a circuit.",
        parameters=[{
            'in': 'path',
            'name': 'circuit_id',
            'description': 'The circuit_id of the circuit which is to be tested.',
            'type': 'integer',
        }, {
            'in': 'query',
            'name': 'direction',
            'description': 'The direction for which to test the speed.',
            'type': 'string',
            'enum': ['upload', 'download'],
            'default': 'download'
        }],
        responses={
            200: {"schema": SpeedTestResponseSchema}
        }
    )
    async def speed_test_existing_circuit(self, request):
        if not request.match_info['circuit_id'].isdigit():
            return Response({"error": "circuit_id must be an integer"}, status=HTTP_BAD_REQUEST)

        circuit = self.tunnels.circuits.get(int(request.match_info['circuit_id']))
        if not circuit:
            return Response({"error": "could not find requested circuit"}, status=HTTP_NOT_FOUND)
        if circuit.state != CIRCUIT_STATE_READY:
            return Response({"error": "the requested circuit is not ready to transfer data"}, status=HTTP_BAD_REQUEST)
        if circuit.ctype == CIRCUIT_TYPE_DATA and PEER_FLAG_SPEED_TEST not in circuit.exit_flags:
            return Response({"error": "the requested circuit does not support speed testing"}, status=HTTP_BAD_REQUEST)
        return await self.run_speed_test(request, circuit)

    @docs(
        tags=["Tunnels"],
        summary="Test the upload or download speed of a newly created circuit. "
                "The circuit is destroyed after the test has completed.",
        parameters=[{
            'in': 'query',
            'name': 'direction',
            'description': 'The direction for which to test the speed.',
            'type': 'string',
            'enum': ['upload', 'download'],
            'default': 'download'
        }, {
            'in': 'query',
            'name': 'goal_hops',
            'description': 'The hop count for the circuit that is to be created.',
            'type': 'integer',
            'default': 1
        }],
        responses={
            200: {"schema": SpeedTestResponseSchema}
        }
    )
    async def speed_test_new_circuit(self, request):
        if 'goal_hops' in request.query and not request.query['goal_hops'].isdigit():
            return Response({"error": "goal_hops must be an integer"}, status=HTTP_BAD_REQUEST)

        goal_hops = int(request.query.get('goal_hops', 1))
        circuit = self.tunnels.create_circuit(goal_hops, ctype='SPEED_TEST', exit_flags=(PEER_FLAG_SPEED_TEST,))
        if not circuit or not await circuit.ready:
            return Response({"error": "failed to create circuit"}, status=HTTP_INTERNAL_SERVER_ERROR)
        result = await self.run_speed_test(request, circuit)
        self.tunnels.remove_circuit(circuit.circuit_id, additional_info='speed test finished')
        return result

    async def run_speed_test(self, request, circuit):
        direction = request.query.get('direction', 'download')
        if direction not in ['upload', 'download']:
            return Response({"error": "invalid direction specified"}, status=HTTP_BAD_REQUEST)

        request_size = 0 if direction == 'download' else 1024
        response_size = 1024 if direction == 'download' else 0
        # Transfer 30 * 1024 * 1024 = 30MB for download a download test, and 15MB for
        # a upload test (excluding protocol overhead).
        num_packets = 30 * 1024 if direction == 'download' else 15 * 1024
        num_sent = 0
        num_ack = 0
        window = 50
        outstanding = set()
        start = default_timer()
        rtts = []

        while True:
            while num_sent < num_packets and len(outstanding) < window:
                outstanding.add(self.tunnels.send_test_request(circuit, request_size, response_size))
                num_sent += 1
            if not outstanding:
                break
            done, outstanding = await wait(outstanding, return_when=FIRST_COMPLETED, timeout=3)
            if not done and num_ack > 0.95 * num_packets:
                # We have received nothing for the past 3s and did get an acknowledgement for 95%
                # of our requests. To avoid waiting for packets that may never arrive we stop the
                # test. Any pending messages are considered lost.
                break
            # Make sure to only count futures that haven't been set by on_timeout.
            results = [f.result() for f in done if f.result() is not None]
            num_ack += len(results)
            rtts.extend([rtt for _, rtt in results])

        return Response({'speed': (num_ack / 1024) / (default_timer() - start),
                         'messages_sent': num_ack + len(outstanding),
                         'messages_received': num_ack,
                         'rtt_mean': mean(rtts),
                         'rtt_median': median(rtts)})

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

    @docs(
        tags=["Tunnels"],
        summary="Estimate the hidden swarm size for a given infohash.",
        parameters=[{
            'in': 'path',
            'name': 'infohash',
            'description': 'Infohash of the swarm for which to estimate the size.',
            'type': 'string',
            'required': True
        }],
        responses={
            200: {
                "schema": schema(SwarmsSizeResponse={
                    "swarm_size": Integer
                })
            }
        }
    )
    async def get_swarm_size(self, request):
        infohash = unhexlify(request.match_info['infohash'])
        swarm_size = await self.tunnels.estimate_swarm_size(infohash, hops=request.query.get('hops', 1))
        return Response({"swarm_size": swarm_size})

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all peers currently part of the tunnel community.",
        responses={
            200: {
                "schema": schema(TunnelPeersResponse={
                    "peers": [schema(TunnelPeer={
                        "ip": String,
                        "port": Integer,
                        "mid": String,
                        "is_key_compatible": Boolean,
                        "flags": List(Integer),
                    })]
                })
            }
        }
    )
    async def get_peers(self, _):
        return Response({"peers": [{
            "ip": peer.address[0],
            "port": peer.address[1],
            "mid": hexlify(peer.mid).decode('utf-8'),
            "is_key_compatible": self.tunnels.crypto.is_key_compatible(peer.public_key),
            "flags": flags
        } for peer, flags in self.tunnels.candidates.items()]})
