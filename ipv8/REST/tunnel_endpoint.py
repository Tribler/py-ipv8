from __future__ import annotations

from binascii import hexlify, unhexlify
from typing import TYPE_CHECKING, cast

from aiohttp import web
from aiohttp_apispec import docs, json_schema
from marshmallow.fields import Boolean, Float, Integer, List, String

from ..dht.provider import DHTCommunityProvider, DHTIntroPointPayload
from ..messaging.anonymization.community import (
    CIRCUIT_STATE_READY,
    CIRCUIT_TYPE_DATA,
    PEER_FLAG_SPEED_TEST,
    PEER_SOURCE_DHT,
    PEER_SOURCE_PEX,
    IntroductionPoint,
    TunnelCommunity,
)
from ..messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ..messaging.anonymization.tunnel import FORWARD
from ..messaging.anonymization.utils import run_speed_test
from ..messaging.serialization import PackError
from ..peer import Peer
from ..types import IPv8
from .base_endpoint import HTTP_BAD_REQUEST, HTTP_INTERNAL_SERVER_ERROR, HTTP_NOT_FOUND, BaseEndpoint, Response
from .schema import AddressWithPK, schema

if TYPE_CHECKING:
    from aiohttp.abc import Request

    from ..messaging.anonymization.tunnel import Circuit

SpeedTestResponseSchema = schema(SpeedTestResponse={
    "speed": (Float, 'Speed in MiB/s'),
    "messages_sent": Integer,
    "messages_received": Integer,
    "rtt_mean": Float,
    "rtt_median": Float
})


class TunnelEndpoint(BaseEndpoint[IPv8]):
    """
    This endpoint is responsible for handling requests for DHT data.
    """

    def __init__(self) -> None:
        """
        Create new unregistered and uninitialized REST endpoint.
        """
        super().__init__()
        self.tunnels: TunnelCommunity | None = None

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """
        self.app.add_routes([web.get('/settings', self.get_settings),
                             web.get('/circuits', self.get_circuits),
                             web.post('/circuits/test', self.speed_test_new_circuit),
                             web.post('/circuits/{circuit_id}/test', self.speed_test_existing_circuit),
                             web.get('/relays', self.get_relays),
                             web.get('/exits', self.get_exits),
                             web.get('/swarms', self.get_swarms),
                             web.get('/swarms/{infohash}/size', self.get_swarm_size),
                             web.get('/peers', self.get_peers),
                             web.get('/peers/dht', self.get_dht_peers),
                             web.get('/peers/pex', self.get_pex_peers)])

    def initialize(self, session: IPv8) -> None:
        """
        Initialize this endpoint for the given session instance.
        """
        super().initialize(session)
        self.tunnels = session.get_overlay(TunnelCommunity)

    @docs(
        tags=["Tunnels"],
        summary="Return a dictionary of all tunnel settings.",
        responses={
            200: {
                "schema": schema(TunnelSettingsResponse={
                    "settings": [schema(TunnelSettings={})]
                })
            }
        }
    )
    def get_settings(self, _: Request) -> Response:
        """
        Return a dictionary of all tunnel settings.
        """
        if self.tunnels is None:
            return Response({"settings": {}})
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        settings: dict[str, str | int | list] = {}
        for name in dir(self.tunnels.settings):
            if name.startswith('__'):
                continue
            key = name.lstrip('_')
            value = getattr(self.tunnels.settings, name)
            if isinstance(value, (str, int)):
                settings[key] = value
            elif isinstance(value, (set, list, tuple)):
                settings[key] = list(value)

        return Response({'settings': settings})

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
    async def get_circuits(self, _: Request) -> Response:
        """
        Return a list of all current circuits.
        """
        if self.tunnels is None:
            return Response({"circuits": []})
        self.tunnels = cast(TunnelCommunity, self.tunnels)

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
        }],
        responses={
            200: {"schema": SpeedTestResponseSchema}
        }
    )
    @json_schema(schema(SpeedTestExistingCircuitRequest={
        'request_size*': (Integer, 'Size of the requests to send (0..2000)'),
        'response_size*': (Integer, 'Size of the responses to send (0..2000)'),
        'num_requests*': (Integer, 'Number of packets to send'),
    }))
    async def speed_test_existing_circuit(self, request: Request) -> Response:
        """
        Test the upload or download speed of a circuit.
        """
        if not request.match_info['circuit_id'].isdigit():
            return Response({"error": "circuit_id must be an integer"}, status=HTTP_BAD_REQUEST)
        if self.tunnels is None:
            return Response({"error": "TunnelCommunity is not initialized"}, status=HTTP_NOT_FOUND)
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        circuit = self.tunnels.circuits.get(int(request.match_info['circuit_id']))
        if not circuit:
            return Response({"error": "could not find requested circuit"}, status=HTTP_NOT_FOUND)
        if circuit.state != CIRCUIT_STATE_READY:
            return Response({"error": "the requested circuit is not ready to transfer data"}, status=HTTP_BAD_REQUEST)
        if circuit.ctype == CIRCUIT_TYPE_DATA and PEER_FLAG_SPEED_TEST not in circuit.exit_flags:
            return Response({"error": "the requested circuit does not support speed testing"}, status=HTTP_BAD_REQUEST)
        return await self.run_speed_test(circuit, (await request.json()))

    @docs(
        tags=["Tunnels"],
        summary="Test the upload or download speed of a newly created circuit. "
                "The circuit is destroyed after the test has completed.",
        responses={
            200: {"schema": SpeedTestResponseSchema}
        }
    )
    @json_schema(schema(SpeedTestNewCircuitRequest={
        'goals_hops': (Integer, 'Number of hops that the newly created circuit should have'),
        'request_size*': (Integer, 'Size of the requests to send (0..2000)'),
        'response_size*': (Integer, 'Size of the responses to send (0..2000)'),
        'num_requests*': (Integer, 'Number of packets to send'),
    }))
    async def speed_test_new_circuit(self, request: Request) -> Response:
        """
        Test the upload or download speed of a newly created circuit.
        The circuit is destroyed after the test has completed.
        """
        if self.tunnels is None:
            return Response({"error": "TunnelCommunity is not initialized"}, status=HTTP_NOT_FOUND)
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        params = await request.json()

        goal_hops = params.get('goal_hops', 1)
        if not 1 <= goal_hops <= 3:
            return Response({"error": "invalid number of hops specified"}, status=HTTP_BAD_REQUEST)

        circuit = self.tunnels.create_circuit(goal_hops, ctype='SPEED_TEST', exit_flags=(PEER_FLAG_SPEED_TEST,))
        if not circuit or not await circuit.ready:
            return Response({"error": "failed to create circuit"}, status=HTTP_INTERNAL_SERVER_ERROR)

        result = await self.run_speed_test(circuit, params)
        await self.tunnels.remove_circuit(circuit.circuit_id, additional_info='speed test finished')
        return result

    async def run_speed_test(self, circuit: Circuit, params: dict) -> Response:
        """
        Run a speed test on the given circuit and form an HTTP response.
        """
        if self.tunnels is None:
            return Response({"error": "TunnelCommunity is not initialized"}, status=HTTP_NOT_FOUND)
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        if not 0 <= params.get('request_size', -1) <= 2000 or not 0 <= params.get('response_size', -1) <= 2000:
            return Response({"error": "invalid request or response size specified"}, status=HTTP_BAD_REQUEST)
        if 'num_requests' not in params:
            return Response({"error": "number of requests is not specified"}, status=HTTP_BAD_REQUEST)
        return Response(await run_speed_test(self.tunnels, circuit,
                                             params['request_size'], params['response_size'], params['num_requests']))

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
                        "direction": String,
                        "bytes_up": Integer,
                        "bytes_down": Integer,
                        "creation_time": Integer
                    })]
                })
            }
        }
    )
    async def get_relays(self, _: Request) -> Response:
        """
        Return a list of all current relays.
        """
        if self.tunnels is None:
            return Response({"relays": []})
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        return Response({"relays": [{
            "circuit_from": circuit_from,
            "circuit_to": relay.circuit_id,
            "is_rendezvous": relay.rendezvous_relay,
            "direction": "forward" if relay.direction == FORWARD else "backward",
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
    async def get_exits(self, _: Request) -> Response:
        """
        Return a list of all current exits.
        """
        if self.tunnels is None or not isinstance(self.tunnels, HiddenTunnelCommunity):
            return Response({"exits": []})
        self.tunnels = cast(HiddenTunnelCommunity, self.tunnels)

        return Response({"exits": [{
            "circuit_from": circuit_from,
            "enabled": exit_sock.enabled,
            "bytes_up": exit_sock.bytes_up,
            "bytes_down": exit_sock.bytes_down,
            "creation_time": exit_sock.creation_time,
            "is_introduction": exit_sock.circuit_id in [c.circuit_id for c, _ in self.tunnels.intro_point_for.values()],
            "is_rendezvous": exit_sock.circuit_id in [c.circuit_id for c in self.tunnels.rendezvous_point_for.values()]
        } for circuit_from, exit_sock in self.tunnels.exit_sockets.items()]})

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
    async def get_swarms(self, _: Request) -> Response:
        """
        Return a list of all current hidden swarms.
        """
        if self.tunnels is None or not isinstance(self.tunnels, HiddenTunnelCommunity):
            return Response({"swarms": []})
        self.tunnels = cast(HiddenTunnelCommunity, self.tunnels)

        return Response({"swarms": [{
            "info_hash": hexlify(swarm.info_hash).decode('utf-8'),
            "num_seeders": swarm.get_num_seeders(),
            "num_connections": swarm.get_num_connections(),
            "num_connections_incomplete": swarm.get_num_connections_incomplete(),
            "num_ips_from_dht": len([ip for ip in swarm.intro_points if ip.source == PEER_SOURCE_DHT]),
            "num_ips_from_pex": len([ip for ip in swarm.intro_points if ip.source == PEER_SOURCE_PEX]),
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
    async def get_swarm_size(self, request: Request) -> Response:
        """
        Estimate the hidden swarm size for a given infohash.
        """
        if self.tunnels is None or not isinstance(self.tunnels, HiddenTunnelCommunity):
            return Response({"swarms": []})
        self.tunnels = cast(HiddenTunnelCommunity, self.tunnels)

        infohash = unhexlify(request.match_info['infohash'])
        swarm_size = await self.tunnels.estimate_swarm_size(infohash, hops=cast(int, request.query.get('hops', 1)))
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
    async def get_peers(self, _: Request) -> Response:
        """
        Return a list of all peers currently part of the tunnel community.
        """
        if self.tunnels is None:
            return Response({"peers": []})
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        return Response({"peers": [{
            "ip": peer.address[0],
            "port": peer.address[1],
            "mid": hexlify(peer.mid).decode('utf-8'),
            "is_key_compatible": self.tunnels.crypto.is_key_compatible(peer.public_key),
            "flags": flags
        } for peer, flags in self.tunnels.candidates.items()]})

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all hidden services peers that are in the local DHT store.",
        responses={
            200: {
                "schema": schema(TunnelDHTPeersResponse={
                    "peers": [AddressWithPK]
                })
            }
        }
    )
    async def get_dht_peers(self, _: Request) -> Response:
        """
        Return a list of all hidden services peers that are in the local DHT store.
        """
        if self.tunnels is None or self.tunnels.dht_provider is None:
            return Response([])
        self.tunnels = cast(TunnelCommunity, self.tunnels)

        dht = cast(DHTCommunityProvider, self.tunnels.dht_provider).dht_community
        ips_by_infohash: dict[bytes, list[IntroductionPoint]] = {}
        for storage in dht.storages.values():
            for key, raw_values in storage.items.items():
                ips_by_infohash[key] = []
                for value in dht.post_process_values([v.data for v in raw_values]):
                    try:
                        payload, __ = dht.serializer.unpack_serializable(DHTIntroPointPayload, value[0])
                    except PackError:
                        continue
                    peer = Peer(b'LibNaCLPK:' + payload.intro_pk, payload.address)
                    ip = IntroductionPoint(peer, b'LibNaCLPK:' + payload.seeder_pk, PEER_SOURCE_DHT, payload.last_seen)
                    ips_by_infohash[key].append(ip)

        return Response([{'info_hash': hexlify(h).decode(),
                          'peers': [i.to_dict() for i in ips]} for h, ips in ips_by_infohash.items()])

    @docs(
        tags=["Tunnels"],
        summary="Return a list of all hidden services peers that are in the local PEX store.",
        responses={
            200: {
                "schema": schema(TunnelPEXPeersResponse={
                    "peers": [AddressWithPK]
                })
            }
        }
    )
    async def get_pex_peers(self, _: Request) -> Response:
        """
        Return a list of all hidden services peers that are in the local PEX store.
        """
        if self.tunnels is None or not isinstance(self.tunnels, HiddenTunnelCommunity):
            return Response([])
        self.tunnels = cast(HiddenTunnelCommunity, self.tunnels)

        return Response([{'info_hash': hexlify(h).decode(),
                          'peers': [i.to_dict() for i in c.get_intro_points()]} for h, c in self.tunnels.pex.items()])
