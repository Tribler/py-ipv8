from __future__ import annotations

import time
from asyncio import Future, sleep
from typing import TYPE_CHECKING
from unittest.mock import Mock

from ....messaging.anonymization.community import CIRCUIT_TYPE_RP_DOWNLOADER
from ....messaging.anonymization.hidden_services import HiddenTunnelCommunity, HiddenTunnelSettings
from ....messaging.anonymization.payload import TestRequestPayload
from ....messaging.anonymization.tunnel import (
    CIRCUIT_TYPE_IP_SEEDER,
    PEER_FLAG_EXIT_BT,
    PEER_FLAG_RELAY,
    PEER_FLAG_SPEED_TEST,
    PEER_SOURCE_DHT,
    IntroductionPoint,
    RoutingObject,
)
from ....peer import Peer
from ....util import fail, succeed
from ...base import TestBase
from ...mocking.exit_socket import MockTunnelExitSocket
from ...mocking.ipv8 import MockIPv8
from .mock import global_dht_services
from .test_community import MockDHTProvider

if TYPE_CHECKING:
    from ....types import Address


class TestHiddenServices(TestBase[HiddenTunnelCommunity]):
    """
    Tests related to the HiddenTunnelCommunity.
    """

    def setUp(self) -> None:
        """
        Set up three nodes and keep track of nodes that should remain hidden from other nodes.
        """
        super().setUp()
        global_dht_services.clear()

        self.initialize(HiddenTunnelCommunity, 3)

        self.private_nodes = []
        self.service = b'0' * 20
        self.received_packets = []

    async def tearDown(self) -> None:
        """
        Make sure to also tear down our hidden nodes.
        """
        for node in self.private_nodes:
            await node.stop()
        return await super().tearDown()

    def get_e2e_circuit_path(self) -> list[tuple[Address, RoutingObject]] | None:
        """
        Return the e2e circuit information which is extracted from the nodes.
        Useful for debugging purposes or to verify whether the e2e circuit is correctly established.
        """
        path = []

        # Find the first node of the e2e circuit
        e2e_circuit = None
        first_node = None
        for node in self.nodes:
            for circuit in list(node.overlay.circuits.values()):
                if circuit.ctype == CIRCUIT_TYPE_RP_DOWNLOADER:
                    first_node = node
                    e2e_circuit = circuit
                    break

        if not e2e_circuit:
            # We didn't find any e2e circuit.
            return None

        def get_node_with_sock_addr(sock_addr: Address) -> MockIPv8 | None:
            # Utility method to quickly return a node with a specific socket address.
            for node in self.nodes:
                if node.overlay.my_peer.address == sock_addr:
                    return node
            return None

        # Add the first node to the path
        path.append((first_node.overlay.my_peer.address, e2e_circuit))

        cur_tunnel = e2e_circuit
        while True:
            next_node = get_node_with_sock_addr(cur_tunnel.hop.address)
            if cur_tunnel.circuit_id not in next_node.overlay.relay_from_to:
                # We reached the end of our e2e circuit.
                path.append((next_node.overlay.my_peer.address, cur_tunnel))
                break
            cur_tunnel = next_node.overlay.relay_from_to[cur_tunnel.circuit_id]
            path.append((next_node.overlay.my_peer.address, cur_tunnel))

        return path

    def create_node(self, settings: None = None, create_dht: bool = False, enable_statistics: bool = False) -> MockIPv8:
        """
        Initialize a HiddenTunnelCommunity without circuits or exit node functionality.
        """
        tunnel_settings = HiddenTunnelSettings()
        tunnel_settings.min_circuits = 0
        tunnel_settings.max_circuits = 0
        tunnel_settings.remove_tunnel_delay = 0
        # For some reason the exit flag set gets remembered across tests, so create a new set here
        tunnel_settings.peer_flags = {PEER_FLAG_RELAY, PEER_FLAG_SPEED_TEST}
        ipv8 = MockIPv8("curve25519", HiddenTunnelCommunity, settings=tunnel_settings)
        ipv8.overlay.ipv8 = ipv8
        ipv8.overlay.crypto_endpoint.setup_tunnels(ipv8.overlay, tunnel_settings)

        # Then kill all automated circuit creation
        ipv8.overlay.cancel_all_pending_tasks()
        # Finally, use the proper exitnode and circuit settings for manual creation
        ipv8.overlay.settings.min_circuits = 1
        ipv8.overlay.settings.max_circuits = 1
        ipv8.overlay.dht_provider = MockDHTProvider(ipv8.overlay.my_peer)
        return ipv8

    async def create_intro(self, node_nr: int, service: bytes, required_ip: Peer | None = None) -> None:
        """
        Create an 1 hop introduction point for some node for some service.
        """
        await self.overlay(node_nr).create_introduction_point(service, required_ip=required_ip)

        await self.deliver_messages()

        for node in self.nodes:
            exit_sockets = node.overlay.exit_sockets
            for circuit_id in exit_sockets:
                exit_sockets[circuit_id] = MockTunnelExitSocket(exit_sockets[circuit_id])

    async def assign_exit_node(self, node_nr: int) -> None:
        """
        Give a node a dedicated exit node to play with.
        """
        exit_node = self.create_node()
        self.private_nodes.append(exit_node)
        exit_node.overlay.settings.peer_flags.add(PEER_FLAG_EXIT_BT)
        public_peer = Peer(exit_node.my_peer.public_key, exit_node.my_peer.address)
        self.network(node_nr).add_verified_peer(public_peer)
        self.network(node_nr).discover_services(public_peer, exit_node.overlay.community_id)
        self.overlay(node_nr).candidates[public_peer] = exit_node.overlay.settings.peer_flags
        self.overlay(node_nr).build_tunnels(1)
        await self.deliver_messages()
        exit_sockets = exit_node.overlay.exit_sockets
        for exit_socket in exit_sockets:
            exit_sockets[exit_socket] = MockTunnelExitSocket(exit_sockets[exit_socket])

    async def test_create_introduction_point(self) -> None:
        """
        Check if setting up an introduction point works.
        Some node, other than the instigator, should be assigned as the intro point.
        """
        self.overlay(0).join_swarm(self.service, 1)
        await self.introduce_nodes()
        await self.create_intro(0, self.service)
        seeder_sk = self.overlay(0).swarms[self.service].seeder_sk
        seeder_pk = seeder_sk.pub().key_to_bin()

        intro_made = False
        for node_nr in range(1, len(self.nodes)):
            intro_made |= seeder_pk in self.overlay(node_nr).intro_point_for

        self.assertTrue(intro_made)

        self.overlay(0).leave_swarm(self.service)
        self.assertNotIn(self.service, self.overlay(0).swarms)
        await sleep(.1)
        self.assertFalse(self.overlay(0).find_circuits(ctype=CIRCUIT_TYPE_IP_SEEDER))

    async def test_dht_lookup_with_counterparty(self) -> None:
        """
        Check if a DHT lookup works.

        Steps:
         1. Create an introduction point
         2. Do a DHT lookup
         3. Create a rendezvous point
         4. Link the circuit e2e
         5. Callback the service handler
         6. Send data
         7. Remove circuits
        """
        future = Future()

        self.overlay(0).join_swarm(self.service, 1, future.set_result, seeding=False)
        self.overlay(2).join_swarm(self.service, 1, future.set_result)

        await self.introduce_nodes()
        await self.create_intro(2, self.service)
        await self.assign_exit_node(0)

        await self.overlay(0).do_peer_discovery()
        await self.deliver_messages()

        await future

        # Verify the length of the e2e circuit
        e2e_path = self.get_e2e_circuit_path()
        self.assertEqual(len(e2e_path), 4)

        # Check if data can be sent over the e2e circuit
        data = b'PACKET'
        _, circuit = e2e_path[0]
        self.overlay(2).on_raw_data = lambda _, __, rdata: self.received_packets.append(rdata)
        self.overlay(0).send_data(circuit.hop.address, circuit.circuit_id, ('0.0.0.0', 0), ('0.0.0.0', 0), data)
        await self.deliver_messages()
        self.assertEqual(len(self.received_packets), 1)
        self.assertEqual(self.received_packets[0], data)

        self.overlay(0).leave_swarm(self.service)
        self.assertNotIn(self.service, self.overlay(0).swarms)
        await sleep(.1)
        self.assertFalse(self.overlay(0).find_circuits(ctype=CIRCUIT_TYPE_IP_SEEDER))
        self.assertFalse(self.overlay(0).find_circuits(ctype=CIRCUIT_TYPE_RP_DOWNLOADER))

    async def test_dht_lookup_no_counterparty(self) -> None:
        """
        Check if a DHT lookup doesn't return on its own required service.
        Ergo, no self-introduction.
        """
        def callback(_: Address) -> None:
            callback.called = True

        callback.called = False

        self.overlay(0).join_swarm(self.service, 1, callback)

        await self.introduce_nodes()
        await self.assign_exit_node(0)

        await self.overlay(0).do_peer_discovery()
        await self.deliver_messages()

        self.assertFalse(callback.called)

    async def test_dht_lookup_failure(self) -> None:
        """
        Check that if a DHT lookup fails, it will retry during the next do_peer_discovery call.
        """
        self.overlay(0).join_swarm(self.service, 1, seeding=False)
        self.overlay(0).settings.swarm_lookup_interval = 0
        swarm = self.overlay(0).swarms[self.service]

        swarm.lookup_func = lambda *_: fail(RuntimeError('unit testing'))
        await self.overlay(0).do_peer_discovery()
        self.assertEqual(swarm.last_dht_response, 0)

        class FakeIP:
            def __init__(self) -> None:
                self.source = PEER_SOURCE_DHT
                self.seeder_pk = 'seeder_pk'
        swarm.lookup_func = lambda *_: succeed([FakeIP()])
        await self.overlay(0).do_peer_discovery()
        self.assertNotEqual(swarm.last_dht_response, 0)

    async def test_pex_lookup(self) -> None:
        """
        Check if peers lookups succeed through the pex communities.
        """
        # Nodes 1 and 2 are introduction points for node 0
        self.overlay(0).join_swarm(self.service, 1)
        await self.introduce_nodes()
        await self.create_intro(0, self.service, required_ip=self.peer(1))
        await self.create_intro(0, self.service, required_ip=self.peer(2))

        # Introduce nodes in the PexCommunity
        self.overlay(1).ipv8.overlays[0].walk_to(self.address(2))
        self.overlay(2).ipv8.overlays[0].walk_to(self.address(1))
        await self.deliver_messages()

        # Add node 3 to the experiment and give this node a 1 hop data circuit (to be used for get-peers messages)
        self.add_node_to_experiment(self.create_node())
        await self.assign_exit_node(3)

        # Ensure node 3 already knows node 2 (which enables PEX) and do a peers-request
        intro_point = IntroductionPoint(self.peer(2),
                                        self.overlay(0).swarms[self.service].seeder_sk.pub().key_to_bin())
        self.overlay(3).join_swarm(self.service, 1, seeding=False)
        self.overlay(3).swarms[self.service].add_intro_point(intro_point)
        self.overlay(3).swarms[self.service].last_dht_response = time.time()
        await self.overlay(3).do_peer_discovery()
        await self.deliver_messages()

        # Node 2 should be known as an introduction point
        peers = [ip.peer for ip in self.overlay(3).swarms[self.service].intro_points]
        self.assertCountEqual(peers, [self.my_peer(1), self.my_peer(2)])

    async def test_pex_lookup_exit_is_ip(self) -> None:
        """
        Check if peers lookups succeed through the pex communities if the exit is the introduction point.
        """
        # Nodes 1 and 2 are introduction points for node 0
        self.overlay(0).join_swarm(self.service, 1)
        await self.introduce_nodes()
        await self.create_intro(0, self.service, required_ip=self.peer(1))
        await self.create_intro(0, self.service, required_ip=self.peer(2))

        # Introduce nodes in the PexCommunity
        self.overlay(1).ipv8.overlays[0].walk_to(self.address(2))
        self.overlay(2).ipv8.overlays[0].walk_to(self.address(1))
        await self.deliver_messages()

        # Add node 3 to the experiment and give this node a 1 hop data circuit (to be used for get-peers messages).
        # The data circuit ends in node 1, which is also an introduction point.
        self.add_node_to_experiment(self.create_node())
        self.overlay(3).create_circuit(1, required_exit=self.peer(1))
        await self.deliver_messages()

        # Ensure node 3 already knows node 1 and do a peers-request. Since node 3 already has a data circuit
        # to node 1, it should send a cell directly to node 3.
        intro_point = IntroductionPoint(self.peer(1),
                                        self.overlay(0).swarms[self.service].seeder_sk.pub().key_to_bin())
        self.overlay(3).join_swarm(self.service, 1, seeding=False)
        self.overlay(3).swarms[self.service].add_intro_point(intro_point)
        await self.overlay(3).do_peer_discovery()
        await self.deliver_messages()

        # Node 2 should be known as an introduction point
        peers = [ip.peer for ip in self.overlay(3).swarms[self.service].intro_points]
        self.assertCountEqual(peers, [self.my_peer(1), self.my_peer(2)])

    async def test_test_request_e2e(self) -> None:
        """
        Check if sending test-request messages over an e2e circuit works as expected.
        """
        future = Future()

        self.overlay(0).join_swarm(self.service, 1, future.set_result, seeding=False)
        self.overlay(2).join_swarm(self.service, 1, future.set_result)
        self.overlay(2).settings.peer_flags.add(PEER_FLAG_SPEED_TEST)

        await self.introduce_nodes()
        await self.create_intro(2, self.service)
        await self.assign_exit_node(0)

        await self.overlay(0).do_peer_discovery()
        await self.deliver_messages()

        await future

        send_cell = Mock(wraps=self.overlay(0).send_cell)
        self.overlay(0).send_cell = send_cell
        on_test_request = Mock(wraps=self.overlay(2).on_test_request)
        self.overlay(2).decode_map_private[TestRequestPayload.msg_id] = on_test_request

        circuit, = self.overlay(0).find_circuits(ctype=CIRCUIT_TYPE_RP_DOWNLOADER)
        data, _ = await self.overlay(0).send_test_request(circuit, 3, 6)
        self.assertEqual(len(send_cell.call_args[0][1].data), 3)
        self.assertEqual(len(data), 6)
        on_test_request.assert_called_once()

        self.overlay(0).leave_swarm(self.service)
        self.overlay(2).leave_swarm(self.service)
