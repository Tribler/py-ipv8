from asyncio import Future
from unittest.mock import Mock

from .mock import MockDHTProvider
from ...base import TestBase
from ...mocking.endpoint import MockEndpointListener
from ...mocking.exit_socket import MockTunnelExitSocket
from ...mocking.ipv8 import MockIPv8
from ....messaging.anonymization.community import TunnelCommunity, TunnelSettings
from ....messaging.anonymization.endpoint import TunnelEndpoint
from ....messaging.anonymization.tunnel import (CIRCUIT_STATE_EXTENDING, PEER_FLAG_EXIT_BT,
                                                PEER_FLAG_EXIT_IPV8, PEER_FLAG_SPEED_TEST)
from ....messaging.interfaces.udp.endpoint import DomainAddress, UDPEndpoint
from ....util import succeed


class TestTunnelCommunity(TestBase):

    def setUp(self):
        super(TestTunnelCommunity, self).setUp()
        self.initialize(TunnelCommunity, 2)

        # An actual UDPEndpoint, if needed by the test (for catching exited data)
        self.public_endpoint = None

    async def tearDown(self):
        # If an endpoint was used, close it
        if self.public_endpoint:
            self.public_endpoint.close()

        return await super(TestTunnelCommunity, self).tearDown()

    def create_node(self):
        # Initialize a TunnelCommunity without circuits or exit node functionality
        settings = TunnelSettings()
        settings.min_circuits = 0
        settings.max_circuits = 0
        settings.remove_tunnel_delay = 0
        ipv8 = MockIPv8(u"curve25519", TunnelCommunity, settings=settings)
        # Then kill all automated circuit creation
        ipv8.overlay.cancel_all_pending_tasks()
        # Finally, use the proper exitnode and circuit settings for manual creation
        ipv8.overlay.settings.min_circuits = 1
        ipv8.overlay.settings.max_circuits = 1
        ipv8.overlay.dht_provider = MockDHTProvider(ipv8.overlay.my_peer)
        return ipv8

    def assert_no_more_tunnels(self):
        """
        Utility method to check whether there are no more tunnels left
        """
        for node in self.nodes:
            self.assertFalse(node.overlay.exit_sockets)
            self.assertFalse(node.overlay.relay_from_to)
            self.assertFalse(node.overlay.circuits)

    def settings(self, i):
        return self.overlay(i).settings

    async def test_introduction_as_exit(self):
        """
        Check if introduction requests share the fact that nodes are exit nodes.
        """
        self.overlay(0).settings.peer_flags.add(PEER_FLAG_EXIT_BT)

        await self.introduce_nodes()

        self.assertIn(self.my_peer(0), self.overlay(1).get_candidates(PEER_FLAG_EXIT_BT))
        self.assertNotIn(self.my_peer(1), self.overlay(0).get_candidates(PEER_FLAG_EXIT_BT))

    async def test_introduction_as_exit_twoway(self):
        """
        Check if two nodes can have each other as exit nodes.
        """
        self.settings(0).peer_flags.add(PEER_FLAG_EXIT_BT)
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)

        await self.introduce_nodes()

        self.assertIn(self.my_peer(0), self.overlay(1).get_candidates(PEER_FLAG_EXIT_BT))
        self.assertIn(self.my_peer(1), self.overlay(0).get_candidates(PEER_FLAG_EXIT_BT))

    async def test_introduction_as_exit_noway(self):
        """
        Check if two nodes don't advertise themselves as exit node incorrectly.
        """
        await self.introduce_nodes()

        self.assertEqual(len(self.overlay(0).get_candidates(PEER_FLAG_EXIT_BT)), 0)
        self.assertEqual(len(self.overlay(1).get_candidates(PEER_FLAG_EXIT_BT)), 0)

    async def test_create_circuit(self):
        """
        Check if 1 hop circuit creation works.
        """
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 1)
        # It should use node 1 for this
        self.overlay(0).build_tunnels(1)

        # Let the circuit creation commence
        await self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.overlay(0).tunnels_ready(1), 1.0)
        # Node 1 has an exit socket open
        self.assertEqual(len(self.overlay(1).exit_sockets), 1)

    async def test_create_circuit_no_exit(self):
        """
        Check if 1 hop circuit creation fails without exit nodes.
        """
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(1)

        # Attempt circuit creation
        await self.deliver_messages()

        # Node 0 should now have no 1 hop circuits (0.0/0%)
        self.assertEqual(self.overlay(0).tunnels_ready(1), 0.0)
        # Node 1 should not have an exit socket open
        self.assertEqual(len(self.overlay(1).exit_sockets), 0)

    async def test_create_circuit_too_many_hops(self):
        """
        Check if creating a circuit that is too long fails.
        """
        for _ in range(3):
            self.add_node_to_experiment(self.create_node())
        for node in self.nodes:
            node.overlay.settings.max_relay_early = 3

        self.overlay(1).settings.peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(5)

        await self.deliver_messages()

        self.assertEqual(self.overlay(0).tunnels_ready(5), 0.0)

    async def test_create_circuit_relay_early_fail_hop1(self):
        """
        Check if extending a circuit using a cell with a bad relay_early flag fails at the first hop.
        """
        self.add_node_to_experiment(self.create_node())
        for node in self.nodes:
            node.overlay.settings.max_relay_early = 0

        self.overlay(1).settings.peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()

        self.overlay(0).settings.max_relay_early = 2
        self.overlay(0).build_tunnels(2)

        await self.deliver_messages()

        self.assertEqual(self.overlay(0).tunnels_ready(2), 0.0)

    async def test_create_circuit_relay_early_fail_hop2(self):
        """
        Check if extending a circuit using a cell with a bad relay_early flag fails at the second hop.
        """
        for _ in range(2):
            self.add_node_to_experiment(self.create_node())
        for node in self.nodes:
            node.overlay.settings.max_relay_early = 1

        self.overlay(1).settings.peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()

        self.overlay(0).settings.max_relay_early = 2
        self.overlay(0).build_tunnels(3)

        await self.deliver_messages()

        self.assertEqual(self.overlay(0).tunnels_ready(3), 0.0)

    async def test_create_circuit_multiple_calls(self):
        """
        Check if circuit creation is aborted when it's already building the requested circuit.
        """
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()

        # Don't allow the exit node to answer, this keeps peer 0's circuit in EXTENDING state
        self.endpoint(1).close()
        self.overlay(0).build_tunnels(1)

        # Node 0 should have 1 circuit in the CIRCUIT_STATE_EXTENDING state
        self.assertEqual(len(self.overlay(0).find_circuits(state=CIRCUIT_STATE_EXTENDING)), 1)

        # Subsequent calls to build_circuits should not change this
        self.overlay(0).build_tunnels(1)
        self.assertEqual(len(self.overlay(0).find_circuits(state=CIRCUIT_STATE_EXTENDING)), 1)

    async def test_destroy_circuit_from_originator(self):
        """
        Check if a 2 hop circuit can be destroyed (by the exit node)
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        # Destroy the circuit we just created using a destroy message
        await self.overlay(0).remove_circuit(list(self.overlay(0).circuits.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_from_exit(self):
        """
        Check if a 2 hop circuit can be destroyed (by the exit node)
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        await self.overlay(2).remove_exit_socket(list(self.overlay(2).exit_sockets.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_from_relay(self):
        """
        Check if a 2 hop circuit can be destroyed (by the relay node)
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        self.overlay(1).remove_relay(list(self.overlay(1).relay_from_to.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_bad_id(self):
        """
        Check if the correct circuit gets destroyed.
        """
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(1)
        await self.deliver_messages()

        # Destroy a circuit which does not exist (circuit_id + 1)
        # This should not affect other circuits
        await self.overlay(0).remove_circuit(list(self.overlay(0).circuits.keys())[0] + 1, destroy=1)
        await self.deliver_messages()

        # Node 0 should still have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.overlay(0).tunnels_ready(1), 1.0)
        # Node 1 still has an exit socket open
        self.assertEqual(len(self.overlay(1).exit_sockets), 1)

    async def test_tunnel_data(self):
        """
        Check if data is correctly exited.
        """
        # Listen in on communication of the target
        self.public_endpoint = UDPEndpoint()
        await self.public_endpoint.open()
        ep_listener = MockEndpointListener(self.public_endpoint)

        # Build a tunnel
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(1)
        await self.deliver_messages()

        # Construct a data packet
        prefix = b'\x00' * 23
        data = prefix + bytes(range(256))

        self.public_endpoint.assert_open()

        # Tunnel the data to the endpoint
        circuit = list(self.overlay(0).circuits.values())[0]
        self.overlay(0).send_data(circuit.peer, circuit.circuit_id,
                                  DomainAddress('localhost', self.public_endpoint.get_address()[1]),
                                  ('0.0.0.0', 0), data)

        future = Future()
        ep_listener.on_packet = lambda packet: ep_listener.received_packets.append(packet) or future.set_result(None)
        await future

        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], data)

    async def test_two_hop_circuit(self):
        """
        Check if a two hop circuit is correctly created.

        Note that we avoid exit nodes in the relay path, so we explicitly set relay nodes to not be exits.
        """
        self.add_node_to_experiment(self.create_node())

        # Build a tunnel
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        self.assertEqual(self.overlay(0).tunnels_ready(2), 1.0)

    async def test_three_hop_circuit(self):
        """
        Check if a three hop circuit is correctly created.

        Note that we avoid exit nodes in the relay path, so we explicitly set relay nodes to not be exits.
        """
        self.add_node_to_experiment(self.create_node())
        self.add_node_to_experiment(self.create_node())

        # Build a tunnel
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(3)
        await self.deliver_messages()

        self.assertEqual(self.overlay(0).tunnels_ready(3), 1.0)

    async def test_create_two_circuit(self):
        """
        Check if multiple 1 hop circuit creation works.
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(0).min_circuits = 2
        self.settings(0).max_circuits = 2
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 2)
        # It should use node 1 and 2 for this
        self.overlay(0).build_tunnels(1)

        # Let the circuit creation commence
        await self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.overlay(0).tunnels_ready(1), 1.0)
        self.assertEqual(len(self.overlay(0).circuits), 2)
        # Two exit sockets are open between node 1 and 2 (NOT evenly spread)
        self.assertEqual(len(self.overlay(1).exit_sockets) + len(self.overlay(2).exit_sockets), 2)

    async def test_reuse_partial_circuit(self):
        """
        Check if we can change the unverified hop of a circuit.
        """
        self.add_node_to_experiment(self.create_node())

        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        self.overlay(2).should_join_circuit = lambda *args: succeed(False)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        # We wanted to create circuit 0 -> 1 -> 2, but node 2 is not responding
        circuit = list(self.overlay(0).circuits.values())[0]
        self.assertEqual([h.mid for h in circuit.hops], [self.mid(1)])
        self.assertEqual(circuit.unverified_hop.mid, self.mid(2))

        # Let's add a new exit node, and retry to extend the circuit
        self.add_node_to_experiment(self.create_node())
        self.settings(3).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        # Let's pretend that node 1 selected node 3 as a possible node for circuit extension
        cache = self.overlay(1).request_cache.get(u"created", circuit.circuit_id)
        cache.candidates[self.key_bin(3)] = self.my_peer(3)

        # Retry to extend the circuit
        circuit.required_exit = None
        self.overlay(0).send_extend(circuit, [self.key_bin(3)], 1)
        await self.deliver_messages()

        # Circuit should now be 0 -> 1 -> 3
        self.assertEqual([h.mid for h in circuit.hops], [self.mid(1), self.mid(3)])
        self.assertEqual(circuit.unverified_hop, None)
        self.assertEqual(self.overlay(0).tunnels_ready(2), 1.0)

    async def test_reuse_partial_circuit_first_hop(self):
        """
        Check if we can change the first unverified hop of a circuit.
        """
        self.add_node_to_experiment(self.create_node())

        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_BT)
        self.overlay(1).should_join_circuit = lambda *args: succeed(False)
        await self.introduce_nodes()
        self.overlay(0).build_tunnels(2)
        await self.deliver_messages()

        # Adding the first hop fails, since hop 1 is not responding
        circuit = list(self.overlay(0).circuits.values())[0]
        self.assertEqual(circuit.hops, ())
        self.assertEqual(circuit.unverified_hop.mid, self.mid(1))

        # Let's add a new node, and retry to extend the circuit
        self.add_node_to_experiment(self.create_node())
        await self.introduce_nodes()

        # Retry to extend the circuit
        self.overlay(0).send_initial_create(circuit, [self.my_peer(3)], 1)
        await self.deliver_messages()

        # Circuit should now be 0 -> 2 -> 3
        self.assertEqual([h.mid for h in circuit.hops], [self.mid(3), self.mid(2)])
        self.assertEqual(circuit.unverified_hop, None)
        self.assertEqual(self.overlay(0).tunnels_ready(2), 1.0)

    async def test_tunnel_endpoint_anon(self):
        """
        Check if the tunnel endpoint is routing traffic correctly with anonymity enabled.
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(2).peer_flags.add(PEER_FLAG_EXIT_IPV8)
        await self.introduce_nodes()
        self.overlay(0).create_circuit(1, exit_flags=[PEER_FLAG_EXIT_IPV8])
        await self.deliver_messages()

        exit_socket = list(self.overlay(2).exit_sockets.values())[0]
        self.overlay(2).exit_sockets[exit_socket.circuit_id] = MockTunnelExitSocket(exit_socket)

        send_data = self.overlay(0).send_data
        self.overlay(0).send_data = Mock(wraps=send_data)

        prefix = b'\x00\x01' + b'\x00' * 20
        self.overlay(0).endpoint = endpoint = TunnelEndpoint(self.endpoint(0))
        endpoint.set_tunnel_community(self.overlay(0))
        endpoint.set_anonymity(prefix, True)

        ep_listener = MockEndpointListener(self.endpoint(1))
        endpoint.send(self.overlay(1).my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()
        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], prefix + b'DATA')
        self.overlay(0).send_data.assert_called_once()

        # When a circuit closes, sending data should fail
        self.overlay(0).send_data = Mock(wraps=send_data)
        circuit = self.overlay(0).find_circuits(exit_flags=[PEER_FLAG_EXIT_IPV8])[0]
        await self.overlay(0).remove_circuit(circuit.circuit_id)
        endpoint.send(self.overlay(1).my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()
        self.assertEqual(len(ep_listener.received_packets), 1)
        self.overlay(0).send_data.assert_not_called()

    async def test_tunnel_endpoint_no_anon(self):
        """
        Check if the tunnel endpoint is routing traffic correctly with anonymity disabled.
        """

        prefix = b'\x00' * 22
        self.overlay(0).endpoint = endpoint = TunnelEndpoint(self.endpoint(0))
        endpoint.set_tunnel_community(self.overlay(0))
        endpoint.set_anonymity(prefix, False)

        ep_listener = MockEndpointListener(self.endpoint(1))
        endpoint.send(self.overlay(1).my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()

        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], prefix + b'DATA')

    async def test_tunnel_unicode_destination(self):
        """
        Check if the encoding/decoding a unicode hostname works.
        """
        self.settings(1).peer_flags.add(PEER_FLAG_EXIT_BT)
        await self.introduce_nodes()
        circuit = self.overlay(0).create_circuit(1)
        await circuit.ready

        exit_socket = list(self.overlay(1).exit_sockets.values())[0]
        mock_exit = self.overlay(1).exit_sockets[exit_socket.circuit_id] = MockTunnelExitSocket(exit_socket)
        mock_exit.sendto = Mock()

        unicode_destination = DomainAddress('JP納豆.例.jp', 1234)
        self.overlay(0).send_data(circuit.peer, circuit.circuit_id, unicode_destination, ('0.0.0.0', 0), b'')
        await self.deliver_messages()

        mock_exit.sendto.assert_called_with(b'', unicode_destination)

    async def test_test_request(self):
        """
        Check if sending test-request messages works as expected.
        """
        self.add_node_to_experiment(self.create_node())
        self.settings(1).peer_flags.add(PEER_FLAG_SPEED_TEST)
        await self.introduce_nodes()
        circuit = self.overlay(0).create_circuit(2, exit_flags=[PEER_FLAG_SPEED_TEST])
        await circuit.ready

        send_cell = self.overlay(0).send_cell
        self.overlay(0).send_cell = Mock(wraps=send_cell)
        data, _ = await self.overlay(0).send_test_request(circuit, 3, 6)
        self.assertEqual(len(self.overlay(0).send_cell.call_args[0][1].data), 3)
        self.assertEqual(len(data), 6)
