from asyncio import Future
from collections import defaultdict

from ...base import TestBase
from ...mocking.endpoint import MockEndpointListener
from ...mocking.exit_socket import MockTunnelExitSocket
from ...mocking.ipv8 import MockIPv8
from ....messaging.anonymization.community import TunnelCommunity, TunnelSettings
from ....messaging.anonymization.endpoint import TunnelEndpoint
from ....messaging.anonymization.tunnel import (CIRCUIT_STATE_EXTENDING, CIRCUIT_TYPE_IPV8,
                                                PEER_FLAG_EXIT_ANY, PEER_FLAG_EXIT_IPV8)
from ....messaging.interfaces.udp.endpoint import UDPEndpoint
from ....util import cast_to_bin, succeed

# Map of info_hash -> peer list
global_dht_services = defaultdict(list)


class MockDHTProvider(object):

    def __init__(self, peer):
        self.peer = peer
        # DHTDiscoveryCommunity functionality
        global_dht_services[peer.mid].append(peer)

    async def peer_lookup(self, mid):
        return await self.lookup(mid)

    async def lookup(self, info_hash):
        return info_hash, global_dht_services.get(info_hash, [])

    async def announce(self, info_hash, intro_point):
        global_dht_services[info_hash].append(intro_point)


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

    async def test_introduction_as_exit(self):
        """
        Check if introduction requests share the fact that nodes are exit nodes.
        """
        self.nodes[0].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)

        await self.introduce_nodes()

        self.assertIn(self.nodes[0].my_peer, self.nodes[1].overlay.get_candidates(PEER_FLAG_EXIT_ANY))
        self.assertNotIn(self.nodes[1].my_peer, self.nodes[0].overlay.get_candidates(PEER_FLAG_EXIT_ANY))

    async def test_introduction_as_exit_twoway(self):
        """
        Check if two nodes can have each other as exit nodes.
        """
        self.nodes[0].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)

        await self.introduce_nodes()

        self.assertIn(self.nodes[0].my_peer, self.nodes[1].overlay.get_candidates(PEER_FLAG_EXIT_ANY))
        self.assertIn(self.nodes[1].my_peer, self.nodes[0].overlay.get_candidates(PEER_FLAG_EXIT_ANY))

    async def test_introduction_as_exit_noway(self):
        """
        Check if two nodes don't advertise themselves as exit node incorrectly.
        """
        await self.introduce_nodes()

        self.assertEqual(len(self.nodes[0].overlay.get_candidates(PEER_FLAG_EXIT_ANY)), 0)
        self.assertEqual(len(self.nodes[1].overlay.get_candidates(PEER_FLAG_EXIT_ANY)), 0)

    async def test_create_circuit(self):
        """
        Check if 1 hop circuit creation works.
        """
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 1)
        # It should use node 1 for this
        self.nodes[0].overlay.build_tunnels(1)

        # Let the circuit creation commence
        await self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        # Node 1 has an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 1)

    async def test_create_circuit_no_exit(self):
        """
        Check if 1 hop circuit creation fails without exit nodes.
        """
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)

        # Attempt circuit creation
        await self.deliver_messages()

        # Node 0 should now have no 1 hop circuits (0.0/0%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 0.0)
        # Node 1 should not have an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 0)

    async def test_create_circuit_multiple_calls(self):
        """
        Check if circuit creation is aborted when it's already building the requested circuit.
        """
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()

        # Don't allow the exit node to answer, this keeps peer 0's circuit in EXTENDING state
        self.nodes[1].overlay.endpoint.close()
        self.nodes[0].overlay.build_tunnels(1)

        # Node 0 should have 1 circuit in the CIRCUIT_STATE_EXTENDING state
        self.assertEqual(len(self.nodes[0].overlay.find_circuits(state=CIRCUIT_STATE_EXTENDING)), 1)

        # Subsequent calls to build_circuits should not change this
        self.nodes[0].overlay.build_tunnels(1)
        self.assertEqual(len(self.nodes[0].overlay.find_circuits(state=CIRCUIT_STATE_EXTENDING)), 1)

    async def test_destroy_circuit_from_originator(self):
        """
        Check if a 2 hop circuit can be destroyed (by the exit node)
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        # Destroy the circuit we just created using a destroy message
        await self.nodes[0].overlay.remove_circuit(list(self.nodes[0].overlay.circuits.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_from_exit(self):
        """
        Check if a 2 hop circuit can be destroyed (by the exit node)
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        await self.nodes[2].overlay.remove_exit_socket(list(self.nodes[2].overlay.exit_sockets.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_from_relay(self):
        """
        Check if a 2 hop circuit can be destroyed (by the relay node)
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        self.nodes[1].overlay.remove_relay(list(self.nodes[1].overlay.relay_from_to.keys())[0], destroy=1)
        await self.deliver_messages()

        self.assert_no_more_tunnels()

    async def test_destroy_circuit_bad_id(self):
        """
        Check if the correct circuit gets destroyed.
        """
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)
        await self.deliver_messages()

        # Destroy a circuit which does not exist (circuit_id + 1)
        # This should not affect other circuits
        await self.nodes[0].overlay.remove_circuit(list(self.nodes[0].overlay.circuits.keys())[0] + 1, destroy=1)
        await self.deliver_messages()

        # Node 0 should still have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        # Node 1 still has an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 1)

    async def test_tunnel_data(self):
        """
        Check if data is correctly exited.
        """
        # Listen in on communication of the target
        self.public_endpoint = UDPEndpoint()
        await self.public_endpoint.open()
        ep_listener = MockEndpointListener(self.public_endpoint)

        # Build a tunnel
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)
        await self.deliver_messages()

        # Construct a data packet
        prefix = b'\x00' * 23
        data = prefix + cast_to_bin(''.join([chr(i) for i in range(256)]))

        self.public_endpoint.assert_open()

        # Tunnel the data to the endpoint
        circuit = list(self.nodes[0].overlay.circuits.values())[0]
        self.nodes[0].overlay.send_data([circuit.peer.address], circuit.circuit_id,
                                        ('localhost', self.public_endpoint.get_address()[1]), ('0.0.0.0', 0), data)

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
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.tunnels_ready(2), 1.0)

    async def test_three_hop_circuit(self):
        """
        Check if a three hop circuit is correctly created.

        Note that we avoid exit nodes in the relay path, so we explicitly set relay nodes to not be exits.
        """
        self.add_node_to_experiment(self.create_node())
        self.add_node_to_experiment(self.create_node())

        # Build a tunnel
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(3)
        await self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.tunnels_ready(3), 1.0)

    async def test_create_two_circuit(self):
        """
        Check if multiple 1 hop circuit creation works.
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[0].overlay.settings.min_circuits = 2
        self.nodes[0].overlay.settings.max_circuits = 2
        self.nodes[1].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 2)
        # It should use node 1 and 2 for this
        self.nodes[0].overlay.build_tunnels(1)

        # Let the circuit creation commence
        await self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        self.assertEqual(len(self.nodes[0].overlay.circuits), 2)
        # Two exit sockets are open between node 1 and 2 (NOT evenly spread)
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets) + len(self.nodes[2].overlay.exit_sockets), 2)

    async def test_reuse_partial_circuit(self):
        """
        Check if we can change the unverified hop of a circuit.
        """
        self.add_node_to_experiment(self.create_node())

        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        self.nodes[2].overlay.should_join_circuit = lambda *args: succeed(False)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        # We wanted to create circuit 0 -> 1 -> 2, but node 2 is not responding
        circuit = list(self.nodes[0].overlay.circuits.values())[0]
        self.assertEqual([h.mid for h in circuit.hops], [self.nodes[1].overlay.my_peer.mid])
        self.assertEqual(circuit.unverified_hop.mid, self.nodes[2].overlay.my_peer.mid)

        # Let's add a new exit node, and retry to extend the circuit
        self.add_node_to_experiment(self.create_node())
        self.nodes[3].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        await self.introduce_nodes()
        # Let's pretend that node 1 selected node 3 as a possible node for circuit extension
        cache = self.nodes[1].overlay.request_cache.get(u"created", circuit.circuit_id)
        cache.candidates[self.nodes[3].overlay.my_peer.public_key.key_to_bin()] = self.nodes[3].overlay.my_peer

        # Retry to extend the circuit
        circuit.required_exit = None
        self.nodes[0].overlay.send_extend(circuit, [self.nodes[3].overlay.my_peer.public_key.key_to_bin()], 1)
        await self.deliver_messages()

        # Circuit should now be 0 -> 1 -> 3
        self.assertEqual([h.mid for h in circuit.hops], [self.nodes[1].overlay.my_peer.mid,
                                                         self.nodes[3].overlay.my_peer.mid])
        self.assertEqual(circuit.unverified_hop, None)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(2), 1.0)

    async def test_reuse_partial_circuit_first_hop(self):
        """
        Check if we can change the first unverified hop of a circuit.
        """
        self.add_node_to_experiment(self.create_node())

        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_ANY)
        self.nodes[1].overlay.should_join_circuit = lambda *args: succeed(False)
        await self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        await self.deliver_messages()

        # Adding the first hop fails, since hop 1 is not responding
        circuit = list(self.nodes[0].overlay.circuits.values())[0]
        self.assertEqual(circuit.hops, ())
        self.assertEqual(circuit.unverified_hop.mid, self.nodes[1].overlay.my_peer.mid)

        # Let's add a new node, and retry to extend the circuit
        self.add_node_to_experiment(self.create_node())
        await self.introduce_nodes()

        # Retry to extend the circuit
        self.nodes[0].overlay.send_initial_create(circuit, [self.nodes[3].overlay.my_peer], 1)
        await self.deliver_messages()

        # Circuit should now be 0 -> 2 -> 3
        self.assertEqual([h.mid for h in circuit.hops], [self.nodes[3].overlay.my_peer.mid,
                                                         self.nodes[2].overlay.my_peer.mid])
        self.assertEqual(circuit.unverified_hop, None)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(2), 1.0)

    async def test_tunnel_endpoint_anon(self):
        """
        Check if the tunnel endpoint is routing traffic correctly with anonymity enabled.
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[2].overlay.settings.peer_flags.add(PEER_FLAG_EXIT_IPV8)
        await self.introduce_nodes()
        self.nodes[0].overlay.create_circuit(1, CIRCUIT_TYPE_IPV8)
        await self.deliver_messages()

        exit_socket = list(self.nodes[2].overlay.exit_sockets.values())[0]
        self.nodes[2].overlay.exit_sockets[exit_socket.circuit_id] = MockTunnelExitSocket(exit_socket)

        sender = self.nodes[0].overlay
        send_data_org = sender.send_data

        def send_data(*args):
            sender.called = True
            send_data_org(*args)
        sender.called = False
        sender.send_data = send_data

        prefix = b'\x00\x01' + b'\x00' * 20
        self.nodes[0].overlay.endpoint = endpoint = TunnelEndpoint(self.nodes[0].overlay.endpoint)
        endpoint.set_tunnel_community(self.nodes[0].overlay)
        endpoint.set_anonymity(prefix, True)

        ep_listener = MockEndpointListener(self.nodes[1].endpoint)
        endpoint.send(self.nodes[1].overlay.my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()
        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], prefix + b'DATA')
        self.assertTrue(sender.called)

        # When a circuit closes, sending data should fail
        sender.called = False
        circuit = self.nodes[0].overlay.find_circuits(ctype=CIRCUIT_TYPE_IPV8)[0]
        await self.nodes[0].overlay.remove_circuit(circuit.circuit_id)
        endpoint.send(self.nodes[1].overlay.my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()
        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertFalse(sender.called)

    async def test_tunnel_endpoint_no_anon(self):
        """
        Check if the tunnel endpoint is routing traffic correctly with anonymity disabled.
        """

        prefix = b'\x00' * 22
        self.nodes[0].overlay.endpoint = endpoint = TunnelEndpoint(self.nodes[0].overlay.endpoint)
        endpoint.set_tunnel_community(self.nodes[0].overlay)
        endpoint.set_anonymity(prefix, False)

        ep_listener = MockEndpointListener(self.nodes[1].endpoint)
        endpoint.send(self.nodes[1].overlay.my_estimated_wan, prefix + b'DATA')
        await self.deliver_messages()

        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], prefix + b'DATA')
