from ipv8.messaging.anonymization.community import TunnelCommunity, TunnelSettings
from ipv8.messaging.interfaces.udp.endpoint import UDPEndpoint
from test.base import TestBase
from test.mocking.endpoint import MockEndpointListener
from test.mocking.ipv8 import MockIPv8
from test.util import twisted_wrapper


class TestTunnelCommunity(TestBase):

    def setUp(self):
        super(TestTunnelCommunity, self).setUp()
        self.initialize(TunnelCommunity, 2)

        # An actual UDPEndpoint, if needed by the test (for catching exited data)
        self.public_endpoint = None

    def tearDown(self):
        super(TestTunnelCommunity, self).tearDown()

        # If an endpoint was used, close it
        if self.public_endpoint:
            self.public_endpoint.close()

    def create_node(self):
        # Initialize a TunnelCommunity without circuits or exit node functionality
        settings = TunnelSettings()
        settings.become_exitnode = False
        settings.min_circuits = 0
        settings.max_circuits = 0
        ipv8 = MockIPv8(u"curve25519", TunnelCommunity, settings=settings)
        # Then kill all automated circuit creation
        ipv8.overlay.cancel_all_pending_tasks()
        # Finally, use the proper exitnode and circuit settings for manual creation
        ipv8.overlay.settings.min_circuits = 1
        ipv8.overlay.settings.max_circuits = 1
        return ipv8

    @twisted_wrapper
    def test_introduction_as_exit(self):
        """
        Check if introduction requests share the fact that nodes are exit nodes.
        """
        self.nodes[0].overlay.settings.become_exitnode = True
        self.nodes[1].overlay.settings.become_exitnode = False

        yield self.introduce_nodes()

        self.assertIn(self.nodes[0].my_peer.public_key.key_to_bin(), self.nodes[1].overlay.exit_candidates)
        self.assertNotIn(self.nodes[1].my_peer.public_key.key_to_bin(), self.nodes[0].overlay.exit_candidates)

    @twisted_wrapper
    def test_introduction_as_exit_twoway(self):
        """
        Check if two nodes can have each other as exit nodes.
        """
        self.nodes[0].overlay.settings.become_exitnode = True
        self.nodes[1].overlay.settings.become_exitnode = True

        yield self.introduce_nodes()

        self.assertIn(self.nodes[0].my_peer.public_key.key_to_bin(), self.nodes[1].overlay.exit_candidates)
        self.assertIn(self.nodes[1].my_peer.public_key.key_to_bin(), self.nodes[0].overlay.exit_candidates)

    @twisted_wrapper
    def test_introduction_as_exit_noway(self):
        """
        Check if two nodes don't advertise themselves as exit node incorrectly.
        """
        self.nodes[0].overlay.settings.become_exitnode = False
        self.nodes[1].overlay.settings.become_exitnode = False

        yield self.introduce_nodes()

        self.assertEqual(len(self.nodes[0].overlay.exit_candidates), 0)
        self.assertEqual(len(self.nodes[1].overlay.exit_candidates), 0)

    @twisted_wrapper
    def test_create_circuit(self):
        """
        Check if 1 hop circuit creation works.
        """
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 1)
        # It should use node 1 for this
        self.nodes[0].overlay.build_tunnels(1)

        # Let the circuit creation commence
        yield self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        # Node 1 has an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 1)

    @twisted_wrapper
    def test_create_circuit_no_exit(self):
        """
        Check if 1 hop circuit creation fails without exit nodes.
        """
        self.nodes[1].overlay.settings.become_exitnode = False
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)

        # Attempt circuit creation
        yield self.deliver_messages()

        # Node 0 should now have no 1 hop circuits (0.0/0%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 0.0)
        # Node 1 should not have an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 0)

    @twisted_wrapper
    def test_destroy_circuit(self):
        """
        Check if a 1 hop circuit can be destroyed.
        """
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)
        yield self.deliver_messages()

        # Destroy the circuit we just created using a destroy message
        self.nodes[0].overlay.remove_circuit(self.nodes[0].overlay.circuits.keys()[0], destroy=True)
        yield self.deliver_messages()

        # Node 0 should now have no 1 hop circuits (0.0/0%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 0.0)
        # Node 1 should not have an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 0)

    @twisted_wrapper
    def test_destroy_circuit_bad_id(self):
        """
        Check if the correct circuit gets destroyed.
        """
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)
        yield self.deliver_messages()

        # Destroy a circuit which does not exist (circuit_id + 1)
        # This should not affect other circuits
        self.nodes[0].overlay.remove_circuit(self.nodes[0].overlay.circuits.keys()[0] + 1, destroy=True)
        yield self.deliver_messages()

        # Node 0 should still have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        # Node 1 still has an exit socket open
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets), 1)

    @twisted_wrapper
    def test_tunnel_data(self):
        """
        Check if data is correctly exited.
        """
        # Listen in on communication of the target
        self.public_endpoint = UDPEndpoint(8080)
        self.public_endpoint.open()
        ep_listener = MockEndpointListener(self.public_endpoint)

        # Build a tunnel
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(1)
        yield self.deliver_messages()

        # Construct a data packet
        prefix = '\x00' * 23
        data = prefix + ''.join([chr(i) for i in range(256)])

        self.public_endpoint.assert_open()

        # Tunnel the data to the endpoint
        circuit = self.nodes[0].overlay.circuits.values()[0]
        self.nodes[0].overlay.send_data([circuit.sock_addr], circuit.circuit_id,
                                        ('localhost', self.public_endpoint.get_address()[1]), ('0.0.0.0', 0), data)
        # This is not test communication, but actual socket communication, we can't do a smart sleep
        yield self.sleep()

        self.assertEqual(len(ep_listener.received_packets), 1)
        self.assertEqual(ep_listener.received_packets[0][1], data)

    @twisted_wrapper
    def test_two_hop_circuit(self):
        """
        Check if a two hop circuit is correctly created.

        Note that we avoid exit nodes in the relay path, so we explicitly set relay nodes to not be exits.
        """
        self.add_node_to_experiment(self.create_node())

        # Build a tunnel
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(2)
        yield self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.tunnels_ready(2), 1.0)

    @twisted_wrapper
    def test_three_hop_circuit(self):
        """
        Check if a three hop circuit is correctly created.

        Note that we avoid exit nodes in the relay path, so we explicitly set relay nodes to not be exits.
        """
        self.add_node_to_experiment(self.create_node())
        self.add_node_to_experiment(self.create_node())

        # Build a tunnel
        self.nodes[1].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()
        self.nodes[0].overlay.build_tunnels(3)
        yield self.deliver_messages()

        self.assertEqual(self.nodes[0].overlay.tunnels_ready(3), 1.0)

    @twisted_wrapper
    def test_create_two_circuit(self):
        """
        Check if multiple 1 hop circuit creation works.
        """
        self.add_node_to_experiment(self.create_node())
        self.nodes[0].overlay.settings.min_circuits = 2
        self.nodes[0].overlay.settings.max_circuits = 2
        self.nodes[1].overlay.settings.become_exitnode = True
        self.nodes[2].overlay.settings.become_exitnode = True
        yield self.introduce_nodes()

        # Let node 0 build tunnels of 1 hop (settings.min_circuits = settings.max_circuits = 2)
        # It should use node 1 and 2 for this
        self.nodes[0].overlay.build_tunnels(1)

        # Let the circuit creation commence
        yield self.deliver_messages()

        # Node 0 should now have all of its required 1 hop circuits (1.0/100%)
        self.assertEqual(self.nodes[0].overlay.tunnels_ready(1), 1.0)
        self.assertEqual(len(self.nodes[0].overlay.circuits), 2)
        # Two exit sockets are open between node 1 and 2 (NOT evenly spread)
        self.assertEqual(len(self.nodes[1].overlay.exit_sockets) + len(self.nodes[2].overlay.exit_sockets), 2)
