from twisted.internet.defer import inlineCallbacks, Deferred

from ....messaging.anonymization.community import TunnelSettings, CIRCUIT_TYPE_RENDEZVOUS
from ....messaging.anonymization.hidden_services import HiddenTunnelCommunity
from ....peer import Peer
from ...base import TestBase
from ...mocking.exit_socket import MockTunnelExitSocket
from ...mocking.ipv8 import MockIPv8
from ...util import twisted_wrapper

# Map of info_hash -> peer list
global_dht_services = {}


class MockDHTProvider(object):

    def __init__(self, address):
        self.address = address

    def lookup(self, info_hash, cb):
        if info_hash in global_dht_services:
            cb((info_hash, global_dht_services[info_hash], None))

    def announce(self, info_hash):
        if info_hash in global_dht_services:
            global_dht_services[info_hash].append(self.address)
        else:
            global_dht_services[info_hash] = [self.address]


class TestHiddenServices(TestBase):

    def setUp(self):
        super(TestHiddenServices, self).setUp()
        self.initialize(HiddenTunnelCommunity, 3)

        self.private_nodes = []
        self.service = '0' * 20
        self.received_packets = []

    def tearDown(self):
        for node in self.private_nodes:
            node.unload()
        super(TestHiddenServices, self).tearDown()

    def get_e2e_circuit_path(self):
        """
        Return the e2e circuit information which is extracted from the nodes.
        Useful for debugging purposes or to verify whether the e2e circuit is correctly established.
        """
        path = []

        # Find the first node of the e2e circuit
        e2e_circuit = None
        first_node = None
        for node in self.nodes:
            for circuit in node.overlay.circuits.itervalues():
                if circuit.ctype == CIRCUIT_TYPE_RENDEZVOUS:
                    first_node = node
                    e2e_circuit = circuit
                    break

        if not e2e_circuit:
            # We didn't find any e2e circuit.
            return None

        def get_node_with_sock_addr(sock_addr):
            # Utility method to quickly return a node with a specific socket address.
            for node in self.nodes:
                if node.overlay.my_peer.address == sock_addr:
                    return node
            return None

        # Add the first node to the path
        path.append((first_node.overlay.my_peer.address, e2e_circuit))

        cur_tunnel = e2e_circuit
        while True:
            next_node = get_node_with_sock_addr(cur_tunnel.peer.address)
            if cur_tunnel.circuit_id not in next_node.overlay.relay_from_to:
                # We reached the end of our e2e circuit.
                path.append((next_node.overlay.my_peer.address, cur_tunnel))
                break
            cur_tunnel = next_node.overlay.relay_from_to[cur_tunnel.circuit_id]
            path.append((next_node.overlay.my_peer.address, cur_tunnel))

        return path

    def create_node(self):
        # Initialize a HiddenTunnelCommunity without circuits or exit node functionality
        settings = TunnelSettings()
        settings.become_exitnode = False
        settings.min_circuits = 0
        settings.max_circuits = 0
        ipv8 = MockIPv8(u"curve25519", HiddenTunnelCommunity, settings=settings)
        # Then kill all automated circuit creation
        ipv8.overlay.cancel_all_pending_tasks()
        # Finally, use the proper exitnode and circuit settings for manual creation
        ipv8.overlay.settings.min_circuits = 1
        ipv8.overlay.settings.max_circuits = 1
        ipv8.overlay.dht_provider = MockDHTProvider(ipv8.endpoint.wan_address)
        return ipv8

    @inlineCallbacks
    def create_intro(self, node_nr, service):
        """
        Create an 1 hop introduction point for some node for some service.
        """
        lookup_service = self.nodes[node_nr].overlay.get_lookup_info_hash(service)
        self.nodes[node_nr].overlay.hops[lookup_service] = 1
        self.nodes[node_nr].overlay.create_introduction_point(lookup_service)

        yield self.deliver_messages()

        for node in self.nodes:
            exit_sockets = node.overlay.exit_sockets
            for exit_socket in exit_sockets:
                exit_sockets[exit_socket] = MockTunnelExitSocket(exit_sockets[exit_socket])

    @inlineCallbacks
    def assign_exit_node(self, node_nr):
        """
        Give a node a dedicated exit node to play with.
        """
        exit_node = self.create_node()
        self.private_nodes.append(exit_node)
        exit_node.overlay.settings.become_exitnode = True
        public_peer = Peer(exit_node.my_peer.public_key, exit_node.my_peer.address)
        self.nodes[node_nr].network.add_verified_peer(public_peer)
        self.nodes[node_nr].network.discover_services(public_peer, exit_node.overlay.master_peer.mid)
        self.nodes[node_nr].overlay.update_exit_candidates(public_peer, True)
        self.nodes[node_nr].overlay.build_tunnels(1)
        yield self.deliver_messages()
        exit_sockets = exit_node.overlay.exit_sockets
        for exit_socket in exit_sockets:
            exit_sockets[exit_socket] = MockTunnelExitSocket(exit_sockets[exit_socket])

    @twisted_wrapper
    def test_create_introduction_point(self):
        """
        Check if setting up an introduction point works.
        Some node, other than the instigator, should be assigned as the intro point.
        """
        yield self.introduce_nodes()
        yield self.create_intro(0, self.service)

        lookup_service = self.nodes[0].overlay.get_lookup_info_hash(self.service)

        intro_made = False
        for node_nr in range(1, len(self.nodes)):
            intro_made |= lookup_service in self.nodes[node_nr].overlay.intro_point_for

        self.assertTrue(intro_made)

    @twisted_wrapper
    def test_dht_lookup_with_counterparty(self):
        """
        Check if a DHT lookup works.

        Steps:
         1. Create an introduction point
         2. Do a DHT lookup
         3. Share keys
         4. Create a rendezvous point
         5. Link the circuit e2e
         6. Callback the service handler
        """
        callback_called = Deferred()
        def callback(_):
            callback_called.callback(None)

        self.nodes[0].overlay.register_service(self.service, 1, callback, 0)

        yield self.introduce_nodes()
        yield self.create_intro(2, self.service)
        yield self.assign_exit_node(0)

        self.nodes[0].overlay.do_dht_lookup(self.service)

        yield self.deliver_messages()

        yield callback_called

        # Verify the length of the e2e circuit
        e2e_path = self.get_e2e_circuit_path()
        self.assertEqual(len(e2e_path), 4)

        # Check if data can be sent over the e2e circuit
        data = 'PACKET'
        _, circuit = e2e_path[0]
        self.nodes[2].overlay.on_raw_data = lambda _, __, data: self.received_packets.append(data)
        self.nodes[0].overlay.send_data([circuit.peer], circuit.circuit_id, ('0.0.0.0', 0), ('0.0.0.0', 0), data)
        yield self.deliver_messages()
        self.assertEqual(len(self.received_packets), 1)
        self.assertEqual(self.received_packets[0], data)

    @twisted_wrapper
    def test_dht_lookup_no_counterparty(self):
        """
        Check if a DHT lookup doesn't return on its own required service.
        Ergo, no self-introduction.
        """
        def callback(_):
            callback.called = True

        callback.called = False

        self.nodes[0].overlay.register_service(self.service, 1, callback, 0)

        yield self.introduce_nodes()
        yield self.assign_exit_node(0)

        self.nodes[0].overlay.do_dht_lookup(self.service)

        yield self.deliver_messages()

        self.assertFalse(callback.called)
