from twisted.internet.defer import inlineCallbacks

from messaging.anonymization.community import TunnelSettings
from messaging.anonymization.hidden_services import HiddenTunnelCommunity
from peer import Peer
from test.base import TestBase
from test.mocking.exit_socket import MockTunnelExitSocket
from test.mocking.ipv8 import MockIPv8
from test.util import twisted_test

# Map of info_hash -> peer list
global_dht_services = {}


class MockDHTProvider(object):

    def __init__(self, address):
        self.address = address

    def lookup(self, info_hash, cb):
        if info_hash in global_dht_services:
            cb(info_hash, global_dht_services[info_hash], None)

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

    def tearDown(self):
        super(TestHiddenServices, self).tearDown()

        for node in self.private_nodes:
            node.overlay.unload()

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
        self.nodes[node_nr].overlay.hops[service] = 1
        self.nodes[node_nr].overlay.create_introduction_point(service)

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

    @twisted_test
    def test_create_introduction_point(self):
        """
        Check if setting up an introduction point works.
        Some node, other than the instigator, should be assigned as the intro point.
        """
        yield self.introduce_nodes()
        yield self.create_intro(0, self.service)

        intro_made = False
        for node_nr in range(1, len(self.nodes)):
            intro_made |= self.service in self.nodes[node_nr].overlay.intro_point_for

        self.assertTrue(intro_made)

    @twisted_test
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
        def callback(_):
            callback.called = True
        callback.called = False

        self.nodes[0].overlay.service_callbacks[self.service] = callback

        yield self.introduce_nodes()
        yield self.create_intro(2, self.service)
        yield self.assign_exit_node(0)

        self.nodes[0].overlay.hops[self.service] = 1
        self.nodes[0].overlay.do_dht_lookup(self.service)

        yield self.deliver_messages()

        self.assertTrue(callback.called)

    @twisted_test
    def test_dht_lookup_no_counterparty(self):
        """
        Check if a DHT lookup doesn't return on its own required service.
        Ergo, no self-introduction.
        """
        def callback(_):
            callback.called = True

        callback.called = False

        self.nodes[0].overlay.service_callbacks[self.service] = callback

        yield self.introduce_nodes()
        yield self.assign_exit_node(0)

        self.nodes[0].overlay.hops[self.service] = 1
        self.nodes[0].overlay.do_dht_lookup(self.service)

        yield self.deliver_messages()

        self.assertFalse(callback.called)
