from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, succeed
from twisted.internet.task import deferLater
from twisted.trial import unittest

import twisted
twisted.internet.base.DelayedCall.debug = True

from messaging.anonymization.community import TunnelCommunity, TunnelSettings
from peer import Peer
from test.mocking.ipv8 import MockIPv8


class TestTunnelCommunity(unittest.TestCase):

    def setUp(self):
        self.nodes = [self._create_node() for _ in range(2)]
        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, TunnelCommunity.master_peer.mid)

    def tearDown(self):
        for node in self.nodes:
            node.overlay.unload()

    def _create_node(self):
        settings = TunnelSettings()
        settings.become_exitnode = True
        return MockIPv8(u"curve25519", TunnelCommunity, settings=settings)

    @inlineCallbacks
    def deliver_messages(self, timeout=.01):
        yield deferLater(reactor, timeout, lambda: None)

    @inlineCallbacks
    def test_create_circuit(self):
        node1 = self.nodes[0]
        node2 = self.nodes[1]

        # Send intro request
        node1.discovery.take_step()
        yield self.deliver_messages()

        self.assertIn(node2.my_peer.public_key.key_to_bin(), node1.overlay.exit_candidates)

        node1.overlay.build_tunnels(1)
        yield self.deliver_messages()

        self.assertEqual(node1.overlay.tunnels_ready(1), 1)

        yield succeed(None)
