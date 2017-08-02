from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater
from twisted.trial import unittest

import twisted
twisted.internet.base.DelayedCall.debug = True

from peer import Peer
from test.mocking.ipv8 import MockIPv8


class TestBase(unittest.TestCase):

    def setUp(self, overlay_class, node_count):
        super(TestBase, self).setUp()

        self.nodes = [self.create_node() for _ in range(node_count)]
        self.overlay_class = overlay_class

        # Add nodes to each other
        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, overlay_class.master_peer.mid)

        self.base_calls = reactor.getDelayedCalls()

    def tearDown(self):
        super(TestBase, self).tearDown()
        for node in self.nodes:
            node.overlay.unload()

    def create_node(self):
        return MockIPv8(u"low", self.overlay_class)

    def add_node_to_experiment(self, node):
        """
        Add a new node to this experiment (use `create_node()`).
        """
        for other in self.nodes:
            private_peer = other.my_peer
            public_peer = Peer(private_peer.public_key, private_peer.address)
            node.network.add_verified_peer(public_peer)
            node.network.discover_services(public_peer, node.overlay.master_peer.mid)
        self.nodes.append(node)

    @inlineCallbacks
    def deliver_messages(self, timeout=.05):
        """
        Allow peers to communicate.

        The strategy is as follows:
         1. Measure the amount of open calls in the Twisted reactor (including those of the test suite!!)
         2. After 10 milliseconds, check if we are down to this amount again (no calls need to be handled)
         3. If not, go back to handling calls (step 2) or return, if the timeout has been reached

        :param timeout: the maximum time to wait for messages to be delivered
        """
        time = 0
        while (time < timeout):
            yield self.sleep(.01)
            time += .01
            if reactor.getDelayedCalls() == self.base_calls:
                break

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    @inlineCallbacks
    def introduce_nodes(self):
        for node in self.nodes:
            node.discovery.take_step()
        yield self.deliver_messages()
