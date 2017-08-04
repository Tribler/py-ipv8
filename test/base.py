import sys
import threading
import time

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater
from twisted.trial import unittest

import twisted
twisted.internet.base.DelayedCall.debug = True

from peer import Peer
from test.mocking.ipv8 import MockIPv8


class TestBase(unittest.TestCase):

    __testing__ = True
    __lockup_timestamp__ = 0

    # The time after which the whole test suite is os.exited
    MAX_TEST_TIME = 10

    def __init__(self, methodName='runTest'):
        super(TestBase, self).__init__(methodName)
        self.nodes = []
        self.overlay_class = object
        self.base_calls = []

    def initialize(self, overlay_class, node_count):
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

        self.base_calls = len(reactor.getDelayedCalls())

    def setUp(self):
        super(TestBase, self).setUp()
        self.__lockup_timestamp__ = time.time()

    def tearDown(self):
        super(TestBase, self).tearDown()
        for node in self.nodes:
            node.overlay.unload()

    @classmethod
    def setUpClass(cls):
        cls.__lockup_timestamp__ = time.time()
        def check_twisted():
            while time.time() - cls.__lockup_timestamp__ < cls.MAX_TEST_TIME:
                time.sleep(2)
                # If the test class completed normally, exit
                if not cls.__testing__:
                    return
            # If we made it here, there is a serious issue which we cannot recover from.
            # Most likely the Twisted threadpool got into a deadlock while shutting down.
            import os, traceback
            print >> sys.stderr, "The test-suite locked up! Force quitting! Thread dump:"
            for tid, stack in sys._current_frames().items():
                if tid != threading.currentThread().ident:
                    print >> sys.stderr, "THREAD#%d" % tid
                    for line in traceback.format_list(traceback.extract_stack(stack)):
                        print >> sys.stderr, "|", line[:-1].replace('\n', '\n|   ')
            os._exit(1)
        t = threading.Thread(target=check_twisted)
        t.daemon = True
        t.start()

    @classmethod
    def tearDownClass(cls):
        cls.__testing__ = False

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
    def deliver_messages(self, timeout=.1):
        """
        Allow peers to communicate.

        The strategy is as follows:
         1. Measure the amount of open calls in the Twisted reactor (including those of the test suite!!)
         2. After 10 milliseconds, check if we are down to this amount twice in a row (no calls need to be handled)
         3. If not, go back to handling calls (step 2) or return, if the timeout has been reached

        :param timeout: the maximum time to wait for messages to be delivered
        """
        time = 0
        probable_exit = False
        while (time < timeout):
            yield self.sleep(.01)
            time += .01
            if len(reactor.getDelayedCalls()) <= self.base_calls:
                if probable_exit:
                    break
                probable_exit = True

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    @inlineCallbacks
    def introduce_nodes(self):
        for node in self.nodes:
            node.discovery.take_step()
        yield self.deliver_messages()
