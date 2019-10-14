from __future__ import absolute_import
from __future__ import print_function

import os
import random
import shutil
import string
import sys
import threading
import time

import twisted
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks
from twisted.internet.task import deferLater
from twisted.trial import unittest

from .mocking.endpoint import internet
from .mocking.ipv8 import MockIPv8
from ..peer import Peer

twisted.internet.base.DelayedCall.debug = True


class TestBase(unittest.TestCase):

    __testing__ = True
    __lockup_timestamp__ = 0

    # The time after which the whole test suite is os.exited
    MAX_TEST_TIME = 10

    def __init__(self, methodName='runTest'):
        super(TestBase, self).__init__(methodName)
        self.nodes = []
        self.overlay_class = object
        internet.clear()
        self._tempdirs = []

    def initialize(self, overlay_class, node_count, *args, **kwargs):
        self.overlay_class = overlay_class
        self.nodes = [self.create_node(*args, **kwargs) for _ in range(node_count)]

        # Add nodes to each other
        for node in self.nodes:
            for other in self.nodes:
                if other == node:
                    continue
                private_peer = other.my_peer
                public_peer = Peer(private_peer.public_key, private_peer.address)
                node.network.add_verified_peer(public_peer)
                node.network.discover_services(public_peer, overlay_class.master_peer.mid)

    def setUp(self):
        super(TestBase, self).setUp()
        TestBase.__lockup_timestamp__ = time.time()

    def tearDown(self):
        try:
            for node in self.nodes:
                node.unload()
            internet.clear()
        finally:
            while self._tempdirs:
                shutil.rmtree(self._tempdirs.pop(), ignore_errors=True)
        super(TestBase, self).tearDown()
        # After the super tearDown the remaining blocking calls should have been cancelled.
        # We reschedule the reactor to inspect itself after 0.01 seconds. Note that this cannot
        # be done after 0 seconds because we need to exit this Deferred callback chain first.
        # Also note that the longer we make this timeout, the longer we will have to wait before
        # we can cleanup.
        shutdown_dc = deferLater(reactor, 0.01, lambda: None)
        reactor.wakeUp()
        return shutdown_dc

    @classmethod
    def setUpClass(cls):
        TestBase.__lockup_timestamp__ = time.time()

        def check_twisted():
            while time.time() - TestBase.__lockup_timestamp__ < cls.MAX_TEST_TIME:
                time.sleep(2)
                # If the test class completed normally, exit
                if not cls.__testing__:
                    return
            # If we made it here, there is a serious issue which we cannot recover from.
            # Most likely the Twisted threadpool got into a deadlock while shutting down.
            import traceback
            print("The test-suite locked up! Force quitting! Thread dump:", file=sys.stderr)
            for tid, stack in sys._current_frames().items():
                if tid != threading.currentThread().ident:
                    print("THREAD#%d" % tid, file=sys.stderr)
                    for line in traceback.format_list(traceback.extract_stack(stack)):
                        print("|", line[:-1].replace('\n', '\n|   '), file=sys.stderr)

            delayed_calls = reactor.getDelayedCalls()
            if delayed_calls:
                print("Delayed calls:")
                for dc in delayed_calls:
                    print(">     %s" % dc)

            # Our test suite catches the SIGINT signal, this allows it to print debug information before force exiting.
            # If we were to hard exit here (through os._exit) we would lose this additional information.
            import signal
            os.kill(os.getpid(), signal.SIGINT)
            # But sometimes it just flat out refuses to die (sys.exit will also not work in this case).
            # So we double kill ourselves:
            os._exit(1)  # pylint: disable=W0212
        t = threading.Thread(target=check_twisted)
        t.daemon = True
        t.start()

    @classmethod
    def tearDownClass(cls):
        cls.__testing__ = False

    def create_node(self, *args, **kwargs):
        return MockIPv8(u"low", self.overlay_class, *args, **kwargs)

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
         1. Measure the amount of working threads in the threadpool
         2. After 10 milliseconds, check if we are down to 0 twice in a row
         3. If not, go back to handling calls (step 2) or return, if the timeout has been reached

        :param timeout: the maximum time to wait for messages to be delivered
        """
        rtime = 0
        probable_exit = False
        while (rtime < timeout):
            yield self.sleep(.01)
            rtime += .01
            if len(reactor.getThreadPool().working) == 0:
                if probable_exit:
                    break
                probable_exit = True
            else:
                probable_exit = False

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    @inlineCallbacks
    def introduce_nodes(self):
        for node in self.nodes:
            for other in self.nodes:
                if other != node:
                    node.overlay.walk_to(other.endpoint.wan_address)
        yield self.deliver_messages()

    def temporary_directory(self):
        rndstr = 'temp_'.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
        d = os.path.abspath(self.__class__.__name__ + rndstr)
        self._tempdirs.append(d)
        os.makedirs(d)
        return d
