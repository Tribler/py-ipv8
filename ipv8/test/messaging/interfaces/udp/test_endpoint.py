from __future__ import absolute_import

import asyncio

from twisted.internet import asyncioreactor

# Must install the reactor here, such that no other reactor gets installed in the meantime.
asyncioreactor.install(asyncio.get_event_loop())

import socket
import sys
from unittest import skipIf, TestCase

from six.moves import xrange
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, ensureDeferred
from twisted.internet.task import deferLater, react

from .....messaging.interfaces.endpoint import EndpointListener
from .....messaging.interfaces.udp.endpoint import UDPEndpoint, UDP_MAX_SIZE


def async_test(func, *args, **kwargs):
    """
    Twisted's react function will use sys.exit which raises a SystemExit exception. This will automatically fail the
    test if not caught, so a try ... catch block is used. Based on its return code, a decision is made of whether to
    pass or fail the test. This is what this method does.
    """
    try:
        react(lambda my_reactor: ensureDeferred(func(my_reactor, *args, **kwargs)))
    except SystemExit as exc:
        if int(str(exc)) != 0:
            raise AssertionError("The test did not succeed")


class DummyEndpointListener(EndpointListener):
    """
    This class simply listens on an endpoint and stores incoming packets in a list.
    """
    def __init__(self, endpoint):
        super(DummyEndpointListener, self).__init__(endpoint)
        self.incoming = []

    def on_packet(self, packet):
        self.incoming.append(packet)


class TestUDPEndpoint(TestCase):
    """
    This class contains various tests for the UDP endpoint.
    """
    def setUp(self):
        loop = asyncio.get_event_loop()

        self.endpoint1 = UDPEndpoint(8080)
        loop.run_until_complete(self.endpoint1.open())
        self.endpoint2 = UDPEndpoint(8081)
        loop.run_until_complete(self.endpoint2.open())

        self.ep2_address = ("127.0.0.1", self.endpoint2.get_address()[1])

        self.endpoint2_listener = DummyEndpointListener(self.endpoint2)
        self.endpoint2.add_listener(self.endpoint2_listener)

    def tearDown(self):
        # If an endpoint was used, close it
        if self.endpoint1.is_open():
            self.endpoint1.close()
        if self.endpoint2.is_open():
            self.endpoint2.close()
        super(TestUDPEndpoint, self).tearDown()

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    def test_send_message(self):
        """
        Test sending a basic message through the UDP endpoint.
        """
        async def true_test(my_reactor):
            # Send the package
            datum = b'a' * 10
            await self.endpoint1.send(self.ep2_address, b'a' * 10)

            # Must use the Twisted sleep, otherwise there will be an error. The reactor is Asyncio's.
            await self.sleep()

            self.assertTrue(self.endpoint2_listener.incoming)
            self.assertEqual(self.endpoint2_listener.incoming[0][1], datum, "The received data was not the same as the"
                                                                            "sent data.")

        async_test(true_test)

    def test_send_many_messages(self):
        """
        Test sending multiple messages through the UDP endpoint.
        """

        async def true_test(my_reactor):
            # range must be in [1, 51), since Asyncio transports discard empty datagrams
            asyncio.gather(*[self.endpoint1.send(self.ep2_address, b'a' * ind) for ind in range(1, 51)])
            await self.sleep()
            self.assertEqual(len(self.endpoint2_listener.incoming), 50)

        async_test(true_test)

    def test_send_too_big_message(self):
        """
        Test sending a too big message through the UDP endpoint.
        """
        async def true_test(my_reactor):
            await self.endpoint1.send(self.ep2_address, b'a' * (UDP_MAX_SIZE + 1000))
            await self.sleep()
            self.assertFalse(self.endpoint2_listener.incoming)

        async_test(true_test)

    def test_send_invalid_destination(self):
        """
        Test sending a message with an invalid destination through the UDP endpoint.
        """
        async def true_test(my_reactor):
            await self.endpoint1.send(("0.0.0.0", 0), b'a' * 10)

        async_test(true_test)

    @skipIf(sys.version_info.major > 2, "sendto is write-only in Python3")
    @inlineCallbacks
    def test_blocking_endpoint_resend(self):
        """
        Test rescheduling on blocking socket in Windows.
        """
        # Raise an error on socket send()
        def cb_err_sendto(data, sock_addr):
            raise socket.error(10035, "Fake WSAEWOULDBLOCK")
        real_sendto = self.endpoint1.transport.socket.sendto
        self.endpoint1.transport.socket.sendto = cb_err_sendto

        # The following send raises a WSAEWOULDBLOCK and should queue the packet
        self.endpoint1.send(self.ep2_address, 'a' * 20)
        self.endpoint1.transport.socket.sendto = real_sendto
        yield self.sleep(0.05)
        # Nothing should have arrived
        self.assertEqual(len(self.endpoint2_listener.incoming), 0)

        # Now that the socket no longer errors, both messages should be delivered
        self.endpoint1.send(self.ep2_address, 'a' * 20)
        yield self.sleep(0.05)
        self.assertEqual(len(self.endpoint2_listener.incoming), 2)

    @skipIf(sys.version_info.major > 2, "sendto is write-only in Python3")
    @inlineCallbacks
    def test_blocking_endpoint_resend_limit(self):
        """
        Test not rescheduling more than 100 packets.
        """

        # Raise an error on socket send()
        def cb_err_sendto(data, sock_addr):
            raise socket.error(10035, "Fake WSAEWOULDBLOCK")

        real_sendto = self.endpoint1.transport.socket.sendto
        self.endpoint1.transport.socket.sendto = cb_err_sendto

        # The following send raises a WSAEWOULDBLOCK and should queue the packet
        for i in xrange(102):
            self.endpoint1.send(self.ep2_address, str(i))
        self.endpoint1.transport.socket.sendto = real_sendto
        yield self.sleep(0.05)
        # Nothing should have arrived
        self.assertEqual(len(self.endpoint2_listener.incoming), 0)

        # Now that the socket no longer errors, messages should be delivered
        # The first two messages ('0' and '1') should have been bumped out of the queue
        self.endpoint1.send(self.ep2_address, '102')
        yield self.sleep(0.05)
        self.assertEqual(len(self.endpoint2_listener.incoming), 101)
        self.assertSetEqual({data for _, data in self.endpoint2_listener.incoming},
                            {str(i) for i in xrange(2, 103)})
