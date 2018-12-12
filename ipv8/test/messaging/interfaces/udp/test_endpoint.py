from __future__ import absolute_import

import socket
import sys
from unittest import skipIf

from six.moves import xrange
from twisted.internet.defer import inlineCallbacks

from .....messaging.interfaces.endpoint import EndpointListener
from .....messaging.interfaces.udp.endpoint import UDPEndpoint, UDP_MAX_SIZE
from ....base import TestBase


class DummyEndpointListener(EndpointListener):
    """
    This class simply listens on an endpoint and stores incoming packets in a list.
    """
    def __init__(self, endpoint):
        super(DummyEndpointListener, self).__init__(endpoint)
        self.incoming = []

    def on_packet(self, packet):
        self.incoming.append(packet)


class TestUDPEndpoint(TestBase):
    """
    This class contains various tests for the UDP endpoint.
    """

    @inlineCallbacks
    def setUp(self):
        yield super(TestUDPEndpoint, self).setUp()
        self.endpoint1 = UDPEndpoint(8080)
        self.endpoint1.open()
        self.endpoint2 = UDPEndpoint(8081)
        self.endpoint2.open()

        self.ep2_address = ("127.0.0.1", self.endpoint2.get_address()[1])

        self.endpoint2_listener = DummyEndpointListener(self.endpoint2)
        self.endpoint2.add_listener(self.endpoint2_listener)

    @inlineCallbacks
    def tearDown(self):
        # If an endpoint was used, close it
        if self.endpoint1:
            yield self.endpoint1.close()
        if self.endpoint2:
            yield self.endpoint2.close()
        yield super(TestUDPEndpoint, self).tearDown()

    @inlineCallbacks
    def test_send_message(self):
        """
        Test sending a basic message through the UDP endpoint.
        """
        self.endpoint1.send(self.ep2_address, b'a' * 10)
        yield self.sleep(0.05)
        self.assertTrue(self.endpoint2_listener.incoming)

    @inlineCallbacks
    def test_send_many_messages(self):
        """
        Test sending multiple messages through the UDP endpoint.
        """
        for ind in xrange(0, 50):
            self.endpoint1.send(self.ep2_address, b'a' * ind)
        yield self.sleep(0.05)
        self.assertEqual(len(self.endpoint2_listener.incoming), 50)

    def test_send_too_big_message(self):
        """
        Test sending a too big message through the UDP endpoint.
        """
        self.endpoint1.send(self.ep2_address, b'a' * (UDP_MAX_SIZE + 1000))

    def test_send_invalid_destination(self):
        """
        Test sending a message with an invalid destination through the UDP endpoint.
        """
        self.endpoint1.send(("0.0.0.0", 0), b'a' * 10)

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
