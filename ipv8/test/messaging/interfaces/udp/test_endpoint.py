from .....messaging.interfaces.endpoint import EndpointListener
from .....messaging.interfaces.udp.endpoint import UDPEndpoint, UDP_MAX_SIZE
from .....test.util import twisted_wrapper
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

    def setUp(self):
        super(TestUDPEndpoint, self).setUp()
        self.endpoint1 = UDPEndpoint(8080)
        self.endpoint1.open()
        self.endpoint2 = UDPEndpoint(8081)
        self.endpoint2.open()

        self.endpoint2_listener = DummyEndpointListener(self.endpoint2)
        self.endpoint2.add_listener(self.endpoint2_listener)

    def tearDown(self):
        super(TestUDPEndpoint, self).tearDown()

        # If an endpoint was used, close it
        if self.endpoint1:
            self.endpoint1.close()
        if self.endpoint2:
            self.endpoint2.close()

    @twisted_wrapper
    def test_send_message(self):
        """
        Test sending a basic message through the UDP endpoint.
        """
        self.endpoint1.send(("127.0.0.1", 8081), 'a' * 10)
        yield self.sleep(0.05)
        self.assertTrue(self.endpoint2_listener.incoming)

    @twisted_wrapper
    def test_send_many_messages(self):
        """
        Test sending multiple messages through the UDP endpoint.
        """
        for ind in xrange(0, 50):
            self.endpoint1.send(("127.0.0.1", 8081), 'a' * ind)
        yield self.sleep(0.05)
        self.assertEqual(len(self.endpoint2_listener.incoming), 50)

    def test_send_too_big_message(self):
        """
        Test sending a too big message through the UDP endpoint.
        """
        self.endpoint1.send(("127.0.0.1", 8081), 'a' * (UDP_MAX_SIZE + 1000))

    def test_send_invalid_destination(self):
        """
        Test sending a message with an invalid destination through the UDP endpoint.
        """
        self.endpoint1.send(("0.0.0.0", 0), 'a' * 10)
