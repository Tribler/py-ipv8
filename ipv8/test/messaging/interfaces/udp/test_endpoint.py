from asyncio import sleep

from ....base import TestBase
from .....messaging.interfaces.endpoint import EndpointListener
from .....messaging.interfaces.udp.endpoint import UDPEndpoint


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
    async def setUp(self):
        super(TestUDPEndpoint, self).setUp()
        self.endpoint1 = UDPEndpoint()
        await self.endpoint1.open()
        self.endpoint2 = UDPEndpoint()
        await self.endpoint2.open()

        self.ep2_address = ("127.0.0.1", self.endpoint2.get_address()[1])

        self.endpoint2_listener = DummyEndpointListener(self.endpoint2)
        self.endpoint2.add_listener(self.endpoint2_listener)

    async def tearDown(self):
        # If an endpoint was used, close it
        if self.endpoint1.is_open():
            self.endpoint1.close()
        if self.endpoint2.is_open():
            self.endpoint2.close()
        await super(TestUDPEndpoint, self).tearDown()

    async def test_send_message(self):
        """
        Test sending a basic message through the UDP endpoint.
        """
        # Send the package
        datum = b'a' * 10
        self.endpoint1.send(self.ep2_address, b'a' * 10)
        await sleep(.05)

        self.assertTrue(self.endpoint2_listener.incoming)
        self.assertEqual(self.endpoint2_listener.incoming[0][1], datum, "The received data was not the same as the"
                                                                        "sent data.")

    async def test_send_many_messages(self):
        """
        Test sending multiple messages through the UDP endpoint.
        """
        # range must be in [1, 51), since Asyncio transports discard empty datagrams
        for ind in range(1, 51):
            self.endpoint1.send(self.ep2_address, b'a' * ind)
        await sleep(.05)
        self.assertEqual(len(self.endpoint2_listener.incoming), 50)

    async def test_send_too_big_message(self):
        """
        Test sending a too big message through the UDP endpoint.
        """
        self.endpoint1.send(self.ep2_address, b'a' * (70000))
        await sleep(.05)
        self.assertFalse(self.endpoint2_listener.incoming)

    def test_send_invalid_destination(self):
        """
        Test sending a message with an invalid destination through the UDP endpoint.
        """
        self.endpoint1.send(("0.0.0.0", 0), b'a' * 10)
