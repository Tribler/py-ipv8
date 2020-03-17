import random
from asyncio import get_event_loop

from ...messaging.interfaces.endpoint import Endpoint, EndpointListener

internet = {}


class MockEndpoint(Endpoint):

    def __init__(self, lan_address, wan_address):
        super(MockEndpoint, self).__init__()
        internet[lan_address] = self
        internet[wan_address] = self

        self.lan_address = lan_address
        self.wan_address = wan_address

        self._port = self.lan_address[1]
        self._open = False

    def assert_open(self):
        assert self._open

    def is_open(self):
        return self._open

    def get_address(self):
        return self.wan_address

    def send(self, socket_address, packet):
        if not self.is_open():
            return
        if socket_address in internet:
            # For the unit tests we handle messages in separate asyncio tasks to prevent infinite recursion.
            ep = internet[socket_address]
            get_event_loop().call_soon(ep.notify_listeners, (self.wan_address, packet))
        else:
            raise AssertionError("Received data from unregistered address %s" % repr(socket_address))

    def open(self):
        self._open = True

    def close(self, timeout=0.0):
        self._open = False


class AddressTester(EndpointListener):

    def on_packet(self, packet):
        pass


class AutoMockEndpoint(MockEndpoint):

    def __init__(self):
        super(AutoMockEndpoint, self).__init__(self._generate_unique_address(), self._generate_unique_address())
        self._port = 0

    def _generate_address(self):
        b0 = random.randint(0, 255)
        b1 = random.randint(0, 255)
        b2 = random.randint(0, 255)
        b3 = random.randint(0, 255)
        port = random.randint(0, 65535)

        return ('%d.%d.%d.%d' % (b0, b1, b2, b3), port)

    def _is_lan(self, address):
        """
        Avoid false positives for the actual machine's lan.
        """
        self._port = address[1]
        address_tester = AddressTester(self)
        return address_tester.address_is_lan(address[0])

    def _generate_unique_address(self):
        address = self._generate_address()

        while address in internet or self._is_lan(address):
            address = self._generate_address()

        return address


class MockEndpointListener(EndpointListener):

    def __init__(self, endpoint, main_thread=False):
        super(MockEndpointListener, self).__init__(endpoint, main_thread)

        self.received_packets = []

        endpoint.add_listener(self)

    def on_packet(self, packet):
        self.received_packets.append(packet)
