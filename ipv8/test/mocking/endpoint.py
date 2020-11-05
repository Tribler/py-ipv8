import random
from asyncio import get_event_loop

from ...messaging.interfaces.endpoint import Endpoint, EndpointListener
from ...messaging.interfaces.udp.endpoint import UDPv4Address, UDPv6Address

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

    def reset_byte_counters(self):
        pass


class AddressTester(EndpointListener):

    def on_packet(self, packet):
        pass

    def is_lan(self, address):
        if isinstance(address, UDPv4Address):
            return self._address_is_lan_without_netifaces(address)
        return False


class AutoMockEndpoint(MockEndpoint):

    ADDRESS_TYPE = "UDPv4Address"

    def __init__(self):
        self._open = False
        super(AutoMockEndpoint, self).__init__(self._generate_unique_address(), self._generate_unique_address())
        self._port = 0

    def _generate_address(self):
        if self.ADDRESS_TYPE == "UDPv4Address":
            b0 = random.randint(0, 255)
            b1 = random.randint(0, 255)
            b2 = random.randint(0, 255)
            b3 = random.randint(0, 255)
            port = random.randint(0, 65535)

            return UDPv4Address('%d.%d.%d.%d' % (b0, b1, b2, b3), port)
        elif self.ADDRESS_TYPE == "UDPv6Address":
            b0 = random.randint(0, 65535)
            b1 = random.randint(0, 65535)
            b2 = random.randint(0, 65535)
            b3 = random.randint(0, 65535)
            b4 = random.randint(0, 65535)
            b5 = random.randint(0, 65535)
            b6 = random.randint(0, 65535)
            b7 = random.randint(0, 65535)
            port = random.randint(0, 65535)

            return UDPv6Address('%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x' % (b0, b1, b2, b3, b4, b5, b6, b7), port)
        else:
            raise RuntimeError("Illegal address type specified: " + repr(self.ADDRESS_TYPE))

    def _is_lan(self, address):
        """
        Avoid false positives for the actual machine's lan.
        """
        self._port = address[1]
        address_tester = AddressTester(self)
        return address_tester.is_lan(address[0])

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
