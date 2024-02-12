from __future__ import annotations

from typing import TYPE_CHECKING

from .....messaging.interfaces.dispatcher.endpoint import (
    FAST_ADDR_TO_INTERFACE,
    INTERFACES,
    PREFERENCE_ORDER,
    DispatcherEndpoint,
    guess_interface,
)
from .....messaging.interfaces.endpoint import Endpoint, EndpointListener
from .....messaging.interfaces.udp.endpoint import UDPv4Address
from ....base import TestBase

if TYPE_CHECKING:
    from .....types import Address


class DummyEndpointListener(EndpointListener):
    """
    This class simply listens on an endpoint and stores incoming packets in a list.
    """

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Wrap the given endpoint.
        """
        super().__init__(endpoint)
        self.incoming = []

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for incoming packets.
        """
        self.incoming.append(packet)


class DummyEndpoint(Endpoint):
    """
    Non-functional endpoint for manual staging and inspection.
    """

    def __init__(self) -> None:
        """
        Create a new dummy endpoint.
        """
        super().__init__(prefixlen=1)

        self.opened = False
        self.sent = []
        self.bytes_up = 0
        self.bytes_down = 0

    def assert_open(self) -> None:
        """
        Assert open state as usual.
        """
        assert self.opened

    def is_open(self) -> bool:
        """
        Check if opened as usual.
        """
        return self.opened

    def get_address(self) -> Address:
        """
        Give a fake localhost IPv4 address.
        """
        return UDPv4Address("127.0.0.1", 1337)

    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Intercept and store sends without actually sending.
        """
        self.bytes_up += len(packet)
        self.sent.append((socket_address, packet))

    async def open(self) -> bool:
        """
        Do a fake open.
        """
        self.opened = True
        return True

    def close(self) -> None:
        """
        Close as usual.
        """
        self.opened = False

    def reset_byte_counters(self) -> None:
        """
        Reset counters as usual.
        """
        self.bytes_up = 0
        self.bytes_down = 0

    def notify_listeners(self, packet: tuple[Address, bytes]) -> None:
        """
        Perform usual notification.
        """
        socket_address, data = packet
        self.bytes_down += len(data)
        super().notify_listeners(packet)


FAST_ADDR_TO_INTERFACE.clear()
FAST_ADDR_TO_INTERFACE.update({tuple: "Dummy"})
INTERFACES.clear()
INTERFACES.update({"Dummy": DummyEndpoint})
PREFERENCE_ORDER.clear()
PREFERENCE_ORDER.append("Dummy")


class TestDispatcherEndpoint(TestBase):
    """
    This class contains various tests for the DispatcherEndpoint.
    """

    RANDOM_DATA = b"data"

    @staticmethod
    async def _produce_dummy() -> tuple[DispatcherEndpoint, DummyEndpoint, DummyEndpointListener]:
        """
        Create and open a DispatcherEndpoint, dispatching to a dummy endpoint and listener.
        """
        endpoint = DispatcherEndpoint(["Dummy"])
        child_endpoint = next(iter(endpoint.interfaces.values()))
        listener = DummyEndpointListener(endpoint)
        endpoint.add_listener(listener)
        await endpoint.open()
        return endpoint, child_endpoint, listener

    async def test_initialize_no_interfaces(self) -> None:
        """
        Check if the DispatcherEndpoint can initialize and "send" without interfaces.

        This is black-hole functionality and should not crash (though we can't really assert anything here).
        """
        endpoint = DispatcherEndpoint([])
        endpoint.send(("0.0.0.0", 0), TestDispatcherEndpoint.RANDOM_DATA)

    async def test_dispatch_receive(self) -> None:
        """
        Check if packet reception is correctly propagated from children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()
        packet = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA

        child_endpoint.notify_listeners(packet)

        self.assertEqual(1, len(listener.incoming))
        self.assertEqual(packet, listener.incoming[0])

    async def test_dispatch_send(self) -> None:
        """
        Check if packet sending is correctly propagated to children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()
        packet = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA

        endpoint.send(*packet)

        self.assertEqual(1, len(child_endpoint.sent))
        self.assertEqual(packet, child_endpoint.sent[0])

    async def test_dispatch_send_specific(self) -> None:
        """
        Check if packet sending is correctly propagated to children, with specific interface.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()
        packet = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA

        endpoint.send(*packet, interface="Dummy")

        self.assertEqual(1, len(child_endpoint.sent))
        self.assertEqual(packet, child_endpoint.sent[0])

    async def test_is_open(self) -> None:
        """
        Check if is_open is correctly propagated from children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()

        # The Child Endpoint is open and the Dispatcher Endpoint propagates the child's status.
        self.assertTrue(child_endpoint.is_open())
        self.assertTrue(endpoint.is_open())

        # Close the Dispatcher Endpoint.
        await endpoint.close()

        # The Child Endpoint is closed and the Dispatcher Endpoint propagates the child's status.
        self.assertFalse(child_endpoint.is_open())
        self.assertFalse(endpoint.is_open())
        self.assertRaises(AssertionError, endpoint.assert_open)

    async def test_remove_listener(self) -> None:
        """
        Check if remove_listener is correctly propagated to children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()
        packet = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA

        # Registered listeners receive data.
        endpoint.notify_listeners(packet)
        self.assertEqual(1, len(listener.incoming))

        # Remove the listener from the Dispatcher Endpoint.
        endpoint.remove_listener(listener)

        # Unregistered listeners no longer receive data.
        endpoint.notify_listeners(packet)
        self.assertEqual(1, len(listener.incoming))

    async def test_byte_counters(self) -> None:
        """
        Check if byte counters are correctly propagated from children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()
        packet = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA

        self.assertEqual(0, endpoint.bytes_up)
        self.assertEqual(0, endpoint.bytes_down)

        # 2x RANDOM_DATA up and 1x RANDOM_DATA down.
        endpoint.send(*packet)
        endpoint.send(*packet)
        child_endpoint.notify_listeners(packet)

        self.assertEqual(2 * len(TestDispatcherEndpoint.RANDOM_DATA), endpoint.bytes_up)
        self.assertEqual(len(TestDispatcherEndpoint.RANDOM_DATA), endpoint.bytes_down)

        # Back to 0.
        endpoint.reset_byte_counters()

        self.assertEqual(0, endpoint.bytes_up)
        self.assertEqual(0, endpoint.bytes_down)

    async def test_get_address(self) -> None:
        """
        Check if get_address is correctly propagated from children.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()

        self.assertEqual(UDPv4Address("127.0.0.1", 1337), endpoint.get_address())

    async def test_get_address_specific(self) -> None:
        """
        Check if get_address is correctly propagated from children, with specific interface.
        """
        endpoint, child_endpoint, listener = await self._produce_dummy()

        self.assertEqual(UDPv4Address("127.0.0.1", 1337), endpoint.get_address(interface="Dummy"))

    async def test_add_prefix_listener(self) -> None:
        """
        Check if add_prefix_listener is correctly propagated to children.
        """
        endpoint, child_endpoint, listener1 = await self._produce_dummy()
        listener2 = DummyEndpointListener(endpoint)
        endpoint.add_prefix_listener(listener2, b"s")
        packet1 = ("1.2.3.4", 5), TestDispatcherEndpoint.RANDOM_DATA
        packet2 = ("1.2.3.4", 5), b"sata"

        child_endpoint.notify_listeners(packet1)
        child_endpoint.notify_listeners(packet2)

        # Prefix listener should've ignored "data" and only received "sata".
        self.assertEqual(2, len(listener1.incoming))
        self.assertEqual(1, len(listener2.incoming))

    async def test_guess_interface_ipv4(self) -> None:
        """
        Check if guess_interface guesses IPv4 interfaces correctly.
        """
        self.assertEqual("UDPIPv4", guess_interface(("1.2.3.4", 5)))

    async def test_guess_interface_ipv6(self) -> None:
        """
        Check if guess_interface guesses IPv6 interfaces correctly.
        """
        self.assertEqual("UDPIPv6", guess_interface(("2001:0db8:0000:0000:0000:ff00:0042:8329", 5)))

    async def test_guess_interface_ipv6_short(self) -> None:
        """
        Check if guess_interface guesses shortened IPv6 interfaces correctly.
        """
        self.assertEqual("UDPIPv6", guess_interface(("2001:db8:0:0:0:ff00:42:8329", 5)))

    async def test_guess_interface_ipv6_very_short(self) -> None:
        """
        Check if guess_interface guesses zero-omitted IPv6 interfaces correctly.
        """
        self.assertEqual("UDPIPv6", guess_interface(("2001:db8::ff00:42:8329", 5)))

    async def test_guess_interface_ipv6_ipv4map(self) -> None:
        """
        Check if guess_interface guesses IPv4 mapped onto IPv6 interfaces correctly.
        """
        self.assertEqual("UDPIPv6", guess_interface(("::ffff:192.0.2.128", 5)))

    async def test_guess_interface_unknown(self) -> None:
        """
        Check if guess_interface guesses None if the interface is invalid.
        """
        self.assertIsNone(guess_interface(("2001:db8:::ff00:42:8329", 5)))
