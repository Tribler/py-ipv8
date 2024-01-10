from __future__ import annotations

import ipaddress
import os
import random
from asyncio import get_running_loop
from typing import TYPE_CHECKING

from ...messaging.interfaces.endpoint import Endpoint, EndpointListener
from ...messaging.interfaces.udp.endpoint import UDPv4Address, UDPv6Address

if TYPE_CHECKING:
    from ...types import Address

internet = {}


async def crash_event_loop(forwarded_exception: Exception) -> None:
    """
    Raise an exception on the event loop.

    :param forwarded_exception: the exception instance to raise.
    """
    raise forwarded_exception


class MockEndpoint(Endpoint):
    """
    Endpoint that registers an address in the "internet" dictionary instead of using The Internet.
    """

    SEND_INET_EXCEPTION_TO_LOOP = True
    """
    Raise an uncaught AssertionError on the ``asyncio`` event loop if attempting to send to an unknown address.
    Useful for use in defensively-programmed code: bypasses most exception handling.
    """

    def __init__(self, lan_address: Address, wan_address: Address) -> None:
        """
        Register a LAN and a WAN address.
        """
        super().__init__()
        internet[lan_address] = self
        internet[wan_address] = self

        self.lan_address = lan_address
        self.wan_address = wan_address

        self._port = self.lan_address[1]
        self._open = False

    def assert_open(self) -> None:
        """
        Throw an assertion error if this endpoint is not open.
        """
        assert self._open

    def is_open(self) -> bool:
        """
        Check if this endpoint is open.
        """
        return self._open

    def get_address(self) -> Address:
        """
        Get our own registered WAN address.
        """
        return self.wan_address

    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Route a message through the "internet" dictionary.

        WARNING: We schedule a call on the event loop. Otherwise, you can easily create infinite loops!
        """
        if not self.is_open():
            return
        if socket_address in internet:
            # For the unit tests we handle messages in separate asyncio tasks to prevent infinite recursion.
            ep = internet[socket_address]
            get_running_loop().call_soon(ep.notify_listeners, (self.wan_address, packet))
        else:
            e = AssertionError("Attempted to send data to unregistered address %s" % repr(socket_address))
            if self.SEND_INET_EXCEPTION_TO_LOOP:
                get_running_loop().create_task(crash_event_loop(e))
            raise e

    def open(self) -> None:  # noqa: A003
        """
        Set this endpoint to be open.
        """
        self._open = True

    def close(self, timeout: float = 0.0) -> None:
        """
        Close this endpoint.
        """
        self._open = False

    def reset_byte_counters(self) -> None:
        """
        Reset our byte counters (we have none).
        """


class AddressTester(EndpointListener):
    """
    Generating addresses that are on our physical machine's actual physical LAN can lead to issues.
    """

    singleton = None

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Use an endpoint to determine whether addresses are on the actual LAN.
        """
        super().__init__(endpoint, True)
        self._get_lan_address(True)
        AddressTester.singleton = self

    @classmethod
    def get_singleton(cls: type[AddressTester], endpoint: Endpoint) -> AddressTester:
        """
        Create a singleton AddressTester, you only need one.
        """
        if cls.singleton is not None:
            return cls.singleton
        return AddressTester(endpoint)

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        This should never be called.
        """

    def is_lan(self, address: str) -> bool:
        """
        Check if the given address is on our physical LAN.
        """
        return self.address_is_lan(address)


class AutoMockEndpoint(MockEndpoint):
    """
    Randomly generate LAN + WAN addresses that are globally unique and register them in the "internet" dictionary.
    """

    IPV6_ADDRESSES = bool(int(os.environ.get("TEST_IPV8_WITH_IPV6", 0)))

    def __init__(self) -> None:
        """
        Create a new AutoMockEndpoint.
        """
        self._open = False
        super().__init__(self._generate_unique_address(), self._generate_unique_address())
        self._port = 0

    def _generate_address(self) -> UDPv4Address | UDPv6Address:
        if not self.IPV6_ADDRESSES:
            b0 = random.randint(0, 255)
            b1 = random.randint(0, 255)
            b2 = random.randint(0, 255)
            b3 = random.randint(0, 255)
            port = random.randint(0, 65535)

            return UDPv4Address('%d.%d.%d.%d' % (b0, b1, b2, b3), port)

        b0 = random.randint(0, 65535)
        b1 = random.randint(0, 65535)
        b2 = random.randint(0, 65535)
        b3 = random.randint(0, 65535)
        b4 = random.randint(0, 65535)
        b5 = random.randint(0, 65535)
        b6 = random.randint(0, 65535)
        b7 = random.randint(0, 65535)
        port = random.randint(0, 65535)

        exploded_ip = f"{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}:{b6:02x}:{b7:02x}"
        # Our tests assume that the valid (exploded) ip is formatted using `ip_address`.
        # You will get random failures if you fail to normalize (see https://github.com/Tribler/py-ipv8/issues/1243).
        return UDPv6Address(str(ipaddress.ip_address(exploded_ip)), port)

    def _is_lan(self, address: Address) -> bool:
        """
        Avoid false positives for the actual machine's lan.
        """
        self._port = address[1]
        address_tester = AddressTester.get_singleton(self)
        return address_tester.is_lan(address[0])

    def _generate_unique_address(self) -> Address:
        address = self._generate_address()

        while address in internet or self._is_lan(address):
            address = self._generate_address()

        return address


class MockEndpointListener(EndpointListener):
    """
    Listener that simply stores all data sent to it.
    """

    def __init__(self, endpoint: Endpoint, main_thread: bool = False) -> None:
        """
        Create a new MockEndpointListener.
        """
        super().__init__(endpoint, main_thread)

        self.received_packets = []

        endpoint.add_listener(self)

    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when packets are received: simply store them.
        """
        self.received_packets.append(packet)
