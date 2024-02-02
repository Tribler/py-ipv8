from __future__ import annotations

import ipaddress
import logging
import typing

from ipv8.util import maybe_coroutine

from ..endpoint import Endpoint, EndpointListener
from ..udp.endpoint import UDPEndpoint, UDPv4Address, UDPv6Address, UDPv6Endpoint

if typing.TYPE_CHECKING:
    from ipv8.types import Address

INTERFACES = {
    "UDPIPv4": UDPEndpoint,
    "UDPIPv6": UDPv6Endpoint
}
"""
The INTERFACES dictionary describes the mapping of interface names to interface classes.
"""

PREFERENCE_ORDER = [
    "UDPIPv4",
    "UDPIPv6"
]
"""
The PREFERENCE_ORDER list describes the order of preference for the available interfaces.
For example, ``["UDPIPv4", "UDPIPv6"]`` means: use IPv4 over IPv6, if it is available.
"""


FAST_ADDR_TO_INTERFACE: dict[type, str] = {
    UDPv4Address: "UDPIPv4",
    UDPv6Address: "UDPIPv6"
}
"""
The FAST_ADDR_TO_INTERFACE is an internal DispatcherEndpoint mapping, to quickly route information.
For addresses which do not use these classes the slower ``guess_interface`` will be used.
"""


def guess_interface(socket_address: typing.Any) -> str | None:  # noqa: ANN401
    """
    Attempt to guess the interface for the given address.

    If the given address is a tuple of a valid IPv4 address string and a port this returns "UDPIPv4".
    If the given address is a tuple of a valid IPv6 address string and a port this returns "UDPIPv6".
    Otherwise, this returns None.
    """
    try:
        if (isinstance(socket_address, tuple) and len(socket_address) == 2
                and isinstance(socket_address[0], str) and isinstance(socket_address[1], int)):
            if isinstance(ipaddress.ip_address(socket_address[0]), ipaddress.IPv4Address):
                return "UDPIPv4"
            return "UDPIPv6"
    except Exception:
        logging.exception("Exception occurred while guessing interface for %s", repr(socket_address))
    return None


class DispatcherEndpoint(Endpoint):
    """
    An Endpoint implementation to dispatch to other Endpoint implementations.

    The added complexity is as follows:

     - Receiving of packets is hooked directly into the sub-Endpoints, no speed is lost.
     - Sending packets will be directed to the appropriate interface. If an address object class is not defined in
       FAST_ADDR_TO_INTERFACE, this will have to use ``guess_interface``.
     - Adding and removing listeners will have to be forwarded to all sub-Endpoints.
    """

    def __init__(self, interfaces: list[str], **kwargs) -> None:
        """
        Create a new DispatcherEndpoint by giving a list of interfaces to load (check INTERFACES for available
        interfaces).

        You can optionally supply keyword arguments to launch each selected Endpoint implementation, for example:

         .. code-block :: Python

            DispatcherEndpoint(["UDPIPv4"], UDPIPv4={'port': my_custom_port})

        :param interfaces: list of interfaces to load.
        :param kwargs: optional interface-specific launch arguments.
        :returns: None
        """
        super().__init__()
        # Filter the available interfaces and preference order, based on the user's selection.
        self.interfaces = {interface: INTERFACES[interface](**(kwargs.get(interface, {}))) for interface in interfaces}
        self.interface_order = [interface for interface in PREFERENCE_ORDER if interface in interfaces]
        # The order of preference will not change, we can precompute the preferred interface Endpoint.
        self._preferred_interface = self.interfaces[self.interface_order[0]] if self.interface_order else None

    @property
    def bytes_up(self) -> int:
        """
        Get the number of bytes sent over this endpoint.
        """
        return sum(interface.bytes_up for interface in self.interfaces.values())

    @property
    def bytes_down(self) -> int:
        """
        Get the number of bytes received over this endpoint.
        """
        return sum(interface.bytes_down for interface in self.interfaces.values())

    def add_listener(self, listener: EndpointListener) -> None:
        """
        Reroute a listener to all the interfaces we dispatch to.
        """
        for interface in self.interfaces.values():
            interface.add_listener(listener)

    def add_prefix_listener(self, listener: EndpointListener, prefix: bytes) -> None:
        """
        Reroute a prefix listener to all the interfaces we dispatch to.
        """
        for interface in self.interfaces.values():
            interface.add_prefix_listener(listener, prefix)

    def remove_listener(self, listener: EndpointListener) -> None:
        """
        Remove a listener from all the interfaces we dispatch to.
        """
        for interface in self.interfaces.values():
            interface.remove_listener(listener)

    def notify_listeners(self, packet: tuple[Address, bytes]) -> None:
        """
        Dispatch a new packet to all interfaces.
        """
        for interface in self.interfaces.values():
            interface.notify_listeners(packet)

    def assert_open(self) -> None:
        """
        Perform an assert that we are opened.
        """
        assert self.is_open()

    def is_open(self) -> bool:
        """
        Check if we have ANY open interface.
        """
        return any(interface.is_open() for interface in self.interfaces.values())

    def get_address(self, interface: str | None = None) -> Address:
        """
        Get the most likely interface for our interfaces.
        """
        if interface is not None:
            return self.interfaces[interface].get_address()
        if self._preferred_interface:
            return self._preferred_interface.get_address()
        return "0.0.0.0", 0

    def send(self, socket_address: Address, packet: bytes, interface: str | None = None) -> None:
        """
        Send a packet to a given address over the most likely interface, or a given interface.
        """
        if interface is not None:
            self.interfaces[interface].send(socket_address, packet)
        else:
            ep = self.interfaces.get(typing.cast(str, FAST_ADDR_TO_INTERFACE.get(socket_address.__class__)
                                                      or guess_interface(socket_address)))
            if ep is not None:
                ep.send(socket_address, packet)

    async def open(self) -> bool:
        """
        Open all interfaces.
        """
        any_success = False
        for interface in self.interfaces.values():
            any_success |= await interface.open()
        return any_success

    async def close(self) -> None:
        """
        Close all interfaces.
        """
        for interface in self.interfaces.values():
            await maybe_coroutine(interface.close)

    def reset_byte_counters(self) -> None:
        """
        Reset our counters.
        """
        for interface in self.interfaces.values():
            interface.reset_byte_counters()
