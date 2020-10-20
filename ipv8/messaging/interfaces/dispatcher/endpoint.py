import ipaddress
import logging
import typing

from ..endpoint import Endpoint
from ..udp.endpoint import UDPEndpoint, UDPv4Address, UDPv6Address, UDPv6Endpoint

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


FAST_ADDR_TO_INTERFACE = {
    UDPv4Address: "UDPIPv4",
    UDPv6Address: "UDPIPv6"
}
"""
The FAST_ADDR_TO_INTERFACE is an internal DispatcherEndpoint mapping, to quickly route information.
For addresses which do not use these classes the slower ``guess_interface`` will be used.
"""


def guess_interface(socket_address: typing.Any):
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
            else:
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

    def __init__(self, interfaces: typing.List[str], **kwargs) -> None:
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
        super(DispatcherEndpoint, self).__init__()
        # Filter the available interfaces and preference order, based on the user's selection.
        self.interfaces = {interface: INTERFACES[interface](**(kwargs.get(interface, {}))) for interface in interfaces}
        self.interface_order = [interface for interface in PREFERENCE_ORDER if interface in interfaces]
        # The order of preference will not change, we can precompute the preferred interface Endpoint.
        self._preferred_interface = self.interfaces[self.interface_order[0]] if self.interface_order else None

    @property
    def bytes_up(self):
        return sum(interface.bytes_up for interface in self.interfaces.values())

    @property
    def bytes_down(self):
        return sum(interface.bytes_down for interface in self.interfaces.values())

    def add_listener(self, listener) -> None:
        for interface in self.interfaces.values():
            interface.add_listener(listener)

    def add_prefix_listener(self, listener, prefix) -> None:
        for interface in self.interfaces.values():
            interface.add_prefix_listener(listener, prefix)

    def remove_listener(self, listener) -> None:
        for interface in self.interfaces.values():
            interface.remove_listener(listener)

    def notify_listeners(self, packet) -> None:
        for interface in self.interfaces.values():
            interface.notify_listeners(packet)

    def assert_open(self) -> None:
        assert self.is_open()

    def is_open(self) -> bool:
        return any(interface.is_open() for interface in self.interfaces.values())

    def get_address(self, interface=None) -> typing.Optional[typing.Any]:
        if interface is not None:
            return self.interfaces[interface].get_address()
        elif self._preferred_interface:
            return self._preferred_interface.get_address()
        return None

    def send(self, socket_address, packet, interface=None) -> None:
        if interface is not None:
            self.interfaces[interface].send(socket_address, packet)
        else:
            interface = self.interfaces.get(FAST_ADDR_TO_INTERFACE.get(socket_address.__class__)
                                            or guess_interface(socket_address))
            if interface is not None:
                interface.send(socket_address, packet)

    async def open(self) -> None:
        for interface in self.interfaces.values():
            await interface.open()

    def close(self) -> None:
        for interface in self.interfaces.values():
            interface.close()

    def reset_byte_counters(self) -> None:
        for interface in self.interfaces.values():
            interface.reset_byte_counters()
