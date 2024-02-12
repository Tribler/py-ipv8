from __future__ import annotations

import abc
import ipaddress
import logging
import socket
import struct
import threading
from typing import TYPE_CHECKING, Awaitable, Iterable

from .lan_addresses.interfaces import get_lan_addresses

if TYPE_CHECKING:
    from ...types import Address


class Endpoint(metaclass=abc.ABCMeta):
    """
    Interface for sending messages over the Internet.
    """

    def __init__(self, prefixlen: int = 22) -> None:
        """
        Create a new endpoint interface.

        :param prefixlen: the number of bytes of each incoming message that is used for multiplexing.
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self._listeners: list[EndpointListener] = []
        self._prefix_map: dict[bytes, list[EndpointListener]] = {}
        self.prefixlen: int = prefixlen
        self.listener_update_lock: threading.RLock = threading.RLock()

    def add_listener(self, listener: EndpointListener) -> None:
        """
        Add an EndpointListener to our listeners.

        :raises: IllegalEndpointListenerError if the provided listener is not an EndpointListener
        """
        if not isinstance(listener, EndpointListener):
            raise IllegalEndpointListenerError(listener)
        with self.listener_update_lock:
            self._listeners.append(listener)
            for prefix in self._prefix_map:
                self._prefix_map[prefix].append(listener)

    def add_prefix_listener(self, listener: EndpointListener, prefix: bytes) -> None:
        """
        Add an EndpointListener to our listeners, only triggers on packets with a specific prefix.

        :raises: IllegalEndpointListenerError if the provided listener is not an EndpointListener
        """
        if not isinstance(listener, EndpointListener):
            raise IllegalEndpointListenerError(listener)
        if not len(prefix) == self.prefixlen:
            raise RuntimeError("Tried to register a prefix of length %d, required to be of length %d!"
                               % (len(prefix), self.prefixlen))
        with self.listener_update_lock:
            self._prefix_map[prefix] = [*self._prefix_map.get(prefix, []), listener, *self._listeners]

    def remove_listener(self, listener: EndpointListener) -> None:
        """
        Remove a listener from our listeners, if it is registered.
        """
        with self.listener_update_lock:
            self._listeners = [l for l in self._listeners if l != listener]
            new_prefix_map = {}
            for prefix in self._prefix_map:
                listeners = [l for l in self._prefix_map[prefix] if l != listener]
                if set(listeners) != set(self._listeners):
                    new_prefix_map[prefix] = listeners
            self._prefix_map = new_prefix_map

    def _deliver_later(self, listener: EndpointListener, packet: tuple[Address, bytes]) -> None:
        """
        Ensure that the listener is still loaded when delivering the packet later.
        """
        if self.is_open() and (packet[1][:self.prefixlen] in self._prefix_map or listener in self._listeners):
            listener.on_packet(packet)

    def notify_listeners(self, packet: tuple[Address, bytes]) -> None:
        """
        Send data to all listeners.
        """
        prefix = packet[1][:self.prefixlen]
        listeners = self._prefix_map.get(prefix, self._listeners)
        for listener in listeners:
            # TODO: Respect listener.use_main_thread:  # noqa: TD002, TD003, FIX002
            self._deliver_later(listener, packet)

    @abc.abstractmethod
    def assert_open(self) -> None:
        """
        Crash with an exception (explaining the situation) if this endpoint is not opened.

        :raises Exception: if this endpoint is not open.
        """

    @abc.abstractmethod
    def is_open(self) -> bool:
        """
        Whether this endpoint is open.
        """

    @abc.abstractmethod
    def get_address(self) -> Address:
        """
        Get the MOST LIKELY external address for this endpoint. This is often wrong!
        """

    @abc.abstractmethod
    def send(self, socket_address: Address, packet: bytes) -> None:
        """
        Try to send data to some address. No delivery guarantees.
        """

    @abc.abstractmethod
    async def open(self) -> bool:
        """
        Attempt to open this endpoint and return if this was successful.
        """

    @abc.abstractmethod
    def close(self) -> None | Awaitable:
        """
        Close this endpoint as quick as possible.
        """

    @abc.abstractmethod
    def reset_byte_counters(self) -> None:
        """
        Reset any internal byte counting mechanisms.
        """


class EndpointListener(metaclass=abc.ABCMeta):
    """
    Handler for messages coming in through an Endpoint.
    """

    def __init__(self, endpoint: Endpoint, main_thread: bool = True) -> None:
        """
        Create a new listener.

        :param main_thread: must run the callback of this listener on the main thread.
        """
        self._use_main_thread = main_thread

        self.endpoint = endpoint

        self._my_estimated_lan = None
        self.my_estimated_wan = self.my_estimated_lan

    @property
    def my_estimated_lan(self) -> Address:
        """
        Estimate our LAN address and port.

        If the endpoint is closed this returns ("::1", 0) for IPv6 and ("0.0.0.0", 0) otherwise.
        If the endpoint is open and we have no idea what our address is, attempt to estimate it.
        Otherwise, return the current value of the estimated LAN address and port.
        """
        if not self.endpoint.is_open():
            if self.is_ipv6_listener:
                return "::1", 0
            return "0.0.0.0", 0
        if self._my_estimated_lan is None:
            self._my_estimated_lan = (self._get_lan_address(True)[0], self.endpoint.get_address()[1])
        return self._my_estimated_lan

    @my_estimated_lan.setter
    def my_estimated_lan(self, value: Address) -> None:
        """
        Set our current estimated lan address.
        """
        self._my_estimated_lan = value

    @property
    def use_main_thread(self) -> bool:
        """
        Does the callback of this listener need to be executed on the main thread.
        """
        return self._use_main_thread

    @abc.abstractmethod
    def on_packet(self, packet: tuple[Address, bytes]) -> None:
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
        """

    def _is_ipv6_address(self, address: str) -> bool:
        """
        Whether the supplied address is IPv6.
        """
        try:
            return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
        except ValueError:
            return False

    @property
    def is_ipv6_listener(self) -> bool:
        """
        Whether we are on an IPv6 address.
        """
        if self.endpoint.is_open():
            return self._is_ipv6_address(self.endpoint.get_address()[0])
        return getattr(self.endpoint, "SOCKET_FAMILY", socket.AF_INET) == socket.AF_INET6

    def _address_in_subnet(self, address: str, subnet: tuple[str, int]) -> bool:
        """
        Checks whether a given address is in a given subnet.

        :param address: an ip v4 address as a string formatted as four pairs of decimals separated by dots
        :param subnet: a tuple consisting of the main address of the subnet formatted as above, and the subnet
        formatted as an int with the number of significant bits in the address.
        :return: True if the address is in the subnet, False otherwise
        """
        iaddress = struct.unpack_from(">L", socket.inet_aton(address))[0]
        (subnet_main, netmask) = subnet
        isubnet_main = struct.unpack_from(">L", socket.inet_aton(subnet_main))[0]
        iaddress >>= 32 - netmask
        isubnet_main >>= 32 - netmask
        return iaddress == isubnet_main

    def address_in_lan_subnets(self, address: str) -> bool:
        """
        Whether the given address exists in any common lan subnet.
        """
        lan_subnets = (("192.168.0.0", 16),
                       ("172.16.0.0", 12),
                       ("10.0.0.0", 8))
        return any(self._address_in_subnet(address, subnet) for subnet in lan_subnets)

    def address_is_lan(self, address: str) -> bool:
        """
        Whether the given address is a lan address.
        """
        return address in get_lan_addresses()

    def get_ipv6_address(self) -> Address:
        """
        Get the IPv6 address of our endpoint.
        """
        return self.endpoint.get_address()

    def _get_lan_address(self, bootstrap: bool = False) -> Address:
        """
        Attempt to get the newest lan ip of this machine.
        """
        return self._guess_lan_address(get_lan_addresses()), (0 if bootstrap else self.endpoint.get_address()[1])

    def _guess_lan_address(self, addresses: Iterable[str]) -> str:
        """
        Chooses the most likely Interface instance out of INTERFACES to use as our LAN address.
        """
        for address in addresses:
            if self.is_ipv6_listener == self._is_ipv6_address(address):
                return address

        return "127.0.0.1"


class IllegalEndpointListenerError(RuntimeError):
    """
    Exception raised when an EndpointListener instance was expected, but not supplied.
    """

    def __init__(self, other: object) -> None:
        """
        Create a new exception for the given non-EndpointListener object.
        """
        message = f"{type(other)} is not an instance of {EndpointListener.__name__}"
        super().__init__(message)


class EndpointClosedException(Exception):
    """
    Exception raised when an endpoint is expected to be open, but is closed.
    """

    def __init__(self, endpoint: Endpoint) -> None:
        """
        Create a new exception for when the given endpoint is closed and interaction was attempted.
        """
        super().__init__(f"{type(endpoint)} is unexpectedly closed")


class DataTooBigException(Exception):
    """
    Exception raised when the data being sent exceeds the maximum size.
    """

    def __init__(self, size: int, max_size: int) -> None:
        """
        Create a a new exception for when the given size (in bytes) exceeds the given maximum size (in bytes).
        """
        super().__init__(f"Tried to send packet of size {size} > MAX_SIZE({max_size})")


class IllegalDestination(Exception):
    """
    Exception raised when trying to send to the 0 address.
    """

    def __init__(self) -> None:
        """
        Create a new exception for when messages are sent to 0.0.0.0:0 (the NULL address).
        """
        super().__init__("Attempted to send a message to 0.0.0.0:0.")
