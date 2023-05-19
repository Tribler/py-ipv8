import abc
import ipaddress
import logging
import socket
import struct
import threading

from .lan_addresses.interfaces import get_lan_addresses


class Endpoint(metaclass=abc.ABCMeta):
    """
    Interface for sending messages over the Internet.
    """

    def __init__(self, prefixlen=22):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._listeners = []
        self._prefix_map = {}
        self.prefixlen = prefixlen
        self.listener_update_lock = threading.RLock()

    def add_listener(self, listener):
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

    def add_prefix_listener(self, listener, prefix):
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
            self._prefix_map[prefix] = self._prefix_map.get(prefix, []) + [listener] + self._listeners

    def remove_listener(self, listener):
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

    def _deliver_later(self, listener, packet):
        """
        Ensure that the listener is still loaded when delivering the packet later.
        """

        if self.is_open() and (packet[1][:self.prefixlen] in self._prefix_map or listener in self._listeners):
            listener.on_packet(packet)

    def notify_listeners(self, packet):
        """
        Send data to all listeners.

        :param data: the data to send to all listeners.
        """
        prefix = packet[1][:self.prefixlen]
        listeners = self._prefix_map.get(prefix, self._listeners)
        for listener in listeners:
            # TODO: Respect listener.use_main_thread:
            self._deliver_later(listener, packet)

    @abc.abstractmethod
    def assert_open(self):
        pass

    @abc.abstractmethod
    def is_open(self):
        pass

    @abc.abstractmethod
    def get_address(self):
        pass

    @abc.abstractmethod
    def send(self, socket_address, packet):
        pass

    @abc.abstractmethod
    def open(self):
        pass

    @abc.abstractmethod
    def close(self):
        pass

    @abc.abstractmethod
    def reset_byte_counters(self):
        pass


class EndpointListener(metaclass=abc.ABCMeta):
    """
    Handler for messages coming in through an Endpoint.
    """

    def __init__(self, endpoint, main_thread=True):
        """
        Create a new listener.

        :param main_thread: run the callback of this listener on the main thread.
        """
        self._use_main_thread = main_thread

        self.endpoint = endpoint

        self._local_interfaces = []
        self._my_estimated_lan = None
        self.my_estimated_wan = self.my_estimated_lan

    @property
    def my_estimated_lan(self):
        """
        Estimate our LAN address and port.

        If the endpoint is closed this returns ("::1", 0) for IPv6 and ("0.0.0.0", 0) otherwise.
        If the endpoint is open and we have no idea what our address is, attempt to estimate it.
        Otherwise, return the current value of the estimated LAN address and port.
        """
        if not self.endpoint.is_open():
            if self.is_ipv6_listener:
                return "::1", 0
            else:
                return "0.0.0.0", 0
        if self._my_estimated_lan is None:
            self._my_estimated_lan = (self._get_lan_address(True)[0], self.endpoint.get_address()[1])
        return self._my_estimated_lan

    @my_estimated_lan.setter
    def my_estimated_lan(self, value):
        self._my_estimated_lan = value

    @property
    def use_main_thread(self):
        """
        Does the callback of this listener need to be executed on the main thread.
        """
        return self._use_main_thread

    @abc.abstractmethod
    def on_packet(self, packet):
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
        """
        pass

    def _is_ipv6_address(self, address):
        """
        Whether the supplied address is IPv6.
        """
        try:
            return isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address)
        except ValueError:
            return False

    @property
    def is_ipv6_listener(self):
        """
        Whether we are on an IPv6 address.
        """
        if self.endpoint.is_open():
            return self._is_ipv6_address(self.endpoint.get_address()[0])
        else:
            return getattr(self.endpoint, "SOCKET_FAMILY", socket.AF_INET) == socket.AF_INET6

    def _address_in_subnet(self, address, subnet):
        """
        Checks whether a given address is in a given subnet
        :param address: an ip v4 address as a string formatted as four pairs of decimals separated by dots
        :param subnet: a tuple consisting of the main address of the subnet formatted as above, and the subnet formatted as
        an int with the number of significant bits in the address.
        :return: True if the address is in the subnet, False otherwise
        """
        address = struct.unpack_from(">L", socket.inet_aton(address))[0]
        (subnet_main, netmask) = subnet
        subnet_main = struct.unpack_from(">L", socket.inet_aton(subnet_main))[0]
        address >>= 32 - netmask
        subnet_main >>= 32 - netmask
        return address == subnet_main

    def address_in_lan_subnets(self, address):
        lan_subnets = (("192.168.0.0", 16),
                       ("172.16.0.0", 12),
                       ("10.0.0.0", 8))
        return any(self._address_in_subnet(address, subnet) for subnet in lan_subnets)

    def address_is_lan(self, address):
        return address in get_lan_addresses()

    def get_ipv6_address(self):
        return self.endpoint.get_address()

    def _get_lan_address(self, bootstrap=False):
        """
        Attempt to get the newest lan ip of this machine.

        :return: lan address
        """
        return self._guess_lan_address(get_lan_addresses()), (0 if bootstrap else self.endpoint.get_address()[1])

    def _guess_lan_address(self, addresses):
        """
        Chooses the most likely Interface instance out of INTERFACES to use as our LAN address.
        """
        for address in addresses:
            if (not (self.is_ipv6_listener and not self._is_ipv6_address(address))
                    and not (not self.is_ipv6_listener and self._is_ipv6_address(address))):
                return address

        return "127.0.0.1"


class IllegalEndpointListenerError(RuntimeError):
    """
    Exception raised when an EndpointListener instance was expected, but not supplied.
    """

    def __init__(self, other):
        message = '%s is not an instance of %s' % (type(other), str(EndpointListener.__name__))
        super(IllegalEndpointListenerError, self).__init__(message)


class EndpointClosedException(Exception):
    """
    Exception raised when an endpoint is expected to be open, but is closed.
    """

    def __init__(self, endpoint):
        super(EndpointClosedException, self).__init__('%s is unexpectedly closed' % type(endpoint))


class DataTooBigException(Exception):
    """
    Exception raised when the data being sent exceeds the maximum size.
    """

    def __init__(self, size, max_size):
        super(DataTooBigException, self).__init__('Tried to send packet of size %s > MAX_SIZE(%d)' % (size, max_size))


class IllegalDestination(Exception):
    """
    Exception raised when trying to send to the 0 address.
    """

    def __init__(self):
        super(IllegalDestination, self).__init__('Attempted to send a message to 0.0.0.0:0.')
