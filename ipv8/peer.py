from base64 import b64encode
from collections import deque
from struct import unpack
from time import time
from typing import Any, Optional, Tuple

from .keyvault.crypto import default_eccrypto
from .keyvault.keys import Key


class Peer(object):

    def __init__(self, key, address: Optional[Any] = None, intro: bool = True) -> None:
        """
        Create a new Peer.

        :param key: the peer's Key (mostly public) or public key bin
        :param address: the address object for this peer (e.g. ("1.2.3.4", 0) for IPv4 over UDP)
        :param intro: is this peer suggested to us (otherwise it contacted us)
        """
        if not isinstance(key, Key):
            self.key = default_eccrypto.key_from_public_bin(key)
        else:
            self.key = key
        self.mid = self.key.key_to_hash()
        self.public_key = self.key.pub()
        self.addresses = {}
        if address is not None:
            self.addresses[address.__class__] = address
        self.last_response = 0 if intro else time()
        self._lamport_timestamp = 0
        self.pings = deque(maxlen=5)

    @property
    def address(self) -> Tuple[str, int]:
        """
        Deprecated way to retrieve the IPv4 address.

        Use the ``.addresses`` dictionary instead!
        """
        from .messaging.interfaces.udp.endpoint import UDPv4Address
        return self.addresses.get(UDPv4Address, self.addresses.get(tuple, ("0.0.0.0", 0)))

    @address.setter
    def address(self, value: Tuple[str, int]) -> None:
        """
        Deprecated way to set the IPv4 address.

        Use ``add_address()`` instead!
        """
        self.add_address(value)

    def add_address(self, value: Any) -> None:
        """
        Add a known address for this Peer.

        Any object can form an address, but only one type of address can be used per object type.
        For example:

         - Adding instances A(1), B(2) leads to addresses {A: A(1), B: B(2)}
         - Adding instances A(1), B(2), A(3) leads to addresses {A: A(3), B: B(2)}
        """
        self.addresses[value.__class__] = value

    def get_median_ping(self):
        """
        Get the median ping time of this peer.

        :return: the median ping or None if no measurements were performed yet
        :rtype: float or None
        """
        if not self.pings:
            return None
        sorted_pings = sorted(self.pings)
        if len(sorted_pings) % 2 == 0:
            return (sorted_pings[len(sorted_pings) // 2 - 1] + sorted_pings[len(sorted_pings) // 2]) / 2
        else:
            return sorted_pings[len(sorted_pings) // 2]

    def get_average_ping(self):
        """
        Get the average ping time of this peer.

        :return: the average ping or None if no measurements were performed yet
        :rtype: float or None
        """
        if not self.pings:
            return None
        return sum(self.pings) / len(self.pings)

    def update_clock(self, timestamp):
        """
        Update the Lamport timestamp for this peer. The Lamport clock dictates that the current timestamp is
        the maximum of the last known and the most recently delivered timestamp. This is useful when messages
        are delivered asynchronously.

        We also keep a real time timestamp of the last received message for timeout purposes.

        :param timestamp: a received timestamp
        """
        self._lamport_timestamp = max(self._lamport_timestamp, timestamp)
        self.last_response = time()  # This is in seconds since the epoch

    def get_lamport_timestamp(self):
        return self._lamport_timestamp

    def __hash__(self):
        as_long, = unpack(">Q", self.mid[:8])
        return as_long

    def __eq__(self, other):
        if not isinstance(other, Peer):
            return False
        return self.public_key.key_to_bin() == other.public_key.key_to_bin()

    def __ne__(self, other):
        if not isinstance(other, Peer):
            return True
        return self.public_key.key_to_bin() != other.public_key.key_to_bin()

    def __str__(self):
        return 'Peer<%s:%d, %s>' % (self.address[0], self.address[1], b64encode(self.mid).decode('utf-8'))
