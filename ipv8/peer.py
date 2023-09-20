from __future__ import annotations

from base64 import b64encode
from collections import deque
from struct import unpack
from time import time
from typing import TYPE_CHECKING, Any, cast

from .keyvault.crypto import default_eccrypto
from .keyvault.keys import Key
from .messaging.interfaces.udp.endpoint import UDPv4Address, UDPv6Address

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .types import Address


class DirtyDict(dict):
    """
    Dictionary that becomes dirty when elements are changed.
    """

    def __init__(self, **kwargs) -> None:
        """
        Create a new dict that flags when its content has been updated.
        """
        super().__init__(**kwargs)
        self.dirty = True

    def __setitem__(self, key: Any, value: Any) -> None: # noqa: ANN401
        """
        Callback for when an item is set to a value. This dirties the dict.
        """
        super().__setitem__(key, value)
        self.dirty = True

    def update(self, mapping: Mapping, **kwargs) -> None:  # type: ignore[override]
        """
        Callback for when another mapping is merged into this dict. This dirties the dict.
        """
        super().update(mapping, **kwargs)
        self.dirty = True

    def clear(self) -> None:
        """
        Callback for when all items are removed. This dirties the dict.
        """
        super().clear()
        self.dirty = True

    def pop(self, key: Any) -> Any:  # type: ignore[override]  # noqa: ANN401
        """
        Callback for when a particular item is popped. This dirties the dict.
        """
        out = super().pop(key)
        self.dirty = True
        return out

    def popitem(self) -> Any:  # noqa: ANN401
        """
        Callback for when an item is popped. This dirties the dict.
        """
        out = super().popitem()
        self.dirty = True
        return out


class Peer:
    """
    A public key that has additional information attached to it (like an IP address, measured RTT, etc.).
    """

    INTERFACE_ORDER = [UDPv6Address, UDPv4Address, tuple]

    def __init__(self, key: Key | bytes, address: Address | None = None, intro: bool = True) -> None:
        """
        Create a new Peer.

        :param key: the peer's Key (mostly public) or public key bin
        :param address: the address object for this peer (e.g. ("1.2.3.4", 0) for IPv4 over UDP)
        :param intro: is this peer suggested to us (otherwise it contacted us)
        """
        if not isinstance(key, Key):
            self.key: Key = default_eccrypto.key_from_public_bin(key)
        else:
            self.key = cast(Key, key)
        self.public_key = self.key.pub()
        self.mid = self.public_key.key_to_hash()
        self._addresses = DirtyDict()
        if address is not None:
            self._addresses[address.__class__] = address
        self._address = address
        self.creation_time = time()
        self.last_response = 0 if intro else time()
        self._lamport_timestamp = 0
        self.pings: deque = deque(maxlen=5)
        self.new_style_intro = False

    @property
    def addresses(self) -> dict[type[Address], Address]:
        """
        Retrieve the addresses belonging to this Peer.

        You are not allowed to set this addresses dict for a Peer manually.
        You can change the dictionary itself by setting its items or calling its functions, for example ``update()``.
        """
        return self._addresses

    @property
    def address(self) -> Address:
        """
        Retrieve the preferred address for this Peer.

        If you want to manually select the interface, use the ``.addresses`` dictionary instead.
        """
        if self._addresses.dirty:
            self._update_preferred_address()
        return self._address or UDPv4Address("0.0.0.0", 0)

    @address.setter
    def address(self, value: Address) -> None:
        """
        Register an address of this peer.

        Alias of ``add_address(value)``.
        """
        self.add_address(value)

    def add_address(self, value: Any) -> None:  # noqa: ANN401
        """
        Add a known address for this Peer.

        Any object can form an address, but only one type of address can be used per object type.
        For example (normally A, B and C are ``namedtuple`` types):

         - Adding instances A(1), B(2) leads to addresses {A: A(1), B: B(2)}
         - Adding instances A(1), B(2), A(3) leads to addresses {A: A(3), B: B(2)}
        """
        self._addresses[value.__class__] = value
        self._update_preferred_address()

    def _update_preferred_address(self) -> None:
        """
        Update the current address to be the most preferred.
        """
        for interface in self.INTERFACE_ORDER:
            if interface in self._addresses:
                self._address = self._addresses[interface]
                break
        self._addresses.dirty = False

    def get_median_ping(self) -> float | None:
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
        return sorted_pings[len(sorted_pings) // 2]

    def get_average_ping(self) -> float | None:
        """
        Get the average ping time of this peer.

        :return: the average ping or None if no measurements were performed yet
        :rtype: float or None
        """
        if not self.pings:
            return None
        return sum(self.pings) / len(self.pings)

    def update_clock(self, timestamp: int) -> None:
        """
        Update the Lamport timestamp for this peer. The Lamport clock dictates that the current timestamp is
        the maximum of the last known and the most recently delivered timestamp. This is useful when messages
        are delivered asynchronously.

        We also keep a real time timestamp of the last received message for timeout purposes.

        :param timestamp: a received timestamp
        """
        self._lamport_timestamp = max(self._lamport_timestamp, timestamp)
        self.last_response = time()  # This is in seconds since the epoch

    def get_lamport_timestamp(self) -> int:
        """
        Get the Lamport timestamp of this peer.
        """
        return self._lamport_timestamp

    def __hash__(self) -> int:
        """
        Generate a hash based on the mid of this peer.
        """
        as_long, = unpack(">Q", self.mid[:8])
        return as_long

    def __eq__(self, other: object) -> bool:
        """
        Check if the other instance is a peer with the same public key.
        """
        if not isinstance(other, Peer):
            return False
        return self.public_key.key_to_bin() == other.public_key.key_to_bin()

    def __ne__(self, other: object) -> bool:
        """
        Check if the other instance is NOT a peer with the same public key.
        """
        if not isinstance(other, Peer):
            return True
        return self.public_key.key_to_bin() != other.public_key.key_to_bin()

    def __str__(self) -> str:
        """
        Represent this peer as a human-readable string.
        """
        return 'Peer<%s:%d, %s>' % (self.address[0], self.address[1], b64encode(self.mid).decode('utf-8'))
