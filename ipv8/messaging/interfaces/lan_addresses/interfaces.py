from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from .importshield import Platform, conditional_import_shield

if TYPE_CHECKING:
    from .addressprovider import AddressProvider

try:
    import netifaces
except ImportError:
    netifaces = None
BLACKLIST = {"127.0.0.1", "127.0.1.1", "0.0.0.0", "255.255.255.255", "::1"}
VERBOSE = False


@lru_cache(maxsize=1)
def get_providers() -> list[AddressProvider]:
    """
    Construct the ``AddressProvider``s that are applicable for this platform.
    """
    providers: list[AddressProvider] = []
    if netifaces is not None:
        # Netifaces is faster but archived since 2021 and unsupported >= Python 3.11
        with conditional_import_shield(Platform.ANY, VERBOSE):
            from .any_os.netifaces import Netifaces
            providers.append(Netifaces(VERBOSE))
    else:
        # Attempt to mimic netifaces with (slower) ctypes and other OS calls.
        with conditional_import_shield(Platform.ANY, VERBOSE):
            from .any_os.getaddrinfo import SocketGetAddrInfo
            providers.append(SocketGetAddrInfo(VERBOSE))
        with conditional_import_shield(Platform.ANY, VERBOSE):
            from .any_os.testnet1 import TestNet1
            providers.append(TestNet1(VERBOSE))
        with conditional_import_shield(Platform.WINDOWS, VERBOSE):
            from .windows.GetAdaptersAddresses import GetAdaptersAddresses
            providers.append(GetAdaptersAddresses(VERBOSE))
        with conditional_import_shield(Platform.LINUX, VERBOSE):
            from .unix.getifaddrs import GetIfAddrs
            providers.append(GetIfAddrs(VERBOSE))
        with conditional_import_shield(Platform.LINUX, VERBOSE):
            from .unix.ioctl import Ioctl
            providers.append(Ioctl(VERBOSE))
    return providers


def get_lan_addresses() -> list[str]:
    """
    Attempt to find the LAN addresses of this machine using whatever means available.
    """
    votes: dict[str, int] = {}
    for provider in get_providers():
        for found in (provider.get_addresses_buffered() - BLACKLIST):
            votes[found] = votes.get(found, 0) + 1
    return sorted(votes.keys(), key=lambda key: votes[key], reverse=True)


__all__ = ["get_lan_addresses", "get_providers"]
