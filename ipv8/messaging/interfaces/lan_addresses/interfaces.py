from __future__ import annotations

from functools import lru_cache

from .addressprovider import AddressProvider
from .importshield import Platform, conditional_import_shield


try:
    import netifaces
except ImportError:
    netifaces = None
BLACKLIST = {"127.0.0.1", "127.0.1.1", "0.0.0.0", "255.255.255.255", "::1"}


@lru_cache(maxsize=2)  # One copy of verbose and one copy of non-verbose providers.
def get_providers(verbose: bool = False) -> list[AddressProvider]:
    """
    Construct the ``AddressProvider``s that are applicable for this platform.

    :param verbose: Log any errors that are encountered while fetching addresses.
    """
    providers: list[AddressProvider] = []
    if netifaces is not None:
        # Netifaces is faster but archived since 2021 and unsupported >= Python 3.11
        with conditional_import_shield(Platform.ANY, verbose):
            from .any_os.netifaces import Netifaces
            providers.append(Netifaces(verbose))
    else:
        # Attempt to mimic netifaces with (slower) ctypes and other OS calls.
        with conditional_import_shield(Platform.ANY, verbose):
            from .any_os.getaddrinfo import SocketGetAddrInfo
            providers.append(SocketGetAddrInfo(verbose))
        with conditional_import_shield(Platform.ANY, verbose):
            from .any_os.testnet1 import TestNet1
            providers.append(TestNet1(verbose))
        with conditional_import_shield(Platform.WINDOWS, verbose):
            from .windows.GetAdaptersAddresses import GetAdaptersAddresses
            providers.append(GetAdaptersAddresses(verbose))
        with conditional_import_shield(Platform.LINUX, verbose):
            from .unix.getifaddrs import GetIfAddrs
            providers.append(GetIfAddrs(verbose))
        with conditional_import_shield(Platform.LINUX, verbose):
            from .unix.ioctl import Ioctl
            providers.append(Ioctl(verbose))
    return providers


def get_lan_addresses(verbose: bool = False) -> list[str]:
    """
    Attempt to find the LAN addresses of this machine using whatever means available.

    :param verbose: Log any errors that are encountered while fetching addresses.
    """
    votes: dict[str, int] = {}
    for provider in get_providers(verbose):
        for found in (provider.get_addresses_buffered() - BLACKLIST):
            votes[found] = votes.get(found, 0) + 1
    return sorted(votes.keys(), key=lambda key: votes[key], reverse=True)


__all__ = ["get_lan_addresses"]
