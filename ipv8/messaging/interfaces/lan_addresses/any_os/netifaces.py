import ipaddress
import socket

import netifaces

from ..addressprovider import AddressProvider

NETMASK0_V6 = socket.inet_ntop(socket.AF_INET6, b'\x00' * 16)


class Netifaces(AddressProvider):
    """
    Use the ``netifaces`` library to discover local interface addresses.
    """

    def get_addresses(self) -> set:  # noqa: C901
        """
        Use ``netifaces.ifaddresses`` to retrieve addresses.
        """
        out_addresses = []

        try:
            for interface in netifaces.interfaces():
                try:
                    addresses = netifaces.ifaddresses(interface)
                except ValueError:
                    # some interfaces are given that are invalid, we encountered one called ppp0
                    continue

                # IPv4 addresses
                for option in addresses.get(netifaces.AF_INET, []):
                    if option.get("netmask") == "0.0.0.0":
                        continue  # The network interface isn't bound to any network, so we skip it
                    address = option.get("addr")
                    if address is not None:
                        out_addresses.append(address)

                # IPv6 addresses
                for option in addresses.get(netifaces.AF_INET6, []):
                    netmask = option.get("netmask")
                    if (netmask is not None
                            and ipaddress.IPv6Network(netmask, strict=False).network_address == NETMASK0_V6):
                        continue  # The network interface isn't bound to any network, so we skip it
                    address = option.get("addr")
                    if address is not None:
                        selector = address.find("%")
                        if selector != -1:
                            address = address[:selector]
                        out_addresses.append(address)
        except OSError:
            self.on_exception()

        return set(out_addresses)
