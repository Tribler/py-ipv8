import socket
from typing import cast

from ..addressprovider import AddressProvider


class SocketGetAddrInfo(AddressProvider):
    """
    Use the ``socket`` library to discover interface addresses.
    """

    def get_addresses(self) -> set:
        """
        Attempt to use ``getaddrinfo()`` to retrieve addresses.

        Ref. ``UnicodeError``: https://github.com/python/cpython/issues/77139.

        :returns: The set of probable local interfaces.
        """
        interface_specifications = []

        try:
            interface_specifications.extend(socket.getaddrinfo(socket.getfqdn(), 0))
        except (OSError, UnicodeError):
            self.on_exception()

        try:
            interface_specifications.extend(socket.getaddrinfo(socket.gethostname(), None))
        except (OSError, UnicodeError):
            self.on_exception()

        try:
            interface_specifications.extend(socket.getaddrinfo(None, 0))
        except (OSError, UnicodeError):
            self.on_exception()

        return {i[4][0] for i in interface_specifications if cast("str", i[4][0]).find(".") != -1}
