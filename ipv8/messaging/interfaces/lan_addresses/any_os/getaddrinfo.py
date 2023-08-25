import socket

from ..addressprovider import AddressProvider


class SocketGetAddrInfo(AddressProvider):
    """
    Use the ``socket`` library to discover interface addresses.
    """

    def get_addresses(self) -> set:
        """
        Attempt to use ``getaddrinfo()`` to retrieve addresses.
        """
        interface_specifications = []

        try:
            interface_specifications.extend(socket.getaddrinfo(socket.getfqdn(), 0))
        except OSError:
            self.on_exception()

        try:
            interface_specifications.extend(socket.getaddrinfo(socket.gethostname(), None))
        except OSError:
            self.on_exception()

        try:
            interface_specifications.extend(socket.getaddrinfo(None, 0))
        except OSError:
            self.on_exception()

        return {i[4][0] for i in interface_specifications if i[4][0].find(".") != -1}
