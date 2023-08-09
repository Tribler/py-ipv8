import socket

from ..addressprovider import AddressProvider


class TestNet1(AddressProvider):

    def get_addresses(self) -> set:
        """
        Contact ``TEST-NET-1`` to retrieve addresses.
        """
        interface_specifications = []

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.0", 80))
            local_ip = s.getsockname()[0]
            s.close()
            interface_specifications.append(local_ip)
        except OSError:
            self.on_exception()

        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.connect(("::ffff:0:192.0.2.0", 80))
            local_ip = s.getsockname()[0]
            s.close()
            interface_specifications.append(local_ip)
        except OSError:
            self.on_exception()

        return set(interface_specifications)
