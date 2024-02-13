import socket
import struct
import typing

if typing.TYPE_CHECKING:
    def ioctl(__fd: int, __request: int, __arg: bytes, __mutate_flag: bool = ...) -> bytes:
        """
        Stub for the ioctl call's types.
        """
else:
    from fcntl import ioctl

from ..addressprovider import AddressProvider

SIOCGIFADDR = 0x8915
FMT_SOCKADDR = '16sH14s'
FMT_FAMILY = 'H'


class Ioctl(AddressProvider):
    """
    Attempt to find local addresses using the ``ioctl`` system call.
    """

    def get_addresses(self) -> set:
        """
        Attempt to use ``ioctl()`` to retrieve addresses.

        Note: SIOCGIFADDR only supports AF_INET.
        """
        out_addresses = []

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for ifspec in socket.if_nameindex():
                ifreq = ioctl(s.fileno(), SIOCGIFADDR,
                              struct.pack(FMT_SOCKADDR, ifspec[1].encode(), socket.AF_INET, b'\x00' * 14))
                family, = struct.unpack(FMT_FAMILY, ifreq[16:18])
                if family == socket.AF_INET:
                    out_addresses.append(socket.inet_ntop(socket.AF_INET, ifreq[20:24]))
            s.close()
            s = None
        except OSError:
            self.on_exception()
        finally:
            if s is not None:
                try:
                    s.close()
                    s = None
                except OSError:
                    self.on_exception()

        return set(out_addresses)
