import socket
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    Union,
    c_char_p,
    c_int,
    c_short,
    c_ubyte,
    c_uint,
    c_uint32,
    c_ushort,
    c_void_p,
    cast,
    pointer,
    string_at,
)

from ..addressprovider import AddressProvider

libc = CDLL("libc.so.6", use_errno=True)
libc.getifaddrs.restype = c_int
libc.__errno_location.restype = POINTER(c_int)  # noqa: SLF001
libc.strerror.restype = c_char_p

NETMASK0_V4 = b'\x00' * 4
NETMASK0_V6 = b'\x00' * 16

# ruff: noqa: N801


class sockaddr_in(Structure):
    """
    IPv4 address struct.
    """

    _fields_ = [
        ('sin_family', c_short),
        ("sin_port", c_ushort),
        ("sin_addr", c_ubyte * 4),
        ('sin_zero', c_ubyte * 8)
    ]


class sockaddr_in6(Structure):
    """
    IPv6 address struct.
    """

    _fields_ = [
        ('sin6_family', c_short),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", c_ubyte * 16),
        ('sin6_scope_id', c_uint32)
    ]


class sockaddr(Structure):
    """
    Unknown address struct, can be ``sockaddr_in`` or ``sockaddr_in6``.
    """

    _fields_ = [
        ('sa_family', c_ushort),
        ('sa_data', c_ubyte * 14)  # Placeholder, needs logic to cast.
    ]


class ifa_ifu(Union):
    """
    Union to capture both broadcast addresses and "normal" addresses.
    """

    _fields_ = [
        ('ifu_broadaddr', POINTER(sockaddr)),
        ('ifu_dstaddr', POINTER(sockaddr))
    ]


class ifaddrs(Structure):
    """
    Stub for pointers to the next ``ifaddrs`` struct.
    """


ifaddrs._fields_ = [  # noqa: SLF001
    ('ifa_next', POINTER(ifaddrs)),
    ('ifa_name', c_char_p),
    ('ifa_flags', c_uint),
    ('ifa_addr', POINTER(sockaddr)),
    ('ifa_netmask', POINTER(sockaddr)),
    ('ifa_ifu', ifa_ifu),
    ('ifa_data', c_void_p)
]


class GetIfAddrs(AddressProvider):
    """
    Attempt to find local addresses using the ``getifaddrs`` system call.
    """

    def get_addresses(self) -> set:
        """
        Attempt to use ``getifaddrs()`` to retrieve addresses.
        """
        out_addresses = []

        if_addresses = ifaddrs()
        p_if_adresses = pointer(if_addresses)

        ret = libc.getifaddrs(p_if_adresses)

        if ret != 0:
            try:
                errno = getattr(libc, "__errno_location")()
                p_message = libc.strerror(errno.contents)
                raise ValueError(string_at(p_message).decode())
            except ValueError:
                self.on_exception()
            return set()

        next = p_if_adresses  # noqa: A001
        while next:
            p_address = next.contents.ifa_addr
            netmask_is_zero = False  # Check for netmask "0.0.0.0"
            if next.contents.ifa_netmask:
                family = next.contents.ifa_netmask.contents.sa_family
                if family == 2:
                    socket_desc = cast(next.contents.ifa_netmask, POINTER(sockaddr_in)).contents
                    netmask_is_zero = string_at(socket_desc.sin_addr, 4) == NETMASK0_V4
                elif family == 10:
                    socket_desc6 = cast(next.contents.ifa_netmask, POINTER(sockaddr_in6)).contents
                    netmask_is_zero = string_at(socket_desc6.sin6_addr, 16) == NETMASK0_V6
            if p_address and not netmask_is_zero:
                family = p_address.contents.sa_family
                if family == 2:
                    socket_desc = cast(p_address, POINTER(sockaddr_in)).contents
                    out_addresses.append(socket.inet_ntop(socket.AF_INET, string_at(socket_desc.sin_addr, 4)))
                elif family == 10:
                    socket_desc6 = cast(p_address, POINTER(sockaddr_in6)).contents
                    out_addresses.append(socket.inet_ntop(socket.AF_INET6, string_at(socket_desc6.sin6_addr, 16)))
            next = next.contents.ifa_next  # noqa: A001

        # ctypes takes care of free(), no need to call ``freeifaddrs()``

        return set(out_addresses)
