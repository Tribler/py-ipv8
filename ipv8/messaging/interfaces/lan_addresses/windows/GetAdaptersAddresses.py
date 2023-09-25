from __future__ import annotations

import socket
import typing
from ctypes import (
    POINTER,
    Structure,
    Union,
    c_short,
    c_size_t,
    c_ubyte,
    c_uint,
    c_uint64,
    c_ulonglong,
    c_ushort,
    cast,
    pointer,
    string_at,
)
from ctypes.wintypes import BOOL, BYTE, DWORD, HANDLE, INT, LONG, LPVOID, PCHAR, PWCHAR, ULONG, WCHAR

# ruff: noqa: N801, N803, N806, SLF001

if typing.TYPE_CHECKING:
    from ctypes import CDLL, _Pointer, c_ulong, c_void_p

    class WinDLL(CDLL):
        """
        Stub for WinDLL instance types.
        """

        class _HeapAlloc(typing.Protocol, typing.SupportsInt):
            restype: type[LPVOID]
            argtypes: list

            def __call__(self, hHeap: c_void_p, dwFlags: DWORD, dwBytes: c_size_t) -> _Pointer:
                ...

        HeapAlloc: _HeapAlloc

        class _GetProcessHeap(typing.Protocol, typing.SupportsInt):
            restype: type[HANDLE]
            argtypes: list

            def __call__(self) -> _Pointer:
                ...  # incomplete

        GetProcessHeap: _GetProcessHeap

        class _HeapFree(typing.Protocol, typing.SupportsInt):
            restype: type[BOOL]
            argtypes: list

            def __call__(self, hHeap: c_void_p, dwFlags: DWORD, lpMem: _Pointer) -> _Pointer:
                ...

        HeapFree: _HeapFree

    class windll:
        """
        Stub for windll library loader types.
        """

        def __getattr__(self, name: str) -> typing.Any:  # noqa: ANN401
            """
            Stub for all calls to ``windll``.
            """
            ...  # incomplete

        class iphlpapi:
            """
            Stub for iphlpapi library loader types.
            """

            def __getattr__(self, name: str) -> typing.Any:  # noqa: ANN401
                """
                Stub for all calls to ``iphlpapi``.
                """
                ...  # incomplete

            class _GetAdaptersAddresses(typing.Protocol, typing.SupportsInt):  # noqa: PYI046
                def __call__(self, Family: c_ulong, Flags: c_ulong, Reserved: int,
                             AdapterAddresses: _Pointer, SizePointer: _Pointer) -> int:
                    ...

            GetAdaptersAddresses: _GetAdaptersAddresses
else:
    from ctypes import WinDLL, windll

from ..addressprovider import AddressProvider

# The default ctypes kernel32 doesn't have the heap functions we need.
# We bind them (restype + argtypes) later.
actual_kernel32 = WinDLL('kernel32')

# C consts
AF_UNSPEC = ULONG(0)
GAA_FLAG_INCLUDE_PREFIX = ULONG(0x0010)

# Python consts
ERROR_BUFFER_OVERFLOW = 111
MAX_ADAPTER_ADDRESS_LENGTH = 8
MAX_DHCPV6_DUID_LENGTH = 130
MAX_DNS_SUFFIX_STRING_LENGTH = 256

# C dtypes
IF_INDEX = DWORD
IFTYPE = DWORD
IF_OPER_STATUS = DWORD
IP_DAD_STATE = DWORD
IP_PREFIX_ORIGIN = DWORD
IP_SUFFIX_ORIGIN = DWORD
LPSOCKADDR = PCHAR  # Placeholder, needs logic to cast: len 16 -> SOCKADDR_IN, len 28 -> SOCKADDR_IN6
NET_IF_COMPARTMENT_ID = DWORD
NET_IF_CONNECTION_TYPE = c_uint
NET_IF_NETWORK_GUID = c_ubyte * 16
TUNNEL_TYPE = c_uint

# C func shortcuts
_GetAdaptersAddresses = windll.iphlpapi.GetAdaptersAddresses

# C custom func binds
HeapAlloc = actual_kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [HANDLE, DWORD, c_size_t]

GetProcessHeap = actual_kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

HeapFree = actual_kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [HANDLE, DWORD, LPVOID]


class SOCKADDR_IN(Structure):
    """
    IPv4 address struct.
    """

    _fields_ = [
        ("sin_family", c_short),
        ("sin_port", c_ushort),
        ("sin_addr", c_ubyte * 4),
        ("sin_zero", c_ubyte * 8)
    ]


class SOCKADDR_IN6(Structure):
    """
    IPv6 address struct.
    """

    _fields_ = [
        ("sin6_family", c_short),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", ULONG),
        ("sin6_addr", c_ubyte * 16),
        ("sin6_scope_id", ULONG)
    ]


class SOCKET_ADDRESS(Structure):
    """
    Unknown address struct, can be ``SOCKADDR_IN`` or ``SOCKADDR_IN6``.
    """

    _fields_ = [
        ('lpSockaddr', LPSOCKADDR),
        ('iSockaddrLength', INT)
    ]


class IP_ADAPTER_GATEWAY_ADDRESS_LH(Structure):
    """
    Struct for gateway address info linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Reserved", DWORD)]

        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_GATEWAY_ADDRESS_LH._fields_ = [
    ("__u1", IP_ADAPTER_GATEWAY_ADDRESS_LH._u1),
    ("Next", POINTER(IP_ADAPTER_GATEWAY_ADDRESS_LH)),
    ("Address", SOCKET_ADDRESS)
]


class IP_ADAPTER_WINS_SERVER_ADDRESS_LH(Structure):
    """
    Struct for win server address info linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Reserved", DWORD)]

        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_WINS_SERVER_ADDRESS_LH._fields_ = [
    ("__u1", IP_ADAPTER_WINS_SERVER_ADDRESS_LH._u1),
    ("Next", POINTER(IP_ADAPTER_WINS_SERVER_ADDRESS_LH)),
    ("Address", SOCKET_ADDRESS)
]


class IP_ADAPTER_PREFIX_XP(Structure):
    """
    Struct for adapter address info linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Flags", DWORD)]
        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_PREFIX_XP._fields_ = [
    ("__u1", IP_ADAPTER_PREFIX_XP._u1),
    ("Next", POINTER(IP_ADAPTER_PREFIX_XP)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixLength", ULONG)
]


class IP_ADAPTER_DNS_SERVER_ADDRESS_XP(Structure):
    """
    Struct for dns address info linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Reserved", DWORD)]

        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_DNS_SERVER_ADDRESS_XP._fields_ = [
    ("__u1", IP_ADAPTER_DNS_SERVER_ADDRESS_XP._u1),
    ("Next", POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS_XP)),
    ("Address", SOCKET_ADDRESS)
]


class IP_ADAPTER_MULTICAST_ADDRESS_XP(Structure):
    """
    Struct for adapter multicast address info (deprecated Windows XP format) linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Flags", DWORD)]

        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_MULTICAST_ADDRESS_XP._fields_ = [
    ("__u1", IP_ADAPTER_MULTICAST_ADDRESS_XP._u1),
    ("Next", POINTER(IP_ADAPTER_MULTICAST_ADDRESS_XP)),
    ("Address", SOCKET_ADDRESS)
]


class IP_ADAPTER_ANYCAST_ADDRESS_XP(Structure):
    """
    Struct for adapter anycast address info (deprecated Windows XP format) linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Flags", DWORD)]

        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_ANYCAST_ADDRESS_XP._fields_ = [
    ("__u1", IP_ADAPTER_ANYCAST_ADDRESS_XP._u1),
    ("Next", POINTER(IP_ADAPTER_ANYCAST_ADDRESS_XP)),
    ("Address", SOCKET_ADDRESS)
]


class IP_ADAPTER_UNICAST_ADDRESS_LH(Structure):
    """
    Struct for adapter unicast address info linked lists.
    """

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("Flags", DWORD)]
        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_UNICAST_ADDRESS_LH._fields_ = [
    ("__u1", IP_ADAPTER_UNICAST_ADDRESS_LH._u1),
    ("Next", POINTER(IP_ADAPTER_UNICAST_ADDRESS_LH)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", IP_PREFIX_ORIGIN),
    ("SuffixOrigin", IP_SUFFIX_ORIGIN),
    ("DadState", IP_DAD_STATE),
    ("ValidLifetime", ULONG),
    ("PreferredLifetime", ULONG),
    ("LeaseLifetime", ULONG),
    ("OnLinkPrefixLength", c_ubyte),
]


class IP_ADAPTER_DNS_SUFFIX(Structure):
    """
    Struct stub for DNS suffixes.
    """


IP_ADAPTER_DNS_SUFFIX._fields_ = [
    ('Next', POINTER(IP_ADAPTER_DNS_SUFFIX)),
    ('__c', WCHAR * MAX_DNS_SUFFIX_STRING_LENGTH)
]


class IF_LUID(Structure):
    """
    Struct for LUID info.
    """

    _fields_ = [
        ('LowPart', DWORD),
        ('HighPart', LONG)
    ]


class IP_ADAPTER_ADDRESSES_LH(Structure):
    """
    Struct for ``GetAdaptersAddresses`` return values.
    """

    __slots__ = ["__u1", "Next", "AdapterName", "FirstUnicastAddress", "FirstAnycastAddress", "FirstMulticastAddress",
                 "FirstDnsServerAddress", "DnsSuffix", "Description", "FriendlyName", "PhysicalAddress",
                 "PhysicalAddressLength", "Flags", "Mtu", "IfType", "OperStatus", "Ipv6IfIndex", "ZoneIndices",
                 "FirstPrefix", "TransmitLinkSpeed", "ReceiveLinkSpeed", "FirstWinsServerAddress",
                 "FirstGatewayAddress", "Ipv4Metric", "Ipv6Metric", "Luid", "Dhcpv4Server", "CompartmentId",
                 "NetworkGuid", "ConnectionType", "TunnelType", "Dhcpv6Server", "Dhcpv6ClientDuid",
                 "Dhcpv6ClientDuidLength", "Dhcpv6Iaid", "FirstDnsSuffix"]

    class _u1(Union):
        class _s1(Structure):
            _fields_ = [("Length", ULONG),
                        ("IfIndex", IF_INDEX)]
        _fields_ = [("Alignment", c_ulonglong),
                    ("__s1", _s1)]


IP_ADAPTER_ADDRESSES_LH._fields_ = [
    ('__u1', IP_ADAPTER_ADDRESSES_LH._u1),
    ('Next', POINTER(IP_ADAPTER_ADDRESSES_LH)),
    ("AdapterName", PCHAR),
    ("FirstUnicastAddress", POINTER(IP_ADAPTER_UNICAST_ADDRESS_LH)),
    ("FirstAnycastAddress", POINTER(IP_ADAPTER_ANYCAST_ADDRESS_XP)),
    ("FirstMulticastAddress", POINTER(IP_ADAPTER_MULTICAST_ADDRESS_XP)),
    ("FirstDnsServerAddress", POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS_XP)),
    ("DnsSuffix", PWCHAR),
    ("Description", PWCHAR),
    ("FriendlyName", PWCHAR),
    ("PhysicalAddress", BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", ULONG),
    ("Flags", ULONG),
    ("Mtu", ULONG),
    ("IfType", IFTYPE),
    ("OperStatus", IF_OPER_STATUS),
    ("Ipv6IfIndex", IF_INDEX),
    ("ZoneIndices", ULONG * 16),
    ("FirstPrefix", POINTER(IP_ADAPTER_PREFIX_XP)),
    ("TransmitLinkSpeed", c_uint64),
    ("ReceiveLinkSpeed", c_uint64),
    ("FirstWinsServerAddress", POINTER(IP_ADAPTER_WINS_SERVER_ADDRESS_LH)),
    ("FirstGatewayAddress", POINTER(IP_ADAPTER_GATEWAY_ADDRESS_LH)),
    ("Ipv4Metric", ULONG),
    ("Ipv6Metric", ULONG),
    ("Luid", IF_LUID),
    ("Dhcpv4Server", SOCKET_ADDRESS),
    ("CompartmentId", NET_IF_COMPARTMENT_ID),
    ("NetworkGuid", NET_IF_NETWORK_GUID),
    ("ConnectionType", NET_IF_CONNECTION_TYPE),
    ("TunnelType", TUNNEL_TYPE),
    ("Dhcpv6Server", SOCKET_ADDRESS),
    ("Dhcpv6ClientDuid", BYTE * MAX_DHCPV6_DUID_LENGTH),
    ("Dhcpv6ClientDuidLength", ULONG),
    ("Dhcpv6Iaid", ULONG),
    ("FirstDnsSuffix", POINTER(IP_ADAPTER_DNS_SUFFIX))
]


class GetAdaptersAddresses(AddressProvider):
    """
    Attempt to find local addresses using the ``GetAdaptersAddresses`` system call.
    """

    def get_addresses(self) -> set:
        """
        Call ``GetAdaptersAddresses()`` to retrieve addresses.
        """
        ulBufferLength = ULONG(30000)
        pulBufferLength = pointer(ulBufferLength)
        proc_heap = cast(GetProcessHeap(), HANDLE)
        pAdapterAddresses = cast(HeapAlloc(proc_heap, DWORD(0), c_size_t(30000)),
                                 POINTER(IP_ADAPTER_ADDRESSES_LH))

        ret = ERROR_BUFFER_OVERFLOW
        tries = 0
        while ret == ERROR_BUFFER_OVERFLOW and tries < 2:
            ret = _GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, 0, pAdapterAddresses, pulBufferLength)
            if ret == ERROR_BUFFER_OVERFLOW:
                HeapFree(proc_heap, DWORD(0), pAdapterAddresses)
                pAdapterAddresses = cast(HeapAlloc(proc_heap, DWORD(0), c_size_t(ulBufferLength.value)),
                                         POINTER(IP_ADAPTER_ADDRESSES_LH))
            tries += 1

        out_addresses: list[str] = []

        if ret != 0:
            # Memory has already been freed in case of overflow.
            if ret != ERROR_BUFFER_OVERFLOW:
                HeapFree(proc_heap, DWORD(0), pAdapterAddresses)
            return set(out_addresses)

        next = pAdapterAddresses  # noqa: A001
        while next:
            adapterAddresses: IP_ADAPTER_ADDRESSES_LH = next.contents

            next_unicast = adapterAddresses.FirstUnicastAddress
            while next_unicast:
                unicast_address = next_unicast.contents
                if unicast_address.OnLinkPrefixLength != 0:  # Check for netmask "0.0.0.0"
                    address_len = unicast_address.Address.iSockaddrLength
                    if address_len == 16:
                        socket_desc: SOCKADDR_IN = cast(unicast_address.Address.lpSockaddr, POINTER(SOCKADDR_IN)).contents
                        out_addresses.append(socket.inet_ntop(socket.AF_INET, string_at(socket_desc.sin_addr, 4)))
                    elif address_len == 28:
                        socket_desc6: SOCKADDR_IN6 = cast(unicast_address.Address.lpSockaddr, POINTER(SOCKADDR_IN6)).contents
                        out_addresses.append(socket.inet_ntop(socket.AF_INET6, string_at(socket_desc6.sin6_addr, 16)))
                next_unicast = unicast_address.Next

            next = adapterAddresses.Next  # noqa: A001

        # Free memory
        HeapFree(proc_heap, DWORD(0), pAdapterAddresses)

        return set(out_addresses)
