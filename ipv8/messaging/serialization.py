from __future__ import annotations

import abc
import socket
import typing
from array import array
from binascii import hexlify
from contextlib import suppress
from struct import Struct, pack, unpack_from
from typing import TYPE_CHECKING, cast

from .interfaces.udp.endpoint import DomainAddress, UDPv4Address, UDPv6Address

if TYPE_CHECKING:
    from collections.abc import Sequence

ADDRESS_TYPE_IPV4 = 0x01
ADDRESS_TYPE_DOMAIN_NAME = 0x02
ADDRESS_TYPE_IPV6 = 0x03


FormatListType = typing.Union[str, typing.Type["Serializable"], typing.List["FormatListType"]]


class PackError(RuntimeError):
    """
    A given message format could not be packed to bytes or unpacked from bytes.
    """


T = typing.TypeVar('T')
A = typing.TypeVar('A')


class Packer(typing.Generic[T, A], metaclass=abc.ABCMeta):
    """
    A class that can pack and unpack objects to and from bytes.
    """

    @abc.abstractmethod
    def pack(self, data: T) -> bytes:
        """
        Pack the given data.
        """

    @abc.abstractmethod
    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: A) -> int:
        """
        Unpack an object from the given data buffer and return the new offset in the data buffer.
        """


class NestedPayload(Packer):
    """
    This is a special type of format. Allowing for nested packing.

    You can specify which serializable to use by specifying its class in the format_list of the parent Serializable.

    For example, nesting a Serializable of class B in class A::

        class A(Serializable):
            format_list = [B]

        def __init__(self, b_instance):
            pass

        def to_pack_list(self):
            return [("payload", B())]

        @classmethod
        def from_unpack_list(cls, *args):
            return A(*args)

    """

    def __init__(self, serializer: Serializer) -> None:
        """
        Initialize with a known serializer, so we do not keep creating Serializer instances.
        As an added bonus, we also get all of the custom types defined in the given instance.

        :param serializer: the Serializer to inherit
        """
        super().__init__()
        self.serializer = serializer

    def pack(self, serializable: Serializable) -> bytes:
        """
        Pack some serializable.

        :param serializable: the Serializable instance which we should serialize.
        :return: the serialized data
        """
        data = self.serializer.pack_serializable(serializable)
        return pack('>H', len(data)) + data

    def unpack(self,
               data: bytes,
               offset: int,
               unpack_list: list,
               *args: type[Serializable]) -> int:
        """
        Unpack a Serializable using a class definition for some given data and offset.
        This is a special unpack_from which also takes a payload class.

        :param data: the data to unpack from
        :param offset: the offset in the list of data to unpack from
        :param unpack_list: the list to which to append the Serializable
        :param args: a list of one Serializable class to unpack to
        :return: the new offset
        """
        size, = unpack_from('>H', data, offset)
        offset += 2
        serializable_class = args[0]
        unpacked, _ = self.serializer.unpack_serializable(serializable_class, data[offset:offset + size])
        unpack_list.append(unpacked)
        return offset + size


class Bits(Packer):
    """
    A packer for bits into a byte.
    """

    def pack(self, *data: int) -> bytes:
        """
        Pack multiple bits into a single byte.

        :param *data: bit values
        :type *data: list of 8 True or False values (or anything that maps to it in an if-statement)
        """
        byte = 0
        byte |= 0x80 if data[0] else 0x00
        byte |= 0x40 if data[1] else 0x00
        byte |= 0x20 if data[2] else 0x00
        byte |= 0x10 if data[3] else 0x00
        byte |= 0x08 if data[4] else 0x00
        byte |= 0x04 if data[5] else 0x00
        byte |= 0x02 if data[6] else 0x00
        byte |= 0x01 if data[7] else 0x00
        return pack('>B', byte)

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack multiple bits from a single byte. The resulting bits are appended to unpack_list.

        :returns: the new offset
        """
        byte, = unpack_from('>B', data, offset)
        bit_7 = 1 if 0x80 & byte else 0
        bit_6 = 1 if 0x40 & byte else 0
        bit_5 = 1 if 0x20 & byte else 0
        bit_4 = 1 if 0x10 & byte else 0
        bit_3 = 1 if 0x08 & byte else 0
        bit_2 = 1 if 0x04 & byte else 0
        bit_1 = 1 if 0x02 & byte else 0
        bit_0 = 1 if 0x01 & byte else 0
        unpack_list += [bit_7, bit_6, bit_5, bit_4, bit_3, bit_2, bit_1, bit_0]
        return offset + 1


class Raw(Packer):
    """
    Paste/unpack the remaining input without (un)packing.
    """

    def pack(self, packable: bytes) -> bytes:
        """
        Forward the packable without doing anything to it.
        """
        return packable

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Match everything remaining in the data as a bytes string.
        """
        unpack_list.append(data[offset:])
        return len(data)


class VarLen(Packer):
    """
    Pack/unpack from an encoded length + data string.
    """

    def __init__(self, length_format: str, base: int = 1) -> None:
        """
        Create a new VarLen instance.
        """
        self.length_format = length_format
        self.length_size = Struct(length_format).size
        self.base = base

    def pack(self, data: bytes) -> bytes:
        """
        Prefix the length of the given data to it and return the result.
        """
        return pack(self.length_format, len(data) // self.base) + data

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack from VarLen packed data.
        """
        str_length = unpack_from(self.length_format, data, offset)[0] * self.base
        unpack_list.append(data[offset + self.length_size: offset + self.length_size + str_length])
        return offset + self.length_size + str_length


class VarLenUtf8(VarLen):
    """
    Pack/unpack from an unencoded utf8 length + data string.
    """

    def pack(self, data: str) -> bytes:  # type: ignore[override]
        """
        Pack a UTF-8 string.
        """
        return super().pack(data.encode())

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack an encoded UTF-8 string.
        """
        encoded_data: list[bytes] = []
        out = super().unpack(data, offset, encoded_data)
        unpack_list.append(encoded_data[0].decode())
        return out


class IPv4(Packer):
    """
    Pack/unpack an IPv4 address.
    """

    def pack(self, data: tuple[str, int]) -> bytes:
        """
        Pack an IPv4 address to bytes.
        """
        return pack('>4sH', socket.inet_aton(data[0]), data[1])

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack a packed IPv4 address.
        """
        host_bytes, port = unpack_from('>4sH', data, offset)
        unpack_list.append(UDPv4Address(socket.inet_ntoa(host_bytes), port))
        return offset + 6


class Address(Packer):
    """
    Any address format: IPv4, IPv6 or host format.
    """

    def __init__(self, ip_only: bool = False) -> None:
        """
        Create a new Address packer.
        """
        self.ip_only = ip_only

    def pack(self, address: tuple[str, int]) -> bytes:
        """
        Pack a generic address as bytes.
        """
        with suppress(OSError):
            return pack('>B4sH', ADDRESS_TYPE_IPV4, socket.inet_pton(socket.AF_INET, address[0]), address[1])
        with suppress(OSError):
            return pack('>B16sH', ADDRESS_TYPE_IPV6,
                        socket.inet_pton(socket.AF_INET6, address[0]), address[1])

        if not self.ip_only:
            host_bytes = address[0].encode()
            return pack(f'>BH{len(host_bytes)}sH', ADDRESS_TYPE_DOMAIN_NAME,
                        len(host_bytes), host_bytes, address[1])

        msg = f"Unexpected address type {address}"
        raise PackError(msg)

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack a generic address from bytes.
        """
        address_type, = unpack_from('>B', data, offset)
        if address_type == ADDRESS_TYPE_IPV4:
            ip_bytes, port = unpack_from('>4sH', data, offset + 1)
            unpack_list.append(UDPv4Address(socket.inet_ntop(socket.AF_INET, ip_bytes), port))
            return offset + 7
        if address_type == ADDRESS_TYPE_IPV6:
            ip_bytes, port = unpack_from('>16sH', data, offset + 1)
            unpack_list.append(UDPv6Address(socket.inet_ntop(socket.AF_INET6, ip_bytes), port))
            return offset + 19
        if not self.ip_only and address_type == ADDRESS_TYPE_DOMAIN_NAME:
            length, = unpack_from('>H', data, offset + 1)
            host = data[offset + 3: offset + 3 + length].decode()
            unpack_list.append(DomainAddress(host, unpack_from('>H', data, offset + 3 + length)[0]))
            return offset + 5 + length
        msg = f"Cannot unpack address type {address_type}"
        raise PackError(msg)


class ListOf(Packer):
    """
    A list of a given packer.
    """

    def __init__(self, packer: Packer, length_format: str = ">B") -> None:
        """
        Create a new list of a given packer format.

        By default, we encode the number of items in a byte (max 255 items).
        """
        self.packer = packer
        self.length_format = length_format
        self.length_size = Struct(length_format).size

    def pack(self, data: list) -> bytes:
        """
        Feed a list of objects to the registered packer.
        """
        return pack(self.length_format, len(data)) + b''.join([self.packer.pack(item) for item in data])

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack a list of objects from the data.
        """
        length, = unpack_from(self.length_format, data, offset)
        offset += self.length_size

        result: list = []
        unpack_list.append(result)
        for _ in range(length):
            offset = self.packer.unpack(data, offset, result, *args)
        return offset


class DefaultArray(Packer):
    """
    A format known to the ``array`` module (like 'I', 'B', etc.).

    Also adds support for '?'.
    """

    def __init__(self, format_str: str, length_format: str) -> None:
        """
        Create a new packer for the given ``array`` format string.
        """
        self.format_str = format_str
        self.real_format_str = "B" if format_str == "?" else format_str
        self.length_format = length_format
        self.length_size = Struct(length_format).size
        self.base = array(self.real_format_str).itemsize

    def pack(self, data: list) -> bytes:
        """
        Pack a list of items by forwarding them to ``array``.
        """
        return pack(self.length_format, len(data)) + array(self.real_format_str, data).tobytes()

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack a list of items from the known ``array`` format.
        """
        str_length = unpack_from(self.length_format, data, offset)[0] * self.base
        a = array(self.real_format_str)
        a.frombytes(data[offset + self.length_size: offset + self.length_size + str_length])
        unpack_list.append([bool(b) for b in a] if self.format_str == "?" else list(a))
        return offset + self.length_size + str_length


class DefaultStruct(Packer):
    """
    A format known to the ``struct`` module (like 'I', '20s', etc.).
    """

    def __init__(self, format_str: str) -> None:
        """
        Create a new packer for the given ``struct`` format string.
        """
        self.format_str = format_str
        self.size = Struct(format_str).size

    def pack(self, *data: list) -> bytes:
        """
        Pack a list of items by forwarding them to ``struct``.
        """
        return pack(self.format_str, *data)

    def unpack(self, data: bytes, offset: int, unpack_list: list, *args: object) -> int:
        """
        Unpack a list of items from the known ``struct`` format.
        """
        result = unpack_from(self.format_str, data, offset)
        unpack_list.append(result if len(result) > 1 else result[0])
        return offset + self.size


class Serializer:
    """
    The class performing serialization of Serializable objects.
    """

    def __init__(self) -> None:
        """
        Create a new Serializer and register the default formats.
        """
        super().__init__()
        self._packers: dict[str, Packer] = {
            '?': DefaultStruct(">?"),
            'B': DefaultStruct(">B"),
            'BBH': DefaultStruct(">BBH"),
            'BH': DefaultStruct(">BH"),
            'c': DefaultStruct(">c"),
            'f': DefaultStruct(">f"),
            'd': DefaultStruct(">d"),
            'H': DefaultStruct(">H"),
            'HH': DefaultStruct(">HH"),
            'I': DefaultStruct(">I"),
            'l': DefaultStruct(">l"),
            'LL': DefaultStruct(">LL"),
            'q': DefaultStruct(">q"),
            'Q': DefaultStruct(">Q"),
            'QH': DefaultStruct(">QH"),
            'QL': DefaultStruct(">QL"),
            'QQHHBH': DefaultStruct(">QQHHBH"),
            'ccB': DefaultStruct(">ccB"),
            '4SH': DefaultStruct(">4sH"),
            '20s': DefaultStruct(">20s"),
            '32s': DefaultStruct(">32s"),
            '64s': DefaultStruct(">64s"),
            '74s': DefaultStruct(">74s"),
            'c20s': DefaultStruct(">c20s"),
            'bits': Bits(),
            'ipv4': IPv4(),
            'ip_address': Address(ip_only=True),
            'address': Address(),
            'raw': Raw(),
            'varlenBx2': VarLen('>B', 2),
            'varlenH': VarLen('>H'),
            'varlenHutf8': VarLenUtf8('>H'),
            'varlenIutf8': VarLenUtf8('>I'),
            'varlenHx20': VarLen('>H', 20),
            'varlenH-list': ListOf(VarLen('>H')),
            'varlenI': VarLen('>I'),
            'doublevarlenH': VarLen('>H'),
            'payload': NestedPayload(self),
            'payload-list': ListOf(NestedPayload(self)),
            'arrayH-?': DefaultArray("?", "H"),
            'arrayH-q': DefaultArray("q", "H"),
            'arrayH-d': DefaultArray("d", "H"),
        }

    def get_available_formats(self) -> list[str]:
        """
        Get all available packing formats.
        """
        return list(self._packers.keys())

    def get_packer_for(self, name: str) -> Packer:
        """
        Get a packer by name.
        """
        return self._packers[name]

    def add_packer(self, name: str, packer: Packer) -> None:
        """
        Register a new packer with a certain name.

        :param name: the name to register
        :param packer: the packer to use for it
        """
        self._packers[name] = packer

    def pack(self, fmt: str, item: object) -> bytes:
        """
        Pack data without using a Serializable. Using a Serializable is the preferred method.

        :param fmt: the name of the packer to use while packing
        :param item: object to pack
        :return: the packed data
        """
        return self._packers[fmt].pack(item)

    def unpack(self, fmt: FormatListType, data: bytes, offset: int = 0) -> tuple[object, int]:
        """
        Unpack data without using a Serializable. Using a Serializable is the preferred method.

        :param fmt: the name of the packer to use while unpacking
        :param data: bytes to unpack
        :return: the unpacked object
        """
        unpack_list: list = []
        if isinstance(fmt, str):
            offset = self._packers[fmt].unpack(data, offset, unpack_list)
        elif isinstance(fmt, list):
            offset = self._packers['payload-list'].unpack(data, offset, unpack_list, fmt[0])
        else:
            offset = self._packers['payload'].unpack(data, offset, unpack_list, fmt)
        return unpack_list[0], offset

    def pack_serializable(self, serializable: Serializable) -> bytes:
        """
        Serialize a single Serializable instance.

        :param serializable: the Serializable to pack
        :type serializable: Serializable
        :return: the serialized object
        """
        packed = b''
        for packable in serializable.to_pack_list():
            try:
                packed += self._packers[packable[0]].pack(*packable[1:])
            except Exception as e:
                msg = f"Could not pack item: {packable}\n{type(e).__name__}: {e}"
                raise PackError(msg) from e
        return packed

    def pack_serializable_list(self, serializables: Sequence[Serializable]) -> bytes:
        """
        Serialize a list of Serializable instances.

        :param serializables: the Serializables to pack
        :type serializables: [Serializable]
        :return: the serialized list
        """
        return b''.join(self.pack_serializable(serializable) for serializable in serializables)

    def unpack_serializable(self,
                            serializable: type[S],
                            data: bytes,
                            offset: int = 0) -> tuple[S, int]:
        """
        Use the formats specified in a serializable object and unpack to it.

        :param serializable: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :param offset: the optional offset to unpack data from
        """
        unpack_list: list = []
        for fmt in serializable.format_list:
            try:
                offset = self._packers[fmt].unpack(data, offset, unpack_list)  # type: ignore[index]
            except KeyError:
                fmt = cast(typing.Type, fmt)  # If this is not a type, we'll crash
                if not issubclass(fmt, Serializable):
                    raise
                offset = self._packers['payload'].unpack(data, offset, unpack_list, fmt)
            except TypeError:
                if not isinstance(fmt, list):
                    raise
                offset = self._packers['payload-list'].unpack(data, offset, unpack_list, fmt[0])
            except Exception as e:
                msg = f"Could not unpack item: {fmt}\n{type(e).__name__}: {e}"
                raise PackError(msg) from e
        return serializable.from_unpack_list(*unpack_list), offset

    def unpack_serializable_list(self,
                                 serializables: Sequence[type[Serializable]],
                                 data: bytes,
                                 offset: int = 0,
                                 consume_all: bool = True) -> list[Serializable | bytes]:
        """
        Use the formats specified in a list of serializable objects and unpack to them.

        :param serializables: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :param offset: position at which to start reading from data
        :param consume_all: if having a non-empty remainder should throw an error
        :except PackError: if the data could not be fit into the specified serializables
        :except PackError: if consume_all is True and not all of the data was consumed when parsing the serializables
        :return: the list of Serializable instances
        """
        unpacked: list[Serializable | bytes] = []
        for serializable in serializables:
            payload, offset = self.unpack_serializable(serializable, data, offset)
            unpacked.append(payload)
        remainder = data[offset:]
        if not consume_all:
            unpacked.append(remainder)
        elif remainder:
            msg = (f"Incoming packet {[serializable_class.__name__ for serializable_class in serializables]} "
                   f"({hexlify(data)!r}) has extra data: ({hexlify(remainder)!r})")
            raise PackError(msg)
        return unpacked


SelfS = typing.TypeVar('SelfS', bound='Serializable')


class Serializable(metaclass=abc.ABCMeta):
    """
    Interface for serializable objects.
    """

    format_list: list[FormatListType] = []

    @abc.abstractmethod
    def to_pack_list(self) -> list[tuple]:
        """
        Serialize this object to a Serializer pack list.

        E.g.:
        ``[(format1, data1), (format2, data2), (format3, data3), ..]``
        """

    @classmethod
    @abc.abstractmethod
    def from_unpack_list(cls: type[SelfS], *args: typing.Any, **kwargs) -> SelfS:  # noqa: ANN401
        """
        Create a new Serializable object from a list of unpacked variables.
        """


S = typing.TypeVar('S', bound=Serializable)


class Payload(Serializable, abc.ABC):
    """
    A serializable that has extra printing functionality.
    """

    def __str__(self) -> str:
        """
        The string representation of this payload.
        """
        out = self.__class__.__name__
        for attribute in dir(self):
            if not (attribute.startswith('_') or callable(getattr(self, attribute))) \
                    and attribute not in ['format_list', 'names']:
                out += f"\n| {attribute}: {getattr(self, attribute)!r}"
        return out


# Serializers should be stateless.
# Therefore we can expose a global singleton for efficiency.
# If you do need a Serializer with a state, be sure to use your own instance.
default_serializer = Serializer()
