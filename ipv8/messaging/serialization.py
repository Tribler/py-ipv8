from __future__ import annotations

import abc
import socket
import typing
from binascii import hexlify
from struct import Struct, pack, unpack_from

from .interfaces.udp.endpoint import DomainAddress, UDPv4Address, UDPv6Address

ADDRESS_TYPE_IPV4 = 0x01
ADDRESS_TYPE_DOMAIN_NAME = 0x02
ADDRESS_TYPE_IPV6 = 0x03


FormatListType = typing.Union[str, "Serializable", typing.List["FormatListType"]]  # type:ignore


class PackError(RuntimeError):
    pass


class NestedPayload(object):
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

    def __init__(self, serializer):
        """
        Initialize with a known serializer, so we do not keep creating Serializer instances.
        As an added bonus, we also get all of the custom types defined in the given instance.

        :param serializer: the Serializer to inherit
        :type serializer: Serializer
        """
        super(NestedPayload, self).__init__()
        self.serializer = serializer

    def pack(self, serializable):
        """
        Pack some serializable.

        :param serializable: the Serializable instance which we should serialize.
        :type serializable: Serializable
        :return: the serialized data
        :rtype: bytes
        """
        data = self.serializer.pack_serializable(serializable)
        data = pack('>H', len(data)) + data
        return data

    def unpack(self, data, offset, unpack_list, serializable_class):
        """
        Unpack a Serializable using a class definition for some given data and offset.
        This is a special unpack_from which also takes a payload class.

        :param data: the data to unpack from
        :type data: str
        :param offset: the offset in the list of data to unpack from
        :type offset: int
        :param unpack_list: the list to which to append the Serializable
        :type unpack_list: list
        :param serializable_class: the Serializable class to unpack to
        :type serializable_class: type(Serializable)
        :return: the new offset
        :rtype: int
        """
        unpacked, offset = self.serializer.unpack_serializable(serializable_class, data, offset=offset + 2)
        unpack_list.append(unpacked)
        return offset


class Bits(object):

    def pack(self, *data):
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

    def unpack(self, data, offset, unpack_list):
        """
        Unpack multiple bits from a single byte. The resulting bits are appended to unpack_list

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


class Raw(object):
    """
    Paste/unpack the remaining input without (un)packing.
    """

    def pack(self, packable):
        return packable

    def unpack(self, data, offset, unpack_list):
        unpack_list.append(data[offset:])
        return len(data)


class VarLen:
    """
    Pack/unpack from an encoded length + data string.
    """

    def __init__(self, length_format, base=1):
        self.length_format = length_format
        self.length_size = Struct(length_format).size
        self.base = base

    def pack(self, data):
        return pack(self.length_format, len(data) // self.base) + data

    def unpack(self, data, offset, unpack_list):
        str_length = unpack_from(self.length_format, data, offset)[0] * self.base
        unpack_list.append(data[offset + self.length_size: offset + self.length_size + str_length])
        return offset + self.length_size + str_length


class VarLenUtf8(VarLen):
    """
    Pack/unpack from an unencoded utf8 length + data string.
    """
    def pack(self, data):
        return super().pack(data.encode())

    def unpack(self, data, offset, unpack_list):
        encoded_data = []
        out = super().unpack(data, offset, encoded_data)
        unpack_list.append(encoded_data[0].decode())
        return out


class IPv4:
    """
    Pack/unpack an IPv4 address
    """

    def pack(self, data):
        return pack('>4sH', socket.inet_aton(data[0]), data[1])

    def unpack(self, data, offset, unpack_list):
        host_bytes, port = unpack_from('>4sH', data, offset)
        unpack_list.append(UDPv4Address(socket.inet_ntoa(host_bytes), port))
        return offset + 6


class Address:

    def __init__(self, ip_only=False):
        self.ip_only = ip_only

    def pack(self, address):
        if isinstance(address, UDPv6Address):
            return pack('>B16sH', ADDRESS_TYPE_IPV6, socket.inet_pton(socket.AF_INET6, address.ip), address.port)
        if not self.ip_only and isinstance(address, DomainAddress):
            host_bytes = address.host.encode()
            return pack(f'>BH{len(host_bytes)}sH', ADDRESS_TYPE_DOMAIN_NAME, len(host_bytes), host_bytes, address.port)
        if isinstance(address, tuple):
            return pack('>B4sH', ADDRESS_TYPE_IPV4, socket.inet_pton(socket.AF_INET, address[0]), address[1])
        raise PackError(f'Unexpected address type {address}')

    def unpack(self, data, offset, unpack_list):
        address_type, = unpack_from('>B', data, offset)
        if address_type == ADDRESS_TYPE_IPV4:
            ip_bytes, port = unpack_from('>4sH', data, offset + 1)
            unpack_list.append(UDPv4Address(socket.inet_ntop(socket.AF_INET, ip_bytes), port))
            return offset + 7
        elif address_type == ADDRESS_TYPE_IPV6:
            ip_bytes, port = unpack_from('>16sH', data, offset + 1)
            unpack_list.append(UDPv6Address(socket.inet_ntop(socket.AF_INET6, ip_bytes), port))
            return offset + 19
        elif not self.ip_only and address_type == ADDRESS_TYPE_DOMAIN_NAME:
            length, = unpack_from('>H', data, offset + 1)
            host = data[offset + 3: offset + 3 + length].decode()
            unpack_list.append(DomainAddress(host, unpack_from('>H', data, offset + 3 + length)[0]))
            return offset + 5 + length
        else:
            raise PackError(f'Cannot unpack address type {address_type}')


class ListOf:

    def __init__(self, packer, length_format='>B'):
        self.packer = packer
        self.length_format = length_format
        self.length_size = Struct(length_format).size

    def pack(self, data):
        return pack(self.length_format, len(data)) + b''.join([self.packer.pack(item) for item in data])

    def unpack(self, data, offset, unpack_list, *args):
        length, = unpack_from(self.length_format, data, offset)
        offset += self.length_size

        result = []
        unpack_list.append(result)
        for _ in range(length):
            offset = self.packer.unpack(data, offset, result, *args)
        return offset


class DefaultStruct:

    def __init__(self, format_str):
        self.format_str = format_str
        self.size = Struct(format_str).size

    def pack(self, *data):
        return pack(self.format_str, *data)

    def unpack(self, data, offset, unpack_list):
        result = unpack_from(self.format_str, data, offset)
        unpack_list.append(result if len(result) > 1 else result[0])
        return offset + self.size


class Serializer(object):

    def __init__(self):
        super(Serializer, self).__init__()
        self._packers = {
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
            'varlenHx20': VarLen('>H', 20),
            'varlenH-list': ListOf(VarLen('>H')),
            'varlenI': VarLen('>I'),
            'doublevarlenH': VarLen('>H'),
            'payload': NestedPayload(self),
            'payload-list': ListOf(NestedPayload(self))
        }

    def get_available_formats(self):
        """
        Get all available packing formats.
        """
        return list(self._packers.keys())

    def get_packer_for(self, name):
        """
        Get a packer by name.
        """
        return self._packers[name]

    def add_packer(self, name, packer):
        """
        Register a new packer with a certain name.

        :param name: the name to register
        :param packer: the packer to use for it
        """
        self._packers[name] = packer

    def pack(self, fmt, item):
        """
        Pack data without using a Serializable. Using a Serializable is the preferred method.
        :param fmt: the name of the packer to use while packing
        :param item: object to pack
        :return: the packed data
        :rtype: bytes
        """
        return self._packers[fmt].pack(item)

    def unpack(self, fmt, data, offset=0):
        """
        Unpack data without using a Serializable. Using a Serializable is the preferred method.
        :param fmt: the name of the packer to use while unpacking
        :param data: bytes to unpack
        :return: the unpacked object
        :rtype: object
        """
        unpack_list = []
        if isinstance(fmt, str):
            offset = self._packers[fmt].unpack(data, offset, unpack_list)
        elif isinstance(fmt, list):
            offset = self._packers['payload-list'].unpack(data, offset, unpack_list, fmt[0])
        else:
            offset = self._packers['payload'].unpack(data, offset, unpack_list, fmt)
        return unpack_list[0], offset

    def pack_serializable(self, serializable):
        """
        Serialize a single Serializable instance.

        :param serializable: the Serializable to pack
        :type serializable: Serializable
        :return: the serialized object
        :rtype: bytes
        """
        packed = b''
        for packable in serializable.to_pack_list():
            try:
                packed += self._packers[packable[0]].pack(*packable[1:])
            except Exception as e:
                raise PackError("Could not pack item: %s\n%s: %s" % (packable, type(e).__name__, str(e))) from e
        return packed

    def pack_serializable_list(self, serializables):
        """
        Serialize a list of Serializable instances.

        :param serializables: the Serializables to pack
        :type serializables: [Serializable]
        :return: the serialized list
        :rtype: bytes
        """
        return b''.join(self.pack_serializable(serializable) for serializable in serializables)

    def unpack_serializable(self, serializable, data, offset=0):
        """
        Use the formats specified in a serializable object and unpack to it.

        :param serializable: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :param offset: the optional offset to unpack data from
        """
        unpack_list = []
        for fmt in serializable.format_list:
            try:
                offset = self._packers[fmt].unpack(data, offset, unpack_list)
            except KeyError:
                if not issubclass(fmt, Serializable):
                    raise
                offset = self._packers['payload'].unpack(data, offset, unpack_list, fmt)
            except TypeError:
                if not isinstance(fmt, list):
                    raise
                offset = self._packers['payload-list'].unpack(data, offset, unpack_list, fmt[0])
            except Exception as e:
                raise PackError("Could not unpack item: %s\n%s: %s" % (fmt, type(e).__name__, str(e))) from e
        return serializable.from_unpack_list(*unpack_list), offset

    def unpack_serializable_list(self, serializables, data, offset=0, consume_all=True):
        """
        Use the formats specified in a list of serializable objects and unpack to them.

        :param serializables: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :param offset: position at which to start reading from data
        :param consume_all: if having a non-empty remainder should throw an error
        :except PackError: if the data could not be fit into the specified serializables
        :except PackError: if consume_all is True and not all of the data was consumed when parsing the serializables
        :return: the list of Serializable instances
        :rtype: [Serializable]
        """
        unpacked = []
        for serializable in serializables:
            payload, offset = self.unpack_serializable(serializable, data, offset)
            unpacked.append(payload)
        remainder = data[offset:]
        if not consume_all:
            unpacked.append(remainder)
        elif remainder:
            raise PackError("Incoming packet %s (%s) has extra data: (%s)" %
                            (str([serializable_class.__name__ for serializable_class in serializables]),
                             hexlify(data),
                             hexlify(remainder)))
        return unpacked


class Serializable(metaclass=abc.ABCMeta):
    """
    Interface for serializable objects.
    """

    format_list: typing.List[FormatListType] = []

    @abc.abstractmethod
    def to_pack_list(self) -> typing.List[tuple]:
        """
        Serialize this object to a Serializer pack list.

        E.g.:
        ``[(format1, data1), (format2, data2), (format3, data3), ..]``
        """
        pass

    @abc.abstractmethod
    def from_unpack_list(cls, *args) -> Serializable:  # pylint: disable=E0213
        """
        Create a new Serializable object from a list of unpacked variables.
        """
        pass


class Payload(Serializable, abc.ABC):

    def __str__(self):
        out = self.__class__.__name__
        for attribute in dir(self):
            if not (attribute.startswith('_') or callable(getattr(self, attribute))) \
                    and attribute not in ['format_list', 'names']:
                out += '\n| %s: %s' % (attribute, repr(getattr(self, attribute)))
        return out


# Serializers should be stateless.
# Therefore we can expose a global singleton for efficiency.
# If you do need a Serializer with a state, be sure to use your own instance.
default_serializer = Serializer()
