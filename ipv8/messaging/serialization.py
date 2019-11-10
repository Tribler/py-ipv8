import abc
import itertools
from binascii import hexlify
from struct import Struct, pack, unpack, unpack_from


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
        :return: the serialized data and its size
        :rtype: (str, int)
        """
        data, size = self.serializer.pack_multiple(serializable.to_pack_list())
        # We don't care about the inner size of the Serializable, we already have the outer size.
        data, size = self.serializer.pack('varlenH', data)[0], size + 2
        return data, size

    def unpack_from(self, serializable_class, data, offset):
        """
        Unpack a Serializable using a class definition for some given data and offset.
        This is a special unpack_from which also takes a payload class.

        :param serializable_class: the Serializable class to unpack to
        :type serializable_class: type(Serializable)
        :param data: the data to unpack from
        :type data: str
        :param offset: the offset in the list of data to unpack from
        :type offset: int
        :return: the output Serializable instance and the new offset delta
        :rtype: (Serializable, int)
        """
        raw, size = self.serializer.unpack('varlenH', data, offset)
        unpacked = self.serializer.ez_unpack_serializables([serializable_class], raw)
        # We only ever have 1 serializable, only return item 0.
        return unpacked[0], size


class Bits(object):

    def pack(self, bit_7=0, bit_6=0, bit_5=0, bit_4=0, bit_3=0, bit_2=0, bit_1=0, bit_0=0):
        """
        Pack multiple bits into a single byte.

        :param bit_*: bit at position *
        :type bit_*: True or False (or anything that maps to it in an if-statement)
        """
        byte = 0
        byte |= 0x80 if bit_7 else 0x00
        byte |= 0x40 if bit_6 else 0x00
        byte |= 0x20 if bit_5 else 0x00
        byte |= 0x10 if bit_4 else 0x00
        byte |= 0x08 if bit_3 else 0x00
        byte |= 0x04 if bit_2 else 0x00
        byte |= 0x02 if bit_1 else 0x00
        byte |= 0x01 if bit_0 else 0x00
        return pack('>B', byte), 1

    def unpack_from(self, data, offset):
        """
        Unpack multiple bits from a single byte.

        :returns: list of 8 values in [0, 1] MSB first
        """
        byte, = unpack('>B', data[offset:offset + 1])
        bit_7 = 1 if 0x80 & byte else 0
        bit_6 = 1 if 0x40 & byte else 0
        bit_5 = 1 if 0x20 & byte else 0
        bit_4 = 1 if 0x10 & byte else 0
        bit_3 = 1 if 0x08 & byte else 0
        bit_2 = 1 if 0x04 & byte else 0
        bit_1 = 1 if 0x02 & byte else 0
        bit_0 = 1 if 0x01 & byte else 0
        return [bit_7, bit_6, bit_5, bit_4, bit_3, bit_2, bit_1, bit_0], 1


class Raw(object):
    """
    Paste/unpack the remaining input without (un)packing.
    """

    def pack(self, *data):
        out = b''
        size = 0
        for piece in data:
            out += piece
            size += len(piece)
        return out, size

    def unpack_from(self, data, offset=0):
        out = data[offset:]
        return out, len(out)


class VarLen(object):
    """
    Paste/unpack from an encoded length + data string.
    """

    def __init__(self, format, base=1):
        super(VarLen, self).__init__()
        self.format = format
        self.format_size = Struct(self.format).size
        self.base = base

    def pack(self, *data):
        raw = b''.join(data)
        length = len(raw) // self.base
        size = self.format_size + len(raw)
        return pack('>%s%ds' % (self.format, len(raw)), length, raw), size

    def unpack_from(self, data, offset=0):
        length, = unpack_from('>%s' % self.format, data, offset)
        length *= self.base
        out, = unpack_from('>%ds' % length, data, offset + self.format_size)
        return out, self.format_size + length


class DefaultStruct(Struct):

    def __init__(self, format, single_value=False):
        super(DefaultStruct, self).__init__(format)
        self.single_value = single_value

    def pack(self, *data):
        return super(DefaultStruct, self).pack(*data), self.size

    def unpack_from(self, buffer, offset=0):
        out = super(DefaultStruct, self).unpack_from(buffer, offset)
        if self.single_value:
            return out[0], self.size
        else:
            return list(out), self.size


class Serializer(object):

    def __init__(self):
        super(Serializer, self).__init__()
        self._packers = {
            '?': DefaultStruct(">?", True),
            'B': DefaultStruct(">B", True),
            'BBH': DefaultStruct(">BBH"),
            'BH': DefaultStruct(">BH"),
            'c': DefaultStruct(">c", True),
            'f': DefaultStruct(">f", True),
            'd': DefaultStruct(">d", True),
            'H': DefaultStruct(">H", True),
            'HH': DefaultStruct(">HH"),
            'I': DefaultStruct(">I", True),
            'l': DefaultStruct(">l", True),
            'LL': DefaultStruct(">LL"),
            'Q': DefaultStruct(">Q", True),
            'QH': DefaultStruct(">QH"),
            'QL': DefaultStruct(">QL"),
            'QQHHBH': DefaultStruct(">QQHHBH"),
            'ccB': DefaultStruct(">ccB"),
            '4SH': DefaultStruct(">4sH"),
            '20s': DefaultStruct(">20s", True),
            '32s': DefaultStruct(">32s", True),
            '64s': DefaultStruct(">64s", True),
            '74s': DefaultStruct(">74s", True),
            'c20s': DefaultStruct(">c20s"),
            'bits': Bits(),
            'raw': Raw(),
            'varlenBx2': VarLen('B', 2),
            'varlenH': VarLen('H'),
            'varlenHx20': VarLen('H', 20),
            'varlenI': VarLen('I'),
            'doublevarlenH': VarLen('H'),
            'payload': NestedPayload(self)
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

    def add_packing_format(self, name, format):
        """
        Register a new struct packing format with a certain name.

        :param name: the name to register
        :param format: the format to use for it
        """
        self._packers.update({name: DefaultStruct(format)})

    def pack(self, format, *data):
        """
        Pack some data according to some format name.

        :param format: the format name to use
        :param data: the data to serialize
        :returns: (packed, size)
        """
        return self._packers[format].pack(*data)

    def pack_multiple(self, pack_list):
        """
        Serialize multiple data tuples.

        Each of the tuples in the pack_list are built as (format, arg1, arg2, .., argn)

        :param pack_list: the list of packable tuples
        :returns: (packed, size)
        """
        out = b""
        index = 0
        size = 0
        for packable in pack_list:
            try:
                packed, packed_size = self.pack(*packable)
                out += packed
                size += packed_size
            except Exception as e:
                raise PackError("Could not pack item %d: %s\n%s: %s" % (index, repr(packable),
                                                                        type(e).__name__, str(e))) from e
            index += 1
        return out, size

    def ez_pack_serializables(self, serializables):
        """
        Serialize a list of Serializable instances.

        :param serializables: the Serializables to pack
        :type serializables: [Serializable]
        :return: the serialized list
        :rtype: bytes or str
        """
        out, _ = self.pack_multiple(list(itertools.chain.from_iterable(serializable.to_pack_list()
                                                                       for serializable in serializables)))
        return out

    def unpack(self, format, data, offset=0):
        """
        Use a certain named format to unpack from some data.

        :param format: the format name to unpack with
        :param data: the data to unpack from
        :param offset: the optional offset to unpack data from
        """
        if format not in self._packers and issubclass(format, Serializable):
            return NestedPayload(self).unpack_from(format, data, offset)
        return self._packers[format].unpack_from(data, offset)

    def unpack_multiple(self, unpack_list, data, optional_list=[], offset=0):
        """
        Unpack multiple variables from a data string.

        Each of the tuples in the unpack_list are built as (format, arg1, arg2, .., argn)

        :param unpack_list: the list of formats
        :param data: the data to unpack from
        :param optional_list: the list of optional parameters for this formatting
        :param offset: the optional offset to unpack data from
        """
        current_offset = offset
        out = []
        index = 0
        required_length = len(unpack_list)
        data_length = len(data)
        for format in unpack_list + optional_list:
            if index >= required_length and current_offset >= data_length:
                # We can perform a clean break if we are in the optional set
                break
            try:
                unpacked, unpacked_size = self.unpack(format, data, current_offset)
                if format == 'bits':
                    out.extend(unpacked)
                else:
                    out.append(unpacked)
            except Exception as e:
                raise PackError("Could not pack item %d: %s\n%s: %s" % (index, format,
                                                                        type(e).__name__, str(e))) from e
            current_offset += unpacked_size
            index += 1
        return out, current_offset

    def unpack_to_serializables(self, serializables, data):
        """
        Use the formats specified in a serializable object and unpack to it.

        :param serializables: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :except PackError: if the data could not be fit into the specified serializables
        :return: the list of Serializable instances, with the list of remaining data as the last element
        :rtype: [Serializable] + [bytes or str]
        """
        offset = 0
        out = []
        for serializable in serializables:
            try:
                unpack_list, offset = self.unpack_multiple(serializable.format_list, data,
                                                           serializable.optional_format_list, offset)
            except Exception as e:
                raise PackError("Failed to unserialize %s\n%s: %s" % (serializable.__name__,
                                                                      type(e).__name__, str(e))) from e
            out.append(serializable.from_unpack_list(*unpack_list))
        out.append(data[offset:])
        return out

    def ez_unpack_serializables(self, serializables, data):
        """
        Use the formats specified in a serializable object and unpack to it.

        :param serializables: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        :except PackError: if the data could not be fit into the specified serializables
        :except PackError: if not all of the data was consumed when parsing the serializables
        :return: the list of Serializable instances
        :rtype: [Serializable]
        """
        unpacked = self.unpack_to_serializables(serializables, data)
        unknown_data = unpacked.pop()
        if unknown_data:
            raise PackError("Incoming packet %s (%s) has extra data: (%s)" %
                            (str([serializable_class.__name__ for serializable_class in serializables]),
                             hexlify(data),
                             hexlify(unknown_data)))
        return unpacked


class Serializable(metaclass=abc.ABCMeta):
    """
    Interface for serializable objects.
    """

    format_list = []
    optional_format_list = []

    @abc.abstractmethod
    def to_pack_list(self):
        """
        Serialize this object to a Serializer pack list.

        E.g.:
        ``[(format1, data1), (format2, data2), (format3, data3), ..]``
        """
        pass

    @abc.abstractmethod
    def from_unpack_list(cls, *args):
        """
        Create a new Serializable object from a list of unpacked variables.
        """
        pass


# Serializers should be stateless.
# Therefore we can expose a global singleton for efficiency.
# If you do need a Serializer with a state, be sure to use your own instance.
default_serializer = Serializer()
