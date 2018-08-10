import abc
from struct import pack, unpack, unpack_from, Struct
import sys


class PackError(RuntimeError):
    pass


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
        byte, = unpack('>B', data[offset])
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
        out = ''
        size = 0
        for piece in data:
            s_piece = str(piece)
            out += s_piece
            size += len(s_piece)
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
        raw = ''.join(data)
        length = len(raw)/self.base
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
            'doublevarlenH': VarLen('H')
        }

    def get_available_formats(self):
        """
        Get all available packing formats.
        """
        return self._packers.keys()

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
        out = ""
        index = 0
        size = 0
        for packable in pack_list:
            try:
                packed, packed_size = self.pack(*packable)
                out += packed
                size += packed_size
            except Exception as e:
                raise PackError("Could not pack item %d: %s\n%s: %s" % (index,
                                                                        repr(packable),
                                                                        type(e).__name__,
                                                                        str(e))), None, sys.exc_info()[2]
            index += 1
        return out, size

    def unpack(self, format, data, offset=0):
        """
        Use a certain named format to unpack from some data.

        :param format: the format name to unpack with
        :param data: the data to unpack from
        :param offset: the optional offset to unpack data from
        """
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
                raise PackError("Could not unpack item %d: %s\n%s: %s" % (index,
                                                                          format,
                                                                          type(e).__name__,
                                                                          str(e))), None, sys.exc_info()[2]
            current_offset += unpacked_size
            index += 1
        return out, current_offset

    def unpack_multiple_as_list(self, unpack_list, data, offset=0):
        """
        Unpack repeated list elements from a data string.

        Each of the tuples in the pack_list are built as (format, arg1, arg2, .., argn)

        Note that this method cannot have any optional unpack_list arguments.

        :param unpack_list: the list of formats
        :param data: the data to unpack from
        :param offset: the optional offset to unpack data from
        """
        current_offset = offset
        out = []
        index = 0
        data_length = len(data)
        while current_offset < data_length:
            list_element = []
            for format in unpack_list:
                try:
                    unpacked, unpacked_size = self.unpack(format, data, current_offset)
                    if format == 'bits':
                        list_element.extend(unpacked)
                    else:
                        list_element.append(unpacked)
                except Exception as e:
                    raise PackError("Could not unpack #%d repetition of item %d: %s\n%s: %s" % (index+1,
                                                                                                len(list_element),
                                                                                                format,
                                                                                                type(e).__name__,
                                                                                                str(e))),\
                        None, sys.exc_info()[2]
                current_offset += unpacked_size
                index += 1
            out.append(list_element)
        return out, current_offset

    def unpack_to_serializables(self, serializables, data):
        """
        Use the formats specified in a serializable object and unpack to it.

        :param serializables: the serializable classes to get the format from and unpack to
        :param data: the data to unpack from
        """
        offset = 0
        out = []
        for serializable in serializables:
            try:
                if serializable.is_list_descriptor:
                    unpack_list, offset = self.unpack_multiple_as_list(serializable.format_list, data, offset)
                else:
                    unpack_list, offset = self.unpack_multiple(serializable.format_list, data,
                                                               serializable.optional_format_list, offset)
            except Exception as e:
                    raise PackError("Failed to unserialize %s\n%s: %s" % (serializable.__name__,
                                                                          type(e).__name__,
                                                                          str(e))), None, sys.exc_info()[2]
            out.append(serializable.from_unpack_list(*unpack_list))
        out.append(data[offset:])
        return out


class Serializable(object):
    """
    Interface for serializable objects.
    """

    __metaclass__ = abc.ABCMeta

    format_list = []
    optional_format_list = []
    is_list_descriptor = False

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
