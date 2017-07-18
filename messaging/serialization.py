import abc
from struct import pack, unpack, unpack_from, Struct


class Bits(object):

    size = 1

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
        return pack('>B', byte)

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
        return [bit_7, bit_6, bit_5, bit_4, bit_3, bit_2, bit_1, bit_0]


class Raw(object):
    """
    Paste/unpack the remaining input without (un)packing.
    """

    def __init__(self):
        super(Raw, self).__init__()
        self.size = 0

    def pack(self, *data):
        out = ''
        for piece in data:
            s_piece = str(piece)
            out += s_piece
            self.size += len(s_piece)
        return out

    def unpack_from(self, data, offset=0):
        out = data[offset:]
        self.size = len(out)
        return out


class VarLen(object):
    """
    Paste/unpack from an encoded length + data string.
    """

    def __init__(self, format, base=1):
        super(VarLen, self).__init__()
        self.format = format
        self.format_size = Struct(self.format).size
        self.base = base
        self.size = 0

    def pack(self, *data):
        raw = ''.join(data)
        length = len(raw)/self.base
        self.size = self.format_size + len(raw)
        return pack('>%s%ds' % (self.format, length), length, raw)

    def unpack_from(self, data, offset=0):
        length, = unpack_from('>%s' % self.format, data, offset)
        length *= self.base
        out, = unpack_from('>%ds' % length, data, offset + self.format_size)
        self.size = self.format_size + length
        return out


class DoubleVarLen(object):
    """
    Paste/unpack from an encoded length1, length2 + data string1, data string2.
    """

    def __init__(self, format1, format2, base1=1, base2=1):
        super(DoubleVarLen, self).__init__()
        self.format1 = format1
        self.format1_size = Struct(self.format1).size
        self.format2 = format2
        self.format2_size = Struct(self.format1).size
        self.base1 = base1
        self.base2 = base2
        self.size = 0

    def pack(self, data1, data2):
        length1 = len(data1)/self.base1
        length2 = len(data2)/self.base2
        self.size = self.format1_size + len(data1) + self.format2_size + len(data2)
        return pack('>%s%s%ds%ds' % (self.format1, self.format2, length1, length2), length1, length2, data1, data2)

    def unpack_from(self, data, offset=0):
        length1, length2 = unpack_from('>%s%s' % (self.format1, self.format2), data, offset)
        raw_length = length1 + length2
        length1 *= self.base1
        length2 *= self.base1
        out1, out2 = unpack_from('>%ds%ds' % (length1, length2), data, offset + self.format1_size + self.format2_size)
        self.size = self.format1_size + self.format2_size + raw_length
        return [out1, out2]


class DefaultStruct(Struct):

    def __init__(self, format, single_value=False):
        super(DefaultStruct, self).__init__(format)
        self.single_value = single_value

    def unpack_from(self, buffer, offset=0):
        out = super(DefaultStruct, self).unpack_from(buffer, offset)
        if self.single_value:
            return out[0]
        else:
            return list(out)


class Serializer(object):

    def __init__(self):
        super(Serializer, self).__init__()
        self._packers = {
            '?': DefaultStruct(">?", True),
            'B': DefaultStruct(">B", True),
            'BBH': DefaultStruct(">BBH"),
            'BH': DefaultStruct(">BH"),
            'H': DefaultStruct(">H", True),
            'HH': DefaultStruct(">HH"),
            'LL': DefaultStruct(">LL"),
            'Q': DefaultStruct(">Q", True),
            'QH': DefaultStruct(">QH"),
            'QL': DefaultStruct(">QL"),
            'QQHHBH': DefaultStruct(">QQHHBH"),
            'ccB': DefaultStruct(">ccB"),
            '4SH': DefaultStruct(">4sH"),
            '20s': DefaultStruct(">20s"),
            '32s': DefaultStruct(">32s"),
            'c20s': DefaultStruct(">c20s"),
            'bits': Bits(),
            'raw': Raw(),
            'varlenBx2': VarLen('B', 2),
            'varlenH': VarLen('H'),
            'varlenHx20': VarLen('H', 20),
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
        self._packers.update({name: Struct(format)})

    def pack(self, format, *data):
        """
        Pack some data according to some format name.

        :param format: the format name to use
        :param data: the data to serialize
        """
        return self._packers[format].pack(*data)

    def pack_multiple(self, pack_list):
        """
        Serialize multiple data tuples.

        Each of the tuples in the pack_list are built as (format, arg1, arg2, .., argn)

        :param pack_list: the list of packable tuples
        """
        out = ""
        for packable in pack_list:
            out += self.pack(*packable)
        return out

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
            if format == 'bits':
                out.extend(self.unpack(format, data, current_offset))
            else:
                out.append(self.unpack(format, data, current_offset))
            current_offset += self._packers[format].size
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
                if format == 'bits':
                    list_element.extend(self.unpack(format, data, current_offset))
                else:
                    list_element.append(self.unpack(format, data, current_offset))
                current_offset += self._packers[format].size
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
            if serializable.is_list_descriptor:
                unpack_list, offset = self.unpack_multiple_as_list(serializable.format_list, data, offset)
            else:
                unpack_list, offset = self.unpack_multiple(serializable.format_list, data,
                                                           serializable.optional_format_list, offset)
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
