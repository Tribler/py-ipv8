import struct

from ..base import TestBase
from ...messaging.serialization import DefaultStruct, PackError, Serializable, Serializer


class Short(Serializable):
    format_list = ["H"]

    def __init__(self, number):
        self.number = number

    def to_pack_list(self):
        return [("H", self.number)]

    @classmethod
    def from_unpack_list(cls, *args):
        return Short(*args)


class Byte(Serializable):
    format_list = ["B"]

    def __init__(self, byte):
        self.byte = byte

    def to_pack_list(self):
        return [("B", self.byte)]

    @classmethod
    def from_unpack_list(cls, *args):
        return Byte(*args)


class Nested(Serializable):
    format_list = [[Byte]]

    def __init__(self, byte_list):
        self.byte_list = byte_list

    def to_pack_list(self):
        return [('payload-list', self.byte_list)]

    @classmethod
    def from_unpack_list(cls, *args):
        return Nested(*args)


class TestSerializer(TestBase):

    def setUp(self):
        super(TestSerializer, self).setUp()
        self.serializer = Serializer()

    def check_pack_unpack(self, format_ser, format_unser, value):
        packer = self.serializer.get_packer_for(format_ser)
        values = (value,) if not isinstance(value, (list, tuple)) else value
        serialized = packer.pack(*values)

        unpack_list = []
        packer = self.serializer.get_packer_for(format_unser)
        packer.unpack(serialized, 0, unpack_list)

        self.assertEqual(value, unpack_list[0])

    def test_pack_bool_true(self):
        """
        Check if 'true' booleans can be correctly packed and unpacked.
        """
        self.check_pack_unpack('?', '?', True)

    def test_pack_bool_false(self):
        """
        Check if 'false' booleans can be correctly packed and unpacked.
        """
        self.check_pack_unpack('?', '?', False)

    def test_pack_byte_0(self):
        """
        Check if a 0 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 0)

    def test_pack_byte_1(self):
        """
        Check if a 1 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 1)

    def test_pack_byte_255(self):
        """
        Check if a 255 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 255)

    def test_pack_byte_256(self):
        """
        Check if a 256 (unsigned byte) throws a struct.error.
        """
        self.assertRaises(struct.error, self.check_pack_unpack, 'B', 'B', 256)

    def test_unpack_short_truncated(self):
        """
        Check if 1 byte string cannot be unpacked as a short.
        """
        self.assertRaises(struct.error, self.check_pack_unpack, 'B', 'H', 255)

    def test_pack_list(self):
        """
        Check if a list of shorts is correctly packed and unpacked.
        """
        self.check_pack_unpack('HH', 'HH', (0, 1337))

    def test_get_formats(self):
        """
        Check if all reported formats contain valid packers.
        """
        formats = self.serializer.get_available_formats()

        for format in formats:
            packer = self.serializer.get_packer_for(format)
            pack_name = "%s(%s)" % (packer.__class__.__name__, format)
            self.assertTrue(hasattr(packer, 'pack'), msg='%s has no pack() method' % pack_name)
            self.assertTrue(callable(getattr(packer, 'pack')), msg='%s.pack is not a method' % pack_name)
            self.assertTrue(hasattr(packer, 'unpack'), msg='%s has no unpack() method' % pack_name)
            self.assertTrue(callable(getattr(packer, 'unpack')), msg='%s.unpack is not a method' % pack_name)

    def test_add_packer(self):
        """
        Check if we can add a packer on the fly.
        """
        self.serializer.add_packer("H_LE", DefaultStruct("<H"))  # little-endian

        serialized = self.serializer.get_packer_for("H_LE").pack(1)  # Packed as 01 00

        unpacked = []
        self.serializer.get_packer_for("H_LE").unpack(serialized, 0, unpacked)  # little-endian, unpacked as 00 01 = 1
        self.serializer.get_packer_for("H").unpack(serialized, 0, unpacked)  # big-endian, unpacked as 01 00 = 256

        self.assertEqual([1, 256], unpacked)

    def test_nested_serializable(self):
        """
        Check if we can unpack nested serializables.
        """
        instance = Short(123)

        data = self.serializer.pack_serializable(instance)
        output, _ = self.serializer.unpack_serializable(Short, data)

        self.assertEqual(instance.number, output.number)

    def test_serializable_byte_256(self):
        """
        Check if pack_serializable of a 256 (unsigned byte) raises a PackError.
        """
        self.assertRaises(PackError, self.serializer.pack_serializable, Byte(256))

    def test_serializable_short_from_byte(self):
        """
        Check if a unpack_serializable of a short from a byte raises a PackError.
        """
        serialized = self.serializer.pack_serializable(Byte(1))
        self.assertRaises(PackError, self.serializer.unpack_serializable, Short, serialized)

    def test_serializable_list(self):
        """
        Check if we can (un)pack serializables easily.
        """
        instance1 = Short(123)
        instance2 = Short(456)

        data = self.serializer.pack_serializable_list([instance1, instance2])
        deserialized = self.serializer.unpack_serializable_list([Short, Short], data)

        self.assertEqual(instance1.number, 123)
        self.assertEqual(instance1.number, deserialized[0].number)
        self.assertEqual(instance2.number, 456)
        self.assertEqual(instance2.number, deserialized[1].number)

    def test_serializable_list_extra_data(self):
        """
        Check if we throw an error when we have too much data to unpack.
        """
        instance1 = Short(123)
        instance2 = Short(456)

        data = self.serializer.pack_serializable_list([instance1, instance2])
        self.assertRaises(PackError, self.serializer.unpack_serializable_list, [Short, Short], data + b"Nope.avi")

    def test_nested_payload_list(self):
        serializable = Nested([Byte(1), Byte(2)])
        data = self.serializer.pack_serializable(serializable)
        decoded, _ = self.serializer.unpack_serializable(Nested, data)
        self.assertEqual(serializable.byte_list[0].byte, decoded.byte_list[0].byte)
        self.assertEqual(serializable.byte_list[1].byte, decoded.byte_list[1].byte)
