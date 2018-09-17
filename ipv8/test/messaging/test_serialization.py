from __future__ import absolute_import

import struct
from unittest import TestCase

from ...messaging.serialization import Serializable, Serializer, PackError


class TestSerializer(TestCase):

    def setUp(self):
        self.serializer = Serializer()

    def test_pack_bool_true(self):
        """
        Check if 'true' booleans can be correctly packed and unpacked.
        """
        value = True

        serialized, _ = self.serializer.pack("?", value)
        unserialized, _ = self.serializer.unpack("?", serialized)

        self.assertEqual(value, unserialized)

    def test_pack_bool_false(self):
        """
        Check if 'false' booleans can be correctly packed and unpacked.
        """
        value = False

        serialized, _ = self.serializer.pack("?", value)
        unserialized, _ = self.serializer.unpack("?", serialized)

        self.assertEqual(value, unserialized)

    def test_pack_byte_0(self):
        """
        Check if a 0 (unsigned byte) can be correctly packed and unpacked.
        """
        value = 0

        serialized, _ = self.serializer.pack("B", value)
        unserialized, _ = self.serializer.unpack("B", serialized)

        self.assertEqual(value, unserialized)

    def test_pack_byte_1(self):
        """
        Check if a 1 (unsigned byte) can be correctly packed and unpacked.
        """
        value = 1

        serialized, _ = self.serializer.pack("B", value)
        unserialized, _ = self.serializer.unpack("B", serialized)

        self.assertEqual(value, unserialized)

    def test_pack_byte_255(self):
        """
        Check if a 255 (unsigned byte) can be correctly packed and unpacked.
        """
        value = 255

        serialized, _ = self.serializer.pack("B", value)
        unserialized, _ = self.serializer.unpack("B", serialized)

        self.assertEqual(value, unserialized)

    def test_pack_byte_256(self):
        """
        Check if a 256 (unsigned byte) throws a struct.error.
        """
        self.assertRaises(struct.error, self.serializer.pack, "B", 256)

    def test_unpack_short_truncated(self):
        """
        Check if 1 byte string cannot be unpacked as a short.
        """
        serialized, _ = self.serializer.pack("B", 255)

        self.assertRaises(struct.error, self.serializer.unpack, "H", serialized)

    def test_pack_list(self):
        """
        Check if a list of shorts is correctly packed and unpacked.
        """
        value0 = 0
        value1 = 1337

        serialized, _ = self.serializer.pack("HH", value0, value1)
        unserialized, _ = self.serializer.unpack("HH", serialized)

        self.assertListEqual([value0, value1], unserialized)

    def test_pack_multiple_byte_256(self):
        """
        Check if pack_multiple of a 256 (unsigned byte) raises a PackError.
        """
        self.assertRaises(PackError, self.serializer.pack_multiple, [("B", 256)])

    def test_unpack_multiple_short_from_byte(self):
        """
        Check if a unpack_multiple of a short from a byte raises a PackError.
        """
        serialized, _ = self.serializer.pack_multiple([("B", 1)])

        self.assertRaises(PackError, self.serializer.unpack_multiple, ["H"], serialized)

    def test_unpack_multiple_list_empty(self):
        """
        Check if a unpack_multiple_as_list can unpack an empty list.
        """
        serialized, _ = self.serializer.pack_multiple([])
        unserialized, _ = self.serializer.unpack_multiple_as_list([], serialized)

        self.assertEqual([], unserialized)

    def test_unpack_multiple_list_bits(self):
        """
        Check if a unpack_multiple_as_list can unpack bits.
        """
        serialized, _ = self.serializer.pack("bits", 0, 1, 0, 1, 0, 1, 0, 1)
        unserialized, _ = self.serializer.unpack_multiple_as_list(["bits"], serialized)

        self.assertEqual(1, len(unserialized))
        self.assertListEqual([0, 1, 0, 1, 0, 1, 0, 1], unserialized[0])

    def test_unpack_multiple_list_short_from_byte(self):
        """
        Check if a unpack_multiple_as_list of a short from a byte raises a PackError.
        """
        serialized, _ = self.serializer.pack_multiple([("B", 1)])

        self.assertRaises(PackError, self.serializer.unpack_multiple_as_list, ["H"], serialized)

    def test_unpack_multiple_list_short_from_byte_3rd(self):
        """
        Check if a unpack_multiple_as_list of a short from a byte raises a PackError in the third repetition.
        """
        serialized, _ = self.serializer.pack_multiple([("H", 1), ("H", 2), ("B", 3)])

        self.assertRaises(PackError, self.serializer.unpack_multiple_as_list, ["H"], serialized)

    def test_unpack_serializables_list_short_from_byte(self):
        """
        Check if a unpack_to_serializables of a short from a byte raises a PackError.
        """
        serialized, _ = self.serializer.pack_multiple([("B", 1)])

        class TestSerializable(Serializable):
            is_list_descriptor = True
            format_list = ["H"]

        self.assertRaises(PackError, self.serializer.unpack_to_serializables, [TestSerializable], serialized)

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
            self.assertTrue(hasattr(packer, 'unpack_from'), msg='%s has no unpack_from() method' % pack_name)
            self.assertTrue(callable(getattr(packer, 'unpack_from')), msg='%s.unpack_from is not a method' % pack_name)

    def test_add_format(self):
        """
        Check if we can add a format on the fly.
        """
        self.serializer.add_packing_format("my_cool_format", "<H") # little-endian

        serialized, _ = self.serializer.pack("my_cool_format", 1) # Packed as 01 00
        [unserialized], _ = self.serializer.unpack("my_cool_format", serialized) # little-endian, unpacked as 00 01 = 1
        unpack_other_end, _ = self.serializer.unpack("H", serialized) # big-endian, unpacked as 01 00 = 256

        self.assertEqual(1, unserialized)
        self.assertEqual(256, unpack_other_end)
