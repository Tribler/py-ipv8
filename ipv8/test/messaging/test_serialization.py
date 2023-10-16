from __future__ import annotations

import struct
from typing import Any, List, cast

from ...messaging.serialization import DefaultStruct, PackError, Serializable, Serializer
from ..base import TestBase


class Short(Serializable):
    """
    Single unsigned short value.
    """

    format_list = ["H"]

    def __init__(self, number: int) -> None:
        """
        Create a Short object from the given number.
        """
        self.number = number

    def to_pack_list(self) -> list[tuple]:
        """
        Serialize to a Serializer pack list.
        """
        return [("H", self.number)]

    @classmethod
    def from_unpack_list(cls: type[Short], number: int) -> Short:
        """
        Create a new Short object from the unpacked value.
        """
        return Short(number)


class Byte(Serializable):
    """
    Single unsigned char value.
    """

    format_list = ["B"]

    def __init__(self, byte: int) -> None:
        """
        Create a Byte object from the given number.
        """
        self.byte = byte

    def to_pack_list(self) -> list[tuple]:
        """
        Serialize to a Serializer pack list.
        """
        return [("B", self.byte)]

    @classmethod
    def from_unpack_list(cls: type[Byte], byte: int) -> Byte:
        """
        Create a new Byte object from the unpacked value.
        """
        return Byte(byte)


class Nested(Serializable):
    """
    Nest a list of Byte objects.
    """

    format_list = [[Byte]]

    def __init__(self, byte_list: list[Byte]) -> None:
        """
        Create a Nested object from the given list of bytes.
        """
        self.byte_list = byte_list

    def to_pack_list(self) -> list[tuple]:
        """
        Serialize to a Serializer pack list.
        """
        return [('payload-list', self.byte_list)]

    @classmethod
    def from_unpack_list(cls: type[Nested], byte_list: list[Byte]) -> Nested:
        """
        Create a new Byte object from the unpacked Byte objects.
        """
        return Nested(byte_list)


class Raw(Serializable):
    """
    Single raw value.
    """

    format_list = ["raw"]

    def __init__(self, byte_string: bytes) -> None:
        """
        Create a Raw object from the given byte string.
        """
        self.raw = byte_string

    def to_pack_list(self) -> list[tuple]:
        """
        Serialize to a Serializer pack list.
        """
        return [("raw", self.raw)]

    @classmethod
    def from_unpack_list(cls: type[Raw], raw_list: list[Raw]) -> Raw:
        """
        Create a new Raw object from the unpacked value.
        """
        return Raw(raw_list)


class NestedWithRaw(Serializable):
    """
    Payload that uses multiple raw values.
    """

    format_list = [[Raw]]

    def __init__(self, raw_list: list[list[Raw]]) -> None:
        """
        Create a NestedWithRaw object from the given list of Raw object.
        """
        self.raw_list = raw_list

    def to_pack_list(self) -> list[tuple]:
        """
        Serialize to a Serializer pack list.
        """
        return [('payload-list', self.raw_list)]

    @classmethod
    def from_unpack_list(cls: type[NestedWithRaw], raw_list: list[list[Raw]]) -> NestedWithRaw:
        """
        Create a new NestedWithRaw object from the unpacked Raw objects.
        """
        return NestedWithRaw(raw_list)


class TestSerializer(TestBase):
    """
    Tests related to the Serializer.
    """

    def setUp(self) -> None:
        """
        Create a serializer.
        """
        super().setUp()
        self.serializer = Serializer()

    def check_pack_unpack(self, format_ser: str, format_unser: str, value: Any) -> None:  # noqa: ANN401
        """
        Pack a value using a given serializer format and unpack using another format.

        Asserts that the value remains unchanged.
        """
        packer = self.serializer.get_packer_for(format_ser)
        values = (value,) if not isinstance(value, (list, tuple)) else value
        serialized = packer.pack(*values)

        unpack_list = []
        packer = self.serializer.get_packer_for(format_unser)
        packer.unpack(serialized, 0, unpack_list)

        self.assertEqual(value, unpack_list[0])

    def test_pack_bool_true(self) -> None:
        """
        Check if 'true' booleans can be correctly packed and unpacked.
        """
        self.check_pack_unpack('?', '?', True)

    def test_pack_bool_false(self) -> None:
        """
        Check if 'false' booleans can be correctly packed and unpacked.
        """
        self.check_pack_unpack('?', '?', False)

    def test_pack_byte_0(self) -> None:
        """
        Check if a 0 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 0)

    def test_pack_byte_1(self) -> None:
        """
        Check if a 1 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 1)

    def test_pack_byte_255(self) -> None:
        """
        Check if a 255 (unsigned byte) can be correctly packed and unpacked.
        """
        self.check_pack_unpack('B', 'B', 255)

    def test_pack_byte_256(self) -> None:
        """
        Check if a 256 (unsigned byte) throws a struct.error.
        """
        self.assertRaises(struct.error, self.check_pack_unpack, 'B', 'B', 256)

    def test_unpack_short_truncated(self) -> None:
        """
        Check if 1 byte string cannot be unpacked as a short.
        """
        self.assertRaises(struct.error, self.check_pack_unpack, 'B', 'H', 255)

    def test_pack_list(self) -> None:
        """
        Check if a list of shorts is correctly packed and unpacked.
        """
        self.check_pack_unpack('HH', 'HH', (0, 1337))

    def test_get_formats(self) -> None:
        """
        Check if all reported formats contain valid packers.
        """
        formats = self.serializer.get_available_formats()

        for fmt in formats:
            packer = self.serializer.get_packer_for(fmt)
            pack_name = f"{packer.__class__.__name__}({fmt})"
            self.assertTrue(hasattr(packer, 'pack'), msg='%s has no pack() method' % pack_name)
            self.assertTrue(callable(packer.pack), msg='%s.pack is not a method' % pack_name)
            self.assertTrue(hasattr(packer, 'unpack'), msg='%s has no unpack() method' % pack_name)
            self.assertTrue(callable(packer.unpack), msg='%s.unpack is not a method' % pack_name)

    def test_add_packer(self) -> None:
        """
        Check if we can add a packer on the fly.
        """
        self.serializer.add_packer("H_LE", DefaultStruct("<H"))  # little-endian

        serialized = self.serializer.get_packer_for("H_LE").pack(1)  # Packed as 01 00

        unpacked = []
        self.serializer.get_packer_for("H_LE").unpack(serialized, 0, unpacked)  # little-endian, unpacked as 00 01 = 1
        self.serializer.get_packer_for("H").unpack(serialized, 0, unpacked)  # big-endian, unpacked as 01 00 = 256

        self.assertEqual([1, 256], unpacked)

    def test_nested_serializable(self) -> None:
        """
        Check if we can unpack nested serializables.
        """
        instance = Short(123)

        data = self.serializer.pack_serializable(instance)
        output, _ = self.serializer.unpack_serializable(Short, data)

        self.assertEqual(instance.number, output.number)

    def test_serializable_byte_256(self) -> None:
        """
        Check if pack_serializable of a 256 (unsigned byte) raises a PackError.
        """
        self.assertRaises(PackError, self.serializer.pack_serializable, Byte(256))

    def test_serializable_short_from_byte(self) -> None:
        """
        Check if a unpack_serializable of a short from a byte raises a PackError.
        """
        serialized = self.serializer.pack_serializable(Byte(1))
        self.assertRaises(PackError, self.serializer.unpack_serializable, Short, serialized)

    def test_serializable_list(self) -> None:
        """
        Check if we can (un)pack serializables easily.
        """
        instance1 = Short(123)
        instance2 = Short(456)

        data = self.serializer.pack_serializable_list([instance1, instance2])
        deserialized = cast(List[Short], self.serializer.unpack_serializable_list([Short, Short], data))

        self.assertEqual(instance1.number, 123)
        self.assertEqual(instance1.number, deserialized[0].number)
        self.assertEqual(instance2.number, 456)
        self.assertEqual(instance2.number, deserialized[1].number)

    def test_serializable_list_extra_data(self) -> None:
        """
        Check if we throw an error when we have too much data to unpack.
        """
        instance1 = Short(123)
        instance2 = Short(456)

        data = self.serializer.pack_serializable_list([instance1, instance2])
        self.assertRaises(PackError, self.serializer.unpack_serializable_list, [Short, Short], data + b"Nope.avi")

    def test_nested_payload_list(self) -> None:
        """
        Check if we can unpack a nested serializable.
        """
        serializable = Nested([Byte(1), Byte(2)])
        data = self.serializer.pack_serializable(serializable)
        decoded, _ = self.serializer.unpack_serializable(Nested, data)
        self.assertEqual(serializable.byte_list[0].byte, decoded.byte_list[0].byte)
        self.assertEqual(serializable.byte_list[1].byte, decoded.byte_list[1].byte)

    def test_nested_serializable_raw(self) -> None:
        """
        Check if we can unpack multiple nested serializables that end with raw.
        """
        instance = NestedWithRaw([Raw(b'123'), Raw(b'456')])
        data = self.serializer.pack_serializable(instance)
        output, _ = self.serializer.unpack_serializable(NestedWithRaw, data)
        self.assertEqual(instance.raw_list[0].raw, output.raw_list[0].raw)
        self.assertEqual(instance.raw_list[1].raw, output.raw_list[1].raw)
