from dataclasses import dataclass, is_dataclass
from typing import List

from ..base import TestBase
from ...messaging.payload_dataclass import overwrite_dataclass, type_from_format
from ...messaging.serialization import default_serializer

ogdataclass = dataclass
dataclass = overwrite_dataclass(dataclass)
varlenH = type_from_format('varlenH')


@dataclass
class NativeBool:
    a: bool


@dataclass
class NativeInt:
    a: int


@dataclass
class NativeBytes:
    a: bytes


@dataclass
class NativeStr:
    a: str


@dataclass
class SerializerType:
    a: varlenH


@dataclass
class NestedType:
    a: NativeInt


@dataclass
class NestedListType:
    a: [NativeInt]


@dataclass
class NestedListTypeType:
    a: List[NativeInt]


@ogdataclass
class Unknown:
    """
    To whomever is reading this and wondering why dict is not supported: use a nested payload instead.
    """
    a: dict


@dataclass
class A:
    a: int
    b: int


@dataclass(eq=False)
class FwdDataclass:
    a: int


@dataclass
class StripMsgId:
    a: int
    msg_id = 1


@dataclass(msg_id=1)
class FwdMsgId:
    a: int


@dataclass
@ogdataclass
class Everything:
    @dataclass
    class Item:
        a: bool

    a: int
    b: bytes
    c: varlenH
    d: Item
    e: [Item]
    f: str
    g: List[Item]


class TestDataclassPayload(TestBase):  # pylint: disable=R0904

    @staticmethod
    def _pack_and_unpack(payload, instance):
        """
        Serialize and unserialize an instance of payload.
        :param payload: the payload class to serialize for
        :type payload: type(Payload)
        :param instance: the payload instance to serialize
        :type instance: Payload
        :return: the repacked instance
        """
        serialized = default_serializer.pack_serializable(instance)
        deserialized, _ = default_serializer.unpack_serializable(payload, serialized)  # pylint: disable=E0632
        return deserialized

    def test_base_unnamed(self):
        """
        Check if the wrapper returns the payload correctly with unnamed arguments.
        """
        payload = A(42, 1337)

        deserialized = self._pack_and_unpack(A, payload)

        self.assertEqual(payload.a, 42)
        self.assertEqual(payload.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_base_named(self):
        """
        Check if the wrapper returns the payload correctly with named arguments.
        """
        payload = A(b=1337, a=42)

        deserialized = self._pack_and_unpack(A, payload)

        self.assertEqual(payload.a, 42)
        self.assertEqual(payload.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_nativebool_t_payload(self):
        """
        Check if unpacked BitPayload(true) works correctly.
        """
        payload = NativeBool(True)

        deserialized = self._pack_and_unpack(NativeBool, payload)

        self.assertEqual(payload.a, True)
        self.assertEqual(deserialized.a, True)

    def test_nativebool_f_payload(self):
        """
        Check if unpacked BitPayload(false) works correctly.
        """
        payload = NativeBool(False)

        deserialized = self._pack_and_unpack(NativeBool, payload)

        self.assertEqual(payload.a, False)
        self.assertEqual(deserialized.a, False)

    def test_nativeint_negative_payload(self):
        """
        Check if unpacked NativeInt(-1) works correctly.
        """
        payload = NativeInt(-1)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, -1)
        self.assertEqual(deserialized.a, -1)

    def test_nativeint_zero_payload(self):
        """
        Check if unpacked NativeInt(0) works correctly.
        """
        payload = NativeInt(0)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, 0)
        self.assertEqual(deserialized.a, 0)

    def test_nativeint_positive_payload(self):
        """
        Check if unpacked NativeInt(1) works correctly.
        """
        payload = NativeInt(1)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, 1)
        self.assertEqual(deserialized.a, 1)

    def test_nativebytes_empty_payload(self):
        """
        Check if unpacked NativeBytes(b'') works correctly.
        """
        payload = NativeBytes(b'')

        deserialized = self._pack_and_unpack(NativeBytes, payload)

        self.assertEqual(payload.a, b'')
        self.assertEqual(deserialized.a, b'')

    def test_nativebytes_filled_payload(self):
        """
        Check if unpacked NativeBytes(b'hi') works correctly.
        """
        payload = NativeBytes(b'hi')

        deserialized = self._pack_and_unpack(NativeBytes, payload)

        self.assertEqual(payload.a, b'hi')
        self.assertEqual(deserialized.a, b'hi')

    def test_nativestr_empty_payload(self):
        """
        Check if unpacked NativeStr('') works correctly.
        """
        payload = NativeStr('')

        deserialized = self._pack_and_unpack(NativeStr, payload)

        self.assertEqual(payload.a, '')
        self.assertEqual(deserialized.a, '')

    def test_nativestr_filled_payload(self):
        """
        Check if unpacked NativeStr('hi') works correctly.
        """
        payload = NativeStr('hi')

        deserialized = self._pack_and_unpack(NativeStr, payload)

        self.assertEqual(payload.a, 'hi')
        self.assertEqual(deserialized.a, 'hi')

    def test_serializertype_payload(self):
        """
        Check if a custom SerializerType ("varlenH") works correctly.
        """
        payload = SerializerType(b'hi')

        deserialized = self._pack_and_unpack(SerializerType, payload)

        self.assertEqual(payload.a, b'hi')
        self.assertEqual(deserialized.a, b'hi')

    def test_nested_payload(self):
        """
        Check if a nested payload works correctly.
        """
        payload = NestedType(NativeInt(42))

        deserialized = self._pack_and_unpack(NestedType, payload)

        self.assertEqual(payload.a, NativeInt(42))
        self.assertEqual(deserialized.a, NativeInt(42))

    def test_nestedlist_empty_payload(self):
        """
        Check if an empty list of nested payloads works correctly.
        """
        payload = NestedListType([])

        deserialized = self._pack_and_unpack(NestedListType, payload)

        self.assertListEqual(payload.a, [])
        self.assertListEqual(deserialized.a, [])

    def test_nestedlist_filled_payload(self):
        """
        Check if a list of nested payloads works correctly.
        """
        payload = NestedListType([NativeInt(42), NativeInt(1337)])

        deserialized = self._pack_and_unpack(NestedListType, payload)

        self.assertListEqual(payload.a, [NativeInt(42), NativeInt(1337)])
        self.assertListEqual(deserialized.a, [NativeInt(42), NativeInt(1337)])

    def test_nestedlisttype_empty_payload(self):
        """
        Check if an empty list type of nested payloads works correctly.
        """
        payload = NestedListTypeType([])

        deserialized = self._pack_and_unpack(NestedListTypeType, payload)

        self.assertListEqual(payload.a, [])
        self.assertListEqual(deserialized.a, [])

    def test_unknown_payload(self):
        """
        Check if an unknown type raises an error.
        """
        self.assertRaises(NotImplementedError, dataclass, Unknown)

    def test_nestedlisttype_filled_payload(self):
        """
        Check if a list type of nested payloads works correctly.
        """
        payload = NestedListTypeType([NativeInt(42), NativeInt(1337)])

        deserialized = self._pack_and_unpack(NestedListTypeType, payload)

        self.assertListEqual(payload.a, [NativeInt(42), NativeInt(1337)])
        self.assertListEqual(deserialized.a, [NativeInt(42), NativeInt(1337)])

    def test_fwd_args(self):
        """
        Check if ``dataclass_payload`` forwards its arguments to ``dataclass``.

        We forward ``eq=False`` because it's easy to test.
        """
        self.assertEqual(NativeInt(1), NativeInt(1))
        self.assertNotEqual(FwdDataclass(3), FwdDataclass(3))

    def test_strip_msg_id(self):
        """
        Check if the ``msg_id`` field is identifier and stripped.
        """
        payload = StripMsgId(42)

        self.assertIn("a", payload.names)
        self.assertNotIn("msg_id", payload.names)
        self.assertListEqual(["q"], payload.format_list)
        self.assertEqual(payload.msg_id, 1)

    def test_fwd_msg_id(self):
        """
        Check if the ``msg_id`` argument is sets the Payload ``msg_id``.
        """
        payload = FwdMsgId(42)

        self.assertIn("a", payload.names)
        self.assertNotIn("msg_id", payload.names)
        self.assertListEqual(["q"], payload.format_list)
        self.assertEqual(payload.msg_id, 1)

    def test_everything(self):
        """
        Check if the wrapper handles all of the different data types together.
        """
        a = Everything(42,
                       b'1337',
                       b'1337',
                       Everything.Item(True),
                       [Everything.Item(False), Everything.Item(True)],
                       "hi",
                       [Everything.Item(True), Everything.Item(False)])

        self.assertTrue(is_dataclass(a))

        r = self._pack_and_unpack(Everything, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(r.a, 42)

        self.assertEqual(a.b, b'1337')
        self.assertEqual(r.b, b'1337')

        self.assertEqual(a.c, b'1337')
        self.assertEqual(r.c, b'1337')

        self.assertEqual(a.d, Everything.Item(True))
        self.assertEqual(r.d, Everything.Item(True))

        self.assertListEqual(a.e, [Everything.Item(False), Everything.Item(True)])
        self.assertListEqual(r.e, [Everything.Item(False), Everything.Item(True)])

        self.assertEqual(a.f, "hi")
        self.assertEqual(r.f, "hi")

        self.assertListEqual(a.g, [Everything.Item(True), Everything.Item(False)])
        self.assertListEqual(r.g, [Everything.Item(True), Everything.Item(False)])
