from __future__ import annotations

from dataclasses import dataclass as ogdataclass
from dataclasses import is_dataclass
from typing import List, TypeVar

from ...messaging.payload_dataclass import dataclass, type_from_format
from ...messaging.serialization import default_serializer
from ..base import TestBase

varlenH = type_from_format('varlenH')  # noqa: N816

T = TypeVar("T")


@dataclass
class NativeBool:
    """
    A single boolean payload.
    """

    a: bool


@dataclass
class NativeInt:
    """
    A single integer payload.
    """

    a: int


@dataclass
class NativeBytes:
    """
    A single bytes payload.
    """

    a: bytes


@dataclass
class NativeStr:
    """
    A single string payload.
    """

    a: str


@dataclass
class SerializerType:
    """
    A ``Serializer`` format payload.
    """

    a: varlenH


@dataclass
class NestedType:
    """
    A single nested payload.
    """

    a: NativeInt


@dataclass
class NestedListType:
    """
    A single list of nested payload.
    """

    a: List[NativeInt]  # Backward compatibility: Python >= 3.9 can use ``list[NativeInt]``

@dataclass
class ListIntType:
    """
    A single list of integers.
    """

    a: List[int]

@dataclass
class ListBoolType:
    """
    A single list of booleans.
    """

    a: List[bool]

@ogdataclass
class Unknown:
    """
    To whomever is reading this and wondering why dict is not supported: use a nested payload instead.
    """

    a: dict


@dataclass
class A:
    """
    A payload consisting of two integers.
    """

    a: int
    b: int


@dataclass
class B:
    """
    A payload consisting of two integers, of which one has a default value.
    """

    a: int
    b: int = 3


@dataclass(eq=False)
class FwdDataclass:
    """
    A payload to test if the dataclass overwrite forwards its arguments to the "real" dataclass.
    """

    a: int


@dataclass
class StripMsgId:
    """
    Payload to make sure that the message id is not seen as a field.
    """

    a: int
    msg_id = 1

    names = []   # Expose secret VariablePayload list
    format_list = []   # Expose secret VariablePayload list


@dataclass(msg_id=1)
class FwdMsgId:
    """
    Payload that specfies the message id as an argument to the dataclass overwrite.
    """

    a: int

    names = []  # Expose secret VariablePayload list
    format_list = []  # Expose secret VariablePayload list


@dataclass
class EverythingItem:
    """
    An item for the following Everything payload.
    """

    a: bool


@dataclass
@ogdataclass
class Everything:
    """
    Dataclass payload that includes all functionality.
    """

    a: int
    b: bytes
    c: varlenH
    d: EverythingItem
    e: List[EverythingItem]  # Backward compatibility: Python >= 3.9 can use ``list[EverythingItem]``
    f: str
    g: List[int]
    h: List[bool]


class TestDataclassPayload(TestBase):
    """
    Tests for dataclass-based payloads.
    """

    @staticmethod
    def _pack_and_unpack(payload: type[T], instance: object) -> T:
        """
        Serialize and unserialize an instance of payload.

        :param payload: the payload class to serialize for
        :type payload: type(Payload)
        :param instance: the payload instance to serialize
        :type instance: Payload
        :return: the repacked instance
        """
        serialized = default_serializer.pack_serializable(instance)
        deserialized, _ = default_serializer.unpack_serializable(payload, serialized)
        return deserialized

    def test_base_unnamed(self) -> None:
        """
        Check if the wrapper returns the payload correctly with unnamed arguments.
        """
        payload = A(42, 1337)

        deserialized = self._pack_and_unpack(A, payload)

        self.assertEqual(payload.a, 42)
        self.assertEqual(payload.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_base_named(self) -> None:
        """
        Check if the wrapper returns the payload correctly with named arguments.
        """
        payload = A(b=1337, a=42)

        deserialized = self._pack_and_unpack(A, payload)

        self.assertEqual(payload.a, 42)
        self.assertEqual(payload.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_pass_default(self) -> None:
        """
        Check if the wrapper forwards default values.
        """
        payload = B(5)

        self.assertEqual(payload.a, 5)
        self.assertEqual(payload.b, 3)

    def test_pass_default_overwrite(self) -> None:
        """
        Check if the wrapper correctly overwrites default values.
        """
        payload = B(5, 7)

        self.assertEqual(payload.a, 5)
        self.assertEqual(payload.b, 7)

    def test_nativebool_t_payload(self) -> None:
        """
        Check if unpacked BitPayload(true) works correctly.
        """
        payload = NativeBool(True)

        deserialized = self._pack_and_unpack(NativeBool, payload)

        self.assertEqual(payload.a, True)
        self.assertEqual(deserialized.a, True)

    def test_nativebool_f_payload(self) -> None:
        """
        Check if unpacked BitPayload(false) works correctly.
        """
        payload = NativeBool(False)

        deserialized = self._pack_and_unpack(NativeBool, payload)

        self.assertEqual(payload.a, False)
        self.assertEqual(deserialized.a, False)

    def test_nativeint_negative_payload(self) -> None:
        """
        Check if unpacked NativeInt(-1) works correctly.
        """
        payload = NativeInt(-1)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, -1)
        self.assertEqual(deserialized.a, -1)

    def test_nativeint_zero_payload(self) -> None:
        """
        Check if unpacked NativeInt(0) works correctly.
        """
        payload = NativeInt(0)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, 0)
        self.assertEqual(deserialized.a, 0)

    def test_nativeint_positive_payload(self) -> None:
        """
        Check if unpacked NativeInt(1) works correctly.
        """
        payload = NativeInt(1)

        deserialized = self._pack_and_unpack(NativeInt, payload)

        self.assertEqual(payload.a, 1)
        self.assertEqual(deserialized.a, 1)

    def test_nativebytes_empty_payload(self) -> None:
        """
        Check if unpacked NativeBytes(b'') works correctly.
        """
        payload = NativeBytes(b'')

        deserialized = self._pack_and_unpack(NativeBytes, payload)

        self.assertEqual(payload.a, b'')
        self.assertEqual(deserialized.a, b'')

    def test_nativebytes_filled_payload(self) -> None:
        """
        Check if unpacked NativeBytes(b'hi') works correctly.
        """
        payload = NativeBytes(b'hi')

        deserialized = self._pack_and_unpack(NativeBytes, payload)

        self.assertEqual(payload.a, b'hi')
        self.assertEqual(deserialized.a, b'hi')

    def test_nativestr_empty_payload(self) -> None:
        """
        Check if unpacked NativeStr('') works correctly.
        """
        payload = NativeStr('')

        deserialized = self._pack_and_unpack(NativeStr, payload)

        self.assertEqual(payload.a, '')
        self.assertEqual(deserialized.a, '')

    def test_nativestr_filled_payload(self) -> None:
        """
        Check if unpacked NativeStr('hi') works correctly.
        """
        payload = NativeStr('hi')

        deserialized = self._pack_and_unpack(NativeStr, payload)

        self.assertEqual(payload.a, 'hi')
        self.assertEqual(deserialized.a, 'hi')

    def test_serializertype_payload(self) -> None:
        """
        Check if a custom SerializerType ("varlenH") works correctly.
        """
        payload = SerializerType(b'hi')

        deserialized = self._pack_and_unpack(SerializerType, payload)

        self.assertEqual(payload.a, b'hi')
        self.assertEqual(deserialized.a, b'hi')

    def test_nested_payload(self) -> None:
        """
        Check if a nested payload works correctly.
        """
        payload = NestedType(NativeInt(42))

        deserialized = self._pack_and_unpack(NestedType, payload)

        self.assertEqual(payload.a, NativeInt(42))
        self.assertEqual(deserialized.a, NativeInt(42))

    def test_native_intlist_payload(self) -> None:
        """
        Check if a list of native types works correctly.
        """
        payload = ListIntType([1, 2])
        deserialized = self._pack_and_unpack(ListIntType, payload)

        self.assertListEqual(payload.a, [1, 2])
        self.assertListEqual(deserialized.a, [1, 2])

    def test_native_boollist_payload(self) -> None:
        """
        Check if a list of native types works correctly.
        """
        payload = ListBoolType([True, False])
        deserialized = self._pack_and_unpack(ListBoolType, payload)

        self.assertListEqual(payload.a, [True, False])
        self.assertListEqual(deserialized.a, [True, False])

    def test_nestedlist_empty_payload(self) -> None:
        """
        Check if an empty list of nested payloads works correctly.
        """
        payload = NestedListType([])

        deserialized = self._pack_and_unpack(NestedListType, payload)

        self.assertListEqual(payload.a, [])
        self.assertListEqual(deserialized.a, [])

    def test_nestedlist_filled_payload(self) -> None:
        """
        Check if a list of nested payloads works correctly.
        """
        payload = NestedListType([NativeInt(42), NativeInt(1337)])

        deserialized = self._pack_and_unpack(NestedListType, payload)

        self.assertListEqual(payload.a, [NativeInt(42), NativeInt(1337)])
        self.assertListEqual(deserialized.a, [NativeInt(42), NativeInt(1337)])

    def test_unknown_payload(self) -> None:
        """
        Check if an unknown type raises an error.
        """
        self.assertRaises(NotImplementedError, dataclass, Unknown)

    def test_fwd_args(self) -> None:
        """
        Check if ``dataclass_payload`` forwards its arguments to ``dataclass``.

        We forward ``eq=False`` because it's easy to test.
        """
        self.assertEqual(NativeInt(1), NativeInt(1))
        self.assertNotEqual(FwdDataclass(3), FwdDataclass(3))

    def test_strip_msg_id(self) -> None:
        """
        Check if the ``msg_id`` field is identifier and stripped.
        """
        payload = StripMsgId(42)

        self.assertIn("a", payload.names)
        self.assertNotIn("msg_id", payload.names)
        self.assertListEqual(["q"], payload.format_list)
        self.assertEqual(payload.msg_id, 1)

    def test_fwd_msg_id(self) -> None:
        """
        Check if the ``msg_id`` argument is sets the Payload ``msg_id``.
        """
        payload = FwdMsgId(42)

        self.assertIn("a", payload.names)
        self.assertNotIn("msg_id", payload.names)
        self.assertListEqual(["q"], payload.format_list)
        self.assertEqual(payload.msg_id, 1)

    def test_everything(self) -> None:
        """
        Check if the wrapper handles all of the different data types together.
        """
        a = Everything(42,
                       b'1337',
                       b'1337',
                       EverythingItem(True),
                       [EverythingItem(False), EverythingItem(True)],
                       "hi",
                       [3, 4],
                       [False, True])

        self.assertTrue(is_dataclass(a))

        r = self._pack_and_unpack(Everything, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(r.a, 42)

        self.assertEqual(a.b, b'1337')
        self.assertEqual(r.b, b'1337')

        self.assertEqual(a.c, b'1337')
        self.assertEqual(r.c, b'1337')

        self.assertEqual(a.d, EverythingItem(True))
        self.assertEqual(r.d, EverythingItem(True))

        self.assertListEqual(a.e, [EverythingItem(False), EverythingItem(True)])
        self.assertListEqual(r.e, [EverythingItem(False), EverythingItem(True)])

        self.assertEqual(a.f, "hi")
        self.assertEqual(r.f, "hi")

        self.assertEqual(a.g, [3, 4])
        self.assertEqual(r.g, [3, 4])

        self.assertEqual(a.h, [False, True])
        self.assertEqual(r.h, [False, True])
