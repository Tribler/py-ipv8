from __future__ import absolute_import

from unittest import TestCase

from ...messaging.lazy_payload import VariablePayload
from ...messaging.payload import Payload
from ...messaging.serialization import default_serializer


class A(VariablePayload):
    """
    A basic VariablePayload.
    """
    format_list = ['I', 'H']
    names = ["a", "b"]


class B(VariablePayload):
    """
    A VariablePayload with a nested Payload.
    """
    format_list = [A]
    names = ["a"]


class C(A):
    """
    A VariablePayload with inherited fields.
    """
    format_list = A.format_list + ['B']
    names = A.names + ['c']


class OldA(Payload):
    format_list = ["I", "H"]

    def __init__(self, a, b):
        self.a = a
        self.b = b

    def to_pack_list(self):
        return [("I", self.a),
                ("H", self.b)]

    @classmethod
    def from_unpack_list(cls, *args):
        return OldA(*args) # pylint: disable=E1120


class D(VariablePayload):
    format_list = ["I"]
    names = ["a"]

    def fix_pack_a(self, value):
        return value + 1

    @classmethod
    def fix_unpack_a(cls, value):
        return value - 1


class NewC(VariablePayload, OldA):
    """
    A VariablePayload with inherited fields.
    """
    format_list = OldA.format_list + ['B']
    names = ['a', 'b', 'c']


class TestVariablePayload(TestCase):

    def _pack_and_unpack(self, payload, instance):
        """
        Serialize and unserialize an instance of payload.
        :param payload: the payload class to serialize for
        :type payload: type(Payload)
        :param instance: the payload instance to serialize
        :type instance: Payload
        :return: the repacked instance
        """
        plist = instance.to_pack_list()
        serialized, _ = default_serializer.pack_multiple(plist)
        deserialized, _ = default_serializer.unpack_to_serializables([payload], serialized)  # pylint: disable=E0632
        return deserialized

    def test_base_unnamed(self):
        """
        Check if the wrapper returns the payload correctly with unnamed arguments.
        """
        a = A(42, 1337)

        deserialized = self._pack_and_unpack(A, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(a.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_base_named(self):
        """
        Check if the wrapper returns the payload correctly with named arguments.
        """
        a = A(b=1337, a=42)

        deserialized = self._pack_and_unpack(A, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(a.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_inheritance(self):
        """
        Check if the wrapper allows for nested payloads.
        """
        a = A(1, 2)
        b = B(a)

        deserialized = self._pack_and_unpack(B, b)

        self.assertEqual(b.a.a, deserialized.a.a)
        self.assertEqual(b.a.b, deserialized.a.b)
        self.assertIsInstance(deserialized, B)
        self.assertIsInstance(deserialized.a, A)

    def test_subclass(self):
        """
        Check if the wrapper allows for subclasses.
        """
        c = C(1, c=3, b=2)

        deserialized = self._pack_and_unpack(C, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, C)
        self.assertIsInstance(deserialized, A)

    def test_old_subclass(self):
        """
        Check if the wrapper allows for subclasses from old-style Payloads.
        """
        c = NewC(1, c=3, b=2)

        deserialized = self._pack_and_unpack(NewC, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, NewC)
        self.assertIsInstance(deserialized, OldA)

    def test_custom_pack(self):
        """
        Check if the wire-format manipulation rules are applied correctly.
        """
        d = D(0)

        serialized, _ = default_serializer.pack_multiple(d.to_pack_list())
        deserialized = self._pack_and_unpack(D, d)

        self.assertEqual(d.a, 0)
        self.assertEqual(deserialized.a, 0)
        self.assertEqual(serialized, b'\x00\x00\x00\x01')
