from __future__ import absolute_import

from unittest import TestCase

from ...messaging.lazy_payload import ezpayload
from ...messaging.payload import Payload
from ...messaging.serialization import default_serializer


@ezpayload
def A(a='I', b='H'):  # pylint: disable=W0613
    """
    :type a: int
    :type b: int
    """
    return A


@ezpayload
def B(a=A):  # pylint: disable=W0613
    """
    :type a: A
    """
    return B


@ezpayload(A)
def C(c='B'):  # pylint: disable=W0613
    """
    :type c: int
    """
    return C


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
        return OldA(*args)  # pylint: disable=E1120


@ezpayload(OldA)
def NewC(c='B'):  # pylint: disable=W0613
    """
    :type c: int
    """
    return NewC


class TestEZPayload(TestCase):

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
        c = C(1, c=3, b=2)  # pylint: disable=E1123,E1124

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
        c = NewC(1, c=3, b=2)  # pylint: disable=E1123,E1124

        deserialized = self._pack_and_unpack(NewC, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, NewC)
        self.assertIsInstance(deserialized, OldA)
