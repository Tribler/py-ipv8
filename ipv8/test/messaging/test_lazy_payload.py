from sys import version_info
from unittest import skipIf

from ..base import TestBase
from ...messaging.lazy_payload import VariablePayload, vp_compile
from ...messaging.payload import Payload
from ...messaging.serialization import default_serializer


skipUnlessPython310 = skipIf(version_info[0] < 4 and not (version_info[0] == 3 and version_info[1] >= 10),
                             reason="Test only available for Python 3.10 and later.")


class A(VariablePayload):
    """
    A basic VariablePayload.
    """
    format_list = ['I', 'H']
    names = ["a", "b"]


@vp_compile
class CompiledA(A):
    pass


class BitsPayload(VariablePayload):
    """
    An unbalanced VariablePayload.
    """
    format_list = ['bits']
    names = ['flag0', 'flag1', 'flag2', 'flag3', 'flag4', 'flag5', 'flag6', 'flag7']


@vp_compile
class CompiledBitsPayload(BitsPayload):
    pass


class B(VariablePayload):
    """
    A VariablePayload with a nested Payload.
    """
    format_list = [A]
    names = ["a"]


@vp_compile
class CompiledB(B):
    pass


@vp_compile
class CompiledBAlt(B):
    format_list = [CompiledA]


class C(A):
    """
    A VariablePayload with inherited fields.
    """
    format_list = A.format_list + ['B']
    names = A.names + ['c']


@vp_compile
class CompiledC(C):
    pass


@vp_compile
class CompiledCAlt(CompiledA):
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
        return OldA(*args)  # pylint: disable=E1120


class D(VariablePayload):
    format_list = ["I"]
    names = ["a"]

    def fix_pack_a(self, value):
        return value + 1

    @classmethod
    def fix_unpack_a(cls, value):
        return value - 1


@vp_compile
class CompiledD(D):
    pass


class NewC(VariablePayload, OldA):
    """
    A VariablePayload with inherited fields.
    """
    format_list = OldA.format_list + ['B']
    names = ['a', 'b', 'c']


@vp_compile
class CompiledNewC(NewC):
    pass


class E(VariablePayload):
    """
    A VariablePayload with a list of payloads.
    """
    format_list = [[A]]
    names = ["list_of_A"]


class TestVariablePayload(TestBase):

    def _pack_and_unpack(self, payload, instance):
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
        a = A(42, 1337)

        deserialized = self._pack_and_unpack(A, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(a.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_base_unnamed_compiled(self):
        """
        Check if the wrapper returns the payload correctly with unnamed arguments, compiled.
        """
        a = CompiledA(42, 1337)

        deserialized = self._pack_and_unpack(CompiledA, a)

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

    def test_base_named_compiled(self):
        """
        Check if the wrapper returns the payload correctly with named arguments, compiled.
        """
        a = CompiledA(b=1337, a=42)

        deserialized = self._pack_and_unpack(CompiledA, a)

        self.assertEqual(a.a, 42)
        self.assertEqual(a.b, 1337)
        self.assertEqual(deserialized.a, 42)
        self.assertEqual(deserialized.b, 1337)

    def test_bits_payload(self):
        """
        Check if unpacked BitPayload works correctly.
        """
        bpl = BitsPayload(False, True, False, True, False, True, False, True)

        deserialized = self._pack_and_unpack(BitsPayload, bpl)

        self.assertEqual(deserialized.flag0, False)
        self.assertEqual(deserialized.flag1, True)
        self.assertEqual(deserialized.flag2, False)
        self.assertEqual(deserialized.flag3, True)
        self.assertEqual(deserialized.flag4, False)
        self.assertEqual(deserialized.flag5, True)
        self.assertEqual(deserialized.flag6, False)
        self.assertEqual(deserialized.flag7, True)

    def test_bits_payload_compiled(self):
        """
        Check if unpacked compiled BitPayload works correctly.
        """
        bpl = CompiledBitsPayload(False, True, False, True, False, True, False, True)

        deserialized = self._pack_and_unpack(BitsPayload, bpl)

        self.assertEqual(deserialized.flag0, False)
        self.assertEqual(deserialized.flag1, True)
        self.assertEqual(deserialized.flag2, False)
        self.assertEqual(deserialized.flag3, True)
        self.assertEqual(deserialized.flag4, False)
        self.assertEqual(deserialized.flag5, True)
        self.assertEqual(deserialized.flag6, False)
        self.assertEqual(deserialized.flag7, True)

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

    def test_inheritance_uncompiled_compiled(self):
        """
        Check if the wrapper allows for nested payloads, compiled.
        """
        a = CompiledA(1, 2)
        b = CompiledB(a)

        deserialized = self._pack_and_unpack(CompiledB, b)

        self.assertEqual(b.a.a, deserialized.a.a)
        self.assertEqual(b.a.b, deserialized.a.b)
        self.assertIsInstance(deserialized, CompiledB)
        self.assertIsInstance(deserialized.a, A)

    def test_inheritance_compiled_compiled(self):
        """
        Check if the wrapper allows for compiled nested payloads, compiled.
        """
        a = CompiledA(1, 2)
        b = CompiledBAlt(a)

        deserialized = self._pack_and_unpack(CompiledBAlt, b)

        self.assertEqual(b.a.a, deserialized.a.a)
        self.assertEqual(b.a.b, deserialized.a.b)
        self.assertIsInstance(deserialized, CompiledBAlt)
        self.assertIsInstance(deserialized.a, CompiledA)

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

    def test_subclass_uncompiled_compiled(self):
        """
        Check if the wrapper allows for subclasses, compiled.
        """
        c = CompiledC(1, c=3, b=2)

        deserialized = self._pack_and_unpack(CompiledC, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, CompiledC)
        self.assertIsInstance(deserialized, A)

    def test_subclass_compiled_compiled(self):
        """
        Check if the wrapper allows for compiled subclasses, compiled.
        """
        c = CompiledCAlt(1, c=3, b=2)

        deserialized = self._pack_and_unpack(CompiledCAlt, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, CompiledCAlt)
        self.assertIsInstance(deserialized, CompiledA)

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

    def test_old_subclass_compiled(self):
        """
        Check if the wrapper allows for subclasses from old-style Payloads, compiled.
        """
        c = CompiledNewC(1, c=3, b=2)

        deserialized = self._pack_and_unpack(CompiledNewC, c)

        self.assertEqual(c.a, deserialized.a)
        self.assertEqual(c.b, deserialized.b)
        self.assertEqual(c.c, deserialized.c)
        self.assertIsInstance(deserialized, CompiledNewC)
        self.assertIsInstance(deserialized, OldA)

    def test_custom_pack(self):
        """
        Check if the wire-format manipulation rules are applied correctly.
        """
        d = D(0)

        serialized = default_serializer.pack_serializable(d)
        deserialized = self._pack_and_unpack(D, d)

        self.assertEqual(d.a, 0)
        self.assertEqual(deserialized.a, 0)
        self.assertEqual(serialized, b'\x00\x00\x00\x01')

    def test_custom_pack_compiled(self):
        """
        Check if the wire-format manipulation rules are applied correctly, compiled.
        """
        d = CompiledD(0)

        serialized = default_serializer.pack_serializable(d)
        deserialized = self._pack_and_unpack(CompiledD, d)

        self.assertEqual(d.a, 0)
        self.assertEqual(deserialized.a, 0)
        self.assertEqual(serialized, b'\x00\x00\x00\x01')

    def test_payload_list(self):
        """
        Check if unpacked payload lists works correctly.
        """
        e = E([A(1, 2), A(3, 4)])

        deserialized = self._pack_and_unpack(E, e)

        self.assertEqual(e.list_of_A[0].a, deserialized.list_of_A[0].a)
        self.assertEqual(e.list_of_A[0].b, deserialized.list_of_A[0].b)
        self.assertEqual(e.list_of_A[1].a, deserialized.list_of_A[1].a)
        self.assertEqual(e.list_of_A[1].b, deserialized.list_of_A[1].b)

    @skipUnlessPython310
    def test_plain_mismatch_list(self):
        """
        Check if a VariablePayload instance does not match anything but its own pattern.

        We intentionally check here for a list of values equal to the __init__ arguments, which is the default.
        If this test fails, you probably screwed up the class-level sub-pattern.
        """
        # pylint: disable=W0122, W0641
        payload = BitsPayload(False, True, False, True, False, True, False, True)

        # The following will crash all interpreters < 3.10 if not contained in a string.
        exec(compile('''
match payload:
    case [False, True, False, True, False, True, False, True]:
        matched = True
    case _:
        matched = False
''', '<string>', 'exec'), globals(), locals())

        self.assertFalse(locals()["matched"])

    @skipUnlessPython310
    def test_compiled_mismatch_list(self):
        """
        Check if a compiled VariablePayload instance does not match anything but its own pattern.

        We intentionally check here for a list of values equal to the __init__ arguments, which is the default.
        If this test fails, you probably screwed up the class-level sub-pattern.
        """
        # pylint: disable=W0122, W0641
        payload = CompiledBitsPayload(False, True, False, True, False, True, False, True)

        # The following will crash all interpreters < 3.10 if not contained in a string.
        exec(compile('''
match payload:
    case [False, True, False, True, False, True, False, True]:
        matched = True
    case _:
        matched = False
''', '<string>', 'exec'), globals(), locals())

        self.assertFalse(locals()["matched"])

    @skipUnlessPython310
    def test_plain_match_pattern(self):
        """
        Check if a VariablePayload instance matches its own pattern.
        """
        # pylint: disable=W0122, W0641
        payload = BitsPayload(False, True, False, True, False, True, False, True)

        # The following will crash all interpreters < 3.10 if not contained in a string.
        exec(compile('''
match payload:
    case BitsPayload(False, True, False, True, False, True, False, True):
        matched = True
    case _:
        matched = False
''', '<string>', 'exec'), globals(), locals())

        self.assertTrue(locals()["matched"])

    @skipUnlessPython310
    def test_compiled_match_pattern(self):
        """
        Check if a compiled VariablePayload instance matches its own pattern.
        """
        # pylint: disable=W0122, W0641
        payload = CompiledBitsPayload(False, True, False, True, False, True, False, True)

        # The following will crash all interpreters < 3.10 if not contained in a string.
        exec(compile('''
match payload:
    case CompiledBitsPayload(False, True, False, True, False, True, False, True):
        matched = True
    case _:
        matched = False
''', '<string>', 'exec'), globals(), locals())

        self.assertTrue(locals()["matched"])
