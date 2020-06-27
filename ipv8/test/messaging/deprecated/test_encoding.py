from ...base import TestBase
from ....messaging.deprecated.encoding import decode, encode


class TestEncoding(TestBase):

    def test_encode_int(self):
        """
        Check if an int can be encoded and decoded.
        """
        value = 42

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_float(self):
        """
        Check if an float can be encoded and decoded.
        """
        value = 42.0

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_unicode(self):
        """
        Check if a unicode value can be encoded and decoded.
        """
        value = u"42"

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_bytes(self):
        """
        Check if an int can be encoded and decoded.
        """
        value = b'\x42'

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_list(self):
        """
        Check if a list can be encoded and decoded.
        """
        value = [42, 42.0, u"42", '\x42']

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_set(self):
        """
        Check if a set can be encoded and decoded.
        """
        value = {42, 42.0, u"42", '\x42'}

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_tuple(self):
        """
        Check if a tuple can be encoded and decoded.
        """
        value = (42, 42.0, u"42", '\x42')

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_dict(self):
        """
        Check if a dictionary can be encoded and decoded.
        """
        value = {42: None, 43: 43.0, u"42": b'\x42'}

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_none(self):
        """
        Check if a None can be encoded and decoded.
        """
        value = None

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_bool(self):
        """
        Check if a (true) boolean can be encoded and decoded.
        """
        value = True

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)

    def test_encode_bool_false(self):
        """
        Check if a (false) boolean can be encoded and decoded.
        """
        value = False

        encoded = encode(value)
        _, decoded = decode(encoded)

        self.assertEqual(value, decoded)
