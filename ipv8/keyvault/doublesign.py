"""
ECDSA for Secp256k1.
Includes private key retrieval based on the same r value for two signatures.
Based on gist: https://gist.github.com/nlitsme/dda36eeef541de37d996
"""
import logging
from binascii import unhexlify, hexlify

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

logger = logging.getLogger(__name__)

try:
    from gmpy2 import mpz
    gmpy_present = True
except ImportError:
    gmpy_present = False

def fastint(int_value):
    return mpz(int_value)  if gmpy_present else int_value

def sha256(msg):
    msg_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    msg_hash.update(msg)
    return msg_hash.finalize()


def str_to_int(s):
    """
    Converts hex string to integer.
    """
    # remove all "\x00" prefixes
    while s and s[0] == "\x00":
        s = s[1:]
    # prepend "\x00" when the most significant bit is set
    if ord(s[0]) & 128:
        s = "\x00" + s
    # turn back into int
    return int(hexlify(s), 16)


def int_to_str32(i):
    """
    Converts integer to hex string (32 bytes)
    """
    i = hex(i).rstrip("L").lstrip("0x") or "0"
    # We want bytes: one byte is two nibbles:
    # Prefix with a 0 if the result is of odd length
    if len(i) % 2 == 1:
        i = "0" + i
    # Now we can turn this into a binary string
    i = unhexlify(i)
    key_len = 32
    # For easy decoding, prepend 0 to r and s until they are of >equal length<
    return "".join(("\x00" * (key_len - len(i)), i))


class FieldElement(object):
    """
    Represents an element in the FiniteField
    """

    def __init__(self, field, value):
        super(FieldElement, self).__init__()
        self.field = field
        self.value = field.integer(value)

    # FieldElement * int
    def __add__(self, rhs): return self.field.add(self, self.field.value(rhs))

    def __sub__(self, rhs): return self.field.sub(self, self.field.value(rhs))

    def __mul__(self, rhs): return self.field.mul(self, self.field.value(rhs))

    def __div__(self, rhs): return self.field.div(self, self.field.value(rhs))

    def __pow__(self, rhs): return self.field.pow(self, rhs)

    # int * FieldElement
    def __radd__(self, rhs): return self.field.add(self.field.value(rhs), self)

    def __rsub__(self, rhs): return self.field.sub(self.field.value(rhs), self)

    def __rmul__(self, rhs): return self.field.mul(self.field.value(rhs), self)

    def __rdiv__(self, rhs): return self.field.div(self.field.value(rhs), self)

    def __rpow__(self, rhs): return self.field.pow(self.field.value(rhs), self)

    def __eq__(self, rhs): return self.field.eq(self, self.field.value(rhs))

    def __ne__(self, rhs): return not self == rhs

    def __str__(self): return "0x%x" % self.value

    def __neg__(self): return self.field.neg(self)

    def sqrt(self, flag): return self.field.sqrt(self, flag)

    def inverse(self): return self.field.inverse(self)

    def iszero(self):
        return self.value == 0


class FiniteField(object):
    """
    FiniteField bounded by the given prime number.
    """

    def __init__(self, p):
        super(FiniteField, self).__init__()
        self.p = p

    def add(self, lhs, rhs):
        return self.value((lhs.value + rhs.value) % self.p)

    def sub(self, lhs, rhs):
        return self.value((lhs.value - rhs.value) % self.p)

    def mul(self, lhs, rhs):
        return self.value((lhs.value * rhs.value) % self.p)

    def div(self, lhs, rhs):
        return self.value((lhs.value * rhs.inverse()) % self.p)

    def pow(self, lhs, rhs):
        return self.value(pow(lhs.value, self.integer(rhs), self.p))

    def eq(self, lhs, rhs):
        return (lhs.value - rhs.value) % self.p == 0

    def neg(self, val):
        return self.value(self.p - val.value)

    def sqrt(self, val, flag):
        """
        Calculates the square root modulus p
        """
        if val.iszero():
            return val
        sw = self.p % 8
        if sw == 3 or sw == 7:
            res = val ** ((self.p + 1) / 4)
        elif sw == 5:
            x = val ** ((self.p + 1) / 4)
            if x == 1:
                res = val ** ((self.p + 3) / 8)
            else:
                res = (4 * val) ** ((self.p - 5) / 8) * 2 * val
        else:
            raise Exception("modsqrt non supported for (p%8)==1")
        if res.value % 2 == flag:
            return res
        return -res

    def inverse(self, value):
        """
        Calculates the multiplicative inverse
        """
        return _modinv(value.value, self.p)

    def value(self, x):
        """
        Converts an integer or FinitField.FieldElement to a value of this FiniteField.
        """
        return x if isinstance(x, FieldElement) and x.field == self else FieldElement(self, x)

    def integer(self, x):
        """
        Returns a plain integer
        """
        int_value = x.value if isinstance(x, FieldElement) else x
        return fastint(int_value)

    def zero(self):
        """
        Returns the additive identity value (a + 0 = a)
        """
        return FieldElement(self, 0)

    def one(self):
        """
        Returns the multiplicative identity value (a * 1 = a)
        """
        return FieldElement(self, 1)


class ECPoint(object):
    """
    Represents an affine point in the elliptic curve.
    """

    def __init__(self, curve, x, y):
        super(ECPoint, self).__init__()
        self.curve = curve
        self.x = x
        self.y = y

    # ECPoint + ECPoint
    def __add__(self, rhs): return self.curve.add(self, rhs)

    def __sub__(self, rhs): return self.curve.sub(self, rhs)

    # ECPoint * int   or ECPoint * FieldElement
    def __mul__(self, rhs): return self.curve.mul(self, rhs)

    def __div__(self, rhs): return self.curve.div(self, rhs)

    def __eq__(self, rhs): return self.curve.eq(self, rhs)

    def __ne__(self, rhs): return not self == rhs

    def __str__(self): return "(%s,%s)" % (self.x, self.y)

    def __neg__(self): return self.curve.neg(self)

    def iszero(self):
        return self.x.iszero() and self.y.iszero()

    def isoncurve(self):
        return self.curve.isoncurve(self)


class EllipticCurve(object):
    """
    Elliptic Curve in Montgomery form.
    """

    def __init__(self, field, a, b):
        super(EllipticCurve, self).__init__()
        self.field = field
        self.a = field.value(a)
        self.b = field.value(b)

    def add(self, p, q):
        if p.iszero(): return q
        if q.iszero(): return p

        if p == q:
            if p.y == 0:
                return self.zero()
            l = (3 * p.x ** 2 + self.a) / (2 * p.y)
        elif p.x == q.x:
            return self.zero()
        else:
            l = (p.y - q.y) / (p.x - q.x)

        x = l ** 2 - (p.x + q.x)
        y = l * (p.x - x) - p.y
        return self.point(x, y)

    def sub(self, lhs, rhs):
        return lhs + -rhs

    def mul(self, pt, scalar):
        scalar = self.field.integer(scalar)
        accumulator = self.zero()
        shifter = pt
        while scalar != 0:
            bit = scalar % 2
            if bit:
                accumulator += shifter
            shifter += shifter
            scalar /= 2

        return accumulator

    def div(self, pt, scalar):
        """
        Scalar division:  P / a = P * (1/a)
        scalar is assumed to be of type FiniteField(grouporder)
        """
        return pt * (1 / scalar)

    def eq(self, lhs, rhs):
        return lhs.x == rhs.x and lhs.y == rhs.y

    def neg(self, pt):
        return self.point(pt.x, -pt.y)

    def zero(self):
        """
        Returns the additive identity point ( aka '0' )
        P + 0 = P
        """
        return self.point(self.field.zero(), self.field.zero())

    def point(self, x, y):
        """
        Constructs an affine point from 2 values
        """
        return ECPoint(self, self.field.value(x), self.field.value(y))

    def isoncurve(self, p):
        """
        Verifies if a point is on the curve
        """
        return p.iszero() or p.y ** 2 == p.x ** 3 + self.a * p.x + self.b

    def decompress(self, x, flag):
        """
        Calculates the y coordinate given only the x value.
        There are 2 possible solutions, use 'flag' to select.
        """
        x = self.field.value(x)
        y_square = x ** 3 + self.a * x + self.b

        return self.point(x, y_square.sqrt(flag))


class ECDSA(object):
    """
    Digital Signature Algorithm using Elliptic Curves
    """

    def __init__(self, ec, G, n):
        super(ECDSA, self).__init__()
        self.ec = ec
        self.G = G
        self.GFn = FiniteField(n)

    def pubkey(self, privkey):
        """
        Computes the public key from the given private key
        :param privkey: Integer representation of private key
        :return: Public key point (ECPoint)
        """
        return self.G * self.GFn.value(privkey)

    def sign(self, message, privkey, secret):
        """
        Signs a message with the given private key and sign secret.
        :param message: Message to sign represented as an integer.
        :param privkey: Private key (integer)
        :param secret: Sign secret (integer)
        :return: Signature (r, s) = (G * k, (m+x*r)/k) where k is secret.
        """
        m = self.GFn.value(message)
        x = self.GFn.value(privkey)
        k = self.GFn.value(secret)

        R = self.G * k

        r = self.GFn.value(R.x)
        s = (m + x * r) / k

        return (r, s)

    def verify(self, message, pubkey, rnum, snum):
        """
        Verify the given signature for message with public key.
        :param message: Signed message
        :param pubkey: Verification public key
        :param rnum: r part of signature (integer)
        :param snum: s part of signature (integer)
        :return: True if verification is successful else False
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)

        R = self.G * (m / s) + pubkey * (r / s)

        return R.x == r

    def custom_sign(self, hex_private_key, msg_str, secret_str):
        """
        Signs a message with the given hex private key and signing secret.
        :param hex_private_key: Private key as hex string
        :param msg_str: Message to sign (string)
        :param secret_str: Signing secret (string)
        :return: Signature (string)
        """
        # First hash the message
        msg_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        msg_hash.update(msg_str)
        msg_hash_int = int(msg_hash.finalize().encode('hex'), 16) % self.GFn.p

        # Convert hex private key to integer
        private_key_int = int(hex_private_key, 16)

        # Also, use the hash of the secret string as secret
        secret_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        secret_hash.update(secret_str)
        secret_hash_int = int(secret_hash.finalize().encode('hex'), 16) % self.GFn.p

        # Generate the signature
        (r, s) = self.sign(msg_hash_int, private_key_int, secret_hash_int)

        # Convert the r and s to a valid hex representation
        r_hex = int_to_str32(r.value)
        s_hex = int_to_str32(s.value)

        signature = "".join((r_hex, s_hex))
        return signature

    def custom_verify(self, msg_str, signature_str):
        """
        Verifies the given signature for the message
        :param msg_str: Signed message (string)
        :param signature_str: Message signature (string)
        :return: True if the signature is correct else False
        """
        length = len(signature_str) / 2
        r = str_to_int(signature_str[:length])
        s = str_to_int(signature_str[length:])

        # First hash the message
        msg_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
        msg_hash.update(msg_str)
        msg_hash_int = int(msg_hash.finalize().encode('hex'), 16) % self.GFn.p

        pubkey = self.pubkey_from_signature(msg_hash_int, r, s, 0)
        return self.verify(msg_hash_int, pubkey, r, s)

    def pubkey_from_signature(self, message, rnum, snum, flag):
        """
        Finds the public key from the message and signature.
        There are two valid signatures so use flag to specify which one.
        :param message: Signed message (integer)
        :param rnum: r part of signature
        :param snum: s part of signature
        :param flag: flag
        :return: Public key (ECPoint)
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)

        R = self.ec.decompress(r, flag)

        return R * (s / r) - self.G * (m / r)

    def pubkey_from_signatures(self, r1, s1, r2, s2, flags):
        """
        Finds the public key from two signatures.
        :param r1: r part of signature 1 (integer)
        :param s1: s part of signature 1 (integer)
        :param r2: r part of signature 2 (integer)
        :param s2: s part of signature 2 (integer)
        :param flags: Flags; tuple (flag1:integer, flag2:integer)
        :return: Public key (ECPoint)
        """
        R1 = self.ec.decompress(r1, flags[0])
        R2 = self.ec.decompress(r2, flags[1])

        rdiff = self.GFn.value(r1 - r2)

        return (R1 * s1 - R2 * s2) * (1 / rdiff)

    def recover_from_double_signature(self, r, s1, s2, m1, m2):
        """
        Finds the private key and signing secret from two signatures with same r value of signatures.
        :param r: r part of both signatures (integer)
        :param s1: s part of signature 1 (integer)
        :param s2: s part of signature 2 (integer)
        :param m1: Signed message 1 (integer)
        :param m2: Signed message 2 (integer)
        :return: Returns (signing_secret, private_key); both integer values
        """
        sdelta = self.GFn.value(s1 - s2)
        mdelta = self.GFn.value(m1 - m2)

        secret = mdelta / sdelta
        x1 = self.privatekey_from_signsecret(r, s1, m1, secret)
        x2 = self.privatekey_from_signsecret(r, s2, m2, secret)

        if x1 != x2:
            logger.error("Recovered private keys are not equal (%s=/=%s)", x1, x2)
            return (secret, None)

        return (secret, x1)

    def recover_from_double_signatures(self, msg1_str, msg2_str, signature1_str, signature2_str):
        """
        Recovers private key and signing secret from two messages and two signatures with common secret.
        :param msg1_str: Signed message 1 (string)
        :param msg2_str: Signed message 2 (string)
        :param signature1_str: Signature 1 (string)
        :param signature2_str: Signature 2 (string)
        :return: Returns (signing_secret, private_key); both string values
        """
        if len(signature1_str) != len(signature2_str):
            logger.error("Invalid signatures:\n%s\n%s", signature1_str, signature2_str)
            return (None, None)

        length = len(signature1_str)/2

        r1 = str_to_int(signature1_str[:length])
        s1 = str_to_int(signature1_str[length:])
        r2 = str_to_int(signature2_str[:length])
        s2 = str_to_int(signature2_str[length:])

        if r1 != r2:
            logger.error("Cannot recover private key from signatures, r values are not equal.\n (%s =/= %s)", r1, r2)
            return (None, None)

        int_data1 = int(sha256(msg1_str).encode('hex'), 16)
        int_data2 = int(sha256(msg2_str).encode('hex'), 16)

        (secret, privatekey) = self.recover_from_double_signature(r1, s1, s2, int_data1, int_data2)
        return (int_to_str32(secret.value), int_to_str32(privatekey.value))

    def privatekey_from_signsecret(self, rnum, snum, message, signsecret):
        """
        Finds private key given sign secret, message and signature.
        :param rnum: r part of signature (integer)
        :param snum: s part of signature (integer)
        :param message: Signed message (integer)
        :param signsecret: Signing secret (integer)
        :return: Private key (integer)
        """
        m = self.GFn.value(message)
        r = self.GFn.value(rnum)
        s = self.GFn.value(snum)
        k = self.GFn.value(signsecret)
        return (s * k - m) / r


def SECP256k1():
    """
    Elliptic Curve parameters for Secp256k1 curve.
    """
    GFp = FiniteField(2 ** 256 - 2 ** 32 - 977)
    ec = EllipticCurve(GFp, 0, 7)
    return ECDSA(ec, ec.point(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                              0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
                 2 ** 256 - 432420386565659656852420866394968145599)
