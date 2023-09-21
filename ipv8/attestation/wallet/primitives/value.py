from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.rsa import _modinv

# ruff: noqa: N803,N806


def format_polynomial(a: int, b: int, c: int) -> str:
    """
    Formats a polynomial cx^2 + bx + a into non-zero/non-one form.

    Ex. '0x^2 + 1x + 2' becomes 'x + 2'

    :param a: x^0 coefficient
    :param b: x^1 coefficient
    :param c: x^2 coefficient
    :returns: pretty format of polynomial
    """
    out = ''
    for (v, s) in [(a, ''), (b, 'x'), (c, 'x^2')]:
        if v:
            fmt_v = '' if abs(v) == 1 and s != '' else str(abs(v))
            out += (' + ' if out else '') + fmt_v + s
    if not out:
        out = '0'
    return out


class FP2Value:
    """
    Defines a rational value (a + bx + cx^2)/(aC + bCx + cCx^2)(mod 1 + x + x^2, mod p).
    """

    def __init__(self, mod: int, a: int = 0, b: int = 0, c: int = 0,  # noqa: PLR0913
                 aC: int = 1, bC: int = 0, cC: int = 0) -> None:
        """
        Intialize a value mod 'mod' of two quadratic polynomials divided by each other modulo (x^2 + x + 1).

        :param mod: the modulus
        :param a: the coefficient of 1
        :param b: the coefficient of x
        :param c: the coefficient of x^2
        :param aC: (the coefficient of 1) ^ -1
        :param bC: (the coefficient of x) ^ -1
        :param cC: (the coefficient of x) ^ -2
        """
        self.mod = mod
        self.a, self.b, self.c, self.aC, self.bC, self.cC = a % mod, b % mod, c % mod, aC % mod, bC % mod, cC % mod

    def __str__(self) -> str:
        """
        Format this value as a string.
        """
        numerator = format_polynomial(self.a, self.b, self.c)
        denominator = format_polynomial(self.aC, self.bC, self.cC)
        if denominator == '1':
            return numerator
        return f"({numerator})/({denominator})"

    def __add__(self, other: FP2Value) -> FP2Value:
        """
        Add this value to another value and return a new FP2Value.
        """
        assert self.mod == other.mod

        a = (self.aC * other.a - self.cC * other.a + self.a * other.aC - self.c * other.aC - self.bC * other.b
             + self.cC * other.b - self.aC * other.c + self.bC * other.c - self.a * other.cC + self.b * other.cC)
        b = (self.bC * other.a - self.cC * other.a + self.b * other.aC - self.c * other.aC + self.aC * other.b
             - self.bC * other.b + self.a * other.bC - self.b * other.bC - self.aC * other.c + self.cC * other.c
             - self.a * other.cC + self.c * other.cC)
        aC = (self.aC * other.aC - self.cC * other.aC - self.bC * other.bC
              + self.cC * other.bC - self.aC * other.cC + self.bC * other.cC)
        bC = (self.bC * other.aC - self.cC * other.aC + self.aC * other.bC
              - self.bC * other.bC - self.aC * other.cC + self.cC * other.cC)
        return FP2Value(self.mod, a=a, b=b, aC=aC, bC=bC)

    def __sub__(self, other: FP2Value) -> FP2Value:
        """
        Subtract another value from this value and return a new FP2Value.
        """
        assert self.mod == other.mod
        a = (-self.aC * other.a + self.cC * other.a + self.a * other.aC - self.c * other.aC + self.bC * other.b
             - self.cC * other.b - self.b * other.bC + self.c * other.bC + self.aC * other.c - self.bC * other.c
             - self.a * other.cC + self.b * other.cC)
        b = (-self.bC * other.a + self.cC * other.a + self.b * other.aC - self.c * other.aC - self.aC * other.b
             + self.bC * other.b + self.a * other.bC - self.b * other.bC + self.aC * other.c - self.cC * other.c
             - self.a * other.cC + self.c * other.cC)
        aC = (self.aC * other.aC - self.cC * other.aC - self.bC * other.bC
              + self.cC * other.bC - self.aC * other.cC + self.bC * other.cC)
        bC = (self.bC * other.aC - self.cC * other.aC + self.aC * other.bC
              - self.bC * other.bC - self.aC * other.cC + self.cC * other.cC)
        return FP2Value(self.mod, a=a, b=b, aC=aC, bC=bC)

    def __mul__(self, other: FP2Value) -> FP2Value:
        """
        Multiply this value with another value and return a new FP2Value.
        """
        assert self.mod == other.mod
        a = (self.a * other.a - self.c * other.a - self.b * other.b
             + self.c * other.b - self.a * other.c + self.b * other.c)
        b = (self.b * other.a - self.c * other.a + self.a * other.b
             - self.b * other.b - self.a * other.c + self.c * other.c)
        aC = (self.aC * other.aC - self.cC * other.aC - self.bC * other.bC
              + self.cC * other.bC - self.aC * other.cC + self.bC * other.cC)
        bC = (self.bC * other.aC - self.cC * other.aC + self.aC * other.bC
              - self.bC * other.bC - self.aC * other.cC + self.cC * other.cC)
        return FP2Value(self.mod, a=a, b=b, aC=aC, bC=bC)

    def __floordiv__(self, other: FP2Value) -> FP2Value:
        """
        Divide this value by another value and return a new FP2Value.
        """
        assert self.mod == other.mod
        a = (self.a * other.aC - self.c * other.aC - self.b * other.bC
             + self.c * other.bC - self.a * other.cC + self.b * other.cC)
        b = (self.b * other.aC - self.c * other.aC + self.a * other.bC
             - self.b * other.bC - self.a * other.cC + self.c * other.cC)
        aC = (self.aC * other.a - self.cC * other.a - self.bC * other.b
              + self.cC * other.b - self.aC * other.c + self.bC * other.c)
        bC = (self.bC * other.a - self.cC * other.a + self.aC * other.b
              - self.bC * other.b - self.aC * other.c + self.cC * other.c)
        return FP2Value(self.mod, a=a, b=b, aC=aC, bC=bC)

    def __eq__(self, other: object) -> bool:
        """
        Check equality with another value.
        """
        if not isinstance(other, FP2Value):
            return False
        divd = (self // other).normalize()
        return all([divd.a == divd.aC, divd.b == divd.bC, divd.c == divd.cC])

    def __hash__(self) -> int:
        """
        Equality is not trivial. We hash everything to 0 for the full equality check.
        """
        return 0

    def intpow(self, power: int) -> FP2Value:
        """
        Raise this value by a given power (int).

        :param power: the power to raise this value by
        :type power: int
        """
        n = -power if power < 0 else power
        R = FP2Value(self.mod, 1)
        U = self
        while n > 0:
            if (n % 2) == 1:
                R *= U
            U *= U
            n = n // 2
        return R.inverse().normalize() if power < 0 else R

    def normalize(self) -> FP2Value:
        """
        Normalize to aC = 1: this is the best human-readable form.

        Ex. '20/4' becomes '5'
            '4 + 4x/2 + 2x' becomes '2 + 2x/1 + x'
        """
        mp = _modinv(self.aC % self.mod, self.mod)
        if mp > 0:
            a = (self.a * mp) % self.mod
            b = (self.b * mp) % self.mod
            c = (self.c * mp) % self.mod
            aC = 1
            bC = (self.bC * mp) % self.mod
            cC = (self.cC * mp) % self.mod
            return FP2Value(self.mod, a, b, c, aC, bC, cC)
        return FP2Value(self.mod, self.a, self.b, self.c, self.aC, self.bC, self.cC)

    def inverse(self) -> FP2Value:
        """
        Return the inverse of this value.
        """
        return FP2Value(self.mod, a=self.aC, b=self.bC, c=self.cC, aC=self.a, bC=self.b, cC=self.c)

    def wp_nominator(self) -> FP2Value:
        """
        Return the '1' and 'x' coefficients as a new value.
        """
        return FP2Value(self.mod, self.a, self.b)

    def wp_denom_inverse(self) -> FP2Value:
        """
        Return the '1^-1' and 'x^-1' coefficients modular inverse.
        """
        iq = FP2Value(self.mod, self.aC * self.aC - self.aC * self.bC + self.bC * self.bC)
        a = FP2Value(self.mod, self.aC - self.bC) // iq
        b = FP2Value(self.mod, -self.bC) // iq
        return FP2Value(self.mod, a.normalize().a, b.normalize().a)

    def wp_compress(self) -> FP2Value:
        """
        Compress this FP2 value into an FP2Value only containing `a` and `b` values.

        This is an expensive operation.
        """
        assert self.c == 0
        assert self.cC == 0
        normalized = self.normalize()
        return normalized.wp_nominator() * normalized.wp_denom_inverse()
