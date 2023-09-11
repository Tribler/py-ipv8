from .....attestation.wallet.primitives.value import FP2Value
from ....base import TestBase


class TestFP2Value(TestBase):
    """
    Tests related to p^2-Galois field values.
    """

    def test_add_unary(self) -> None:
        """
        Check if 2 + 5 = 7 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)
        b = FP2Value(11, 5)

        self.assertEqual(a + b, FP2Value(11, 7))

    def test_add_unary_mod(self) -> None:
        """
        Check if 5 + 7 = 1 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 5)
        b = FP2Value(11, 7)

        self.assertEqual(a + b, FP2Value(11, 1))

    def test_add_x(self) -> None:
        """
        Check if 2x + 5x = 7x mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=2)
        b = FP2Value(11, b=5)

        self.assertEqual(a + b, FP2Value(11, b=7))

    def test_add_x_mod(self) -> None:
        """
        Check if 5x + 7x = 1x mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=5)
        b = FP2Value(11, b=7)

        self.assertEqual(a + b, FP2Value(11, b=1))

    def test_add_x2_mod(self) -> None:
        """
        Check if x^2 + x^2 = 9x + 9 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, c=1)
        b = FP2Value(11, c=1)

        self.assertEqual(a + b, FP2Value(11, 9, 9))

    def test_add_combined_mod(self) -> None:
        """
        Check if x^2 + 5x + 5 + x^2 + 7x + 7 = 10x + 10 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 5, 5, 1)
        b = FP2Value(11, 7, 7, 1)

        self.assertEqual(a + b, FP2Value(11, 10, 10))

    def test_sub_unary(self) -> None:
        """
        Check if 5 - 2 = 3 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 5)
        b = FP2Value(11, 2)

        self.assertEqual(a - b, FP2Value(11, 3))

    def test_sub_unary_mod(self) -> None:
        """
        Check if 2 - 5 = 8 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)
        b = FP2Value(11, 5)

        self.assertEqual(a - b, FP2Value(11, 8))

    def test_sub_x(self) -> None:
        """
        Check if 5x - 2x = 3x mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=5)
        b = FP2Value(11, b=2)

        self.assertEqual(a - b, FP2Value(11, b=3))

    def test_sub_x_mod(self) -> None:
        """
        Check if 2x + 5x = 8x mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=2)
        b = FP2Value(11, b=5)

        self.assertEqual(a - b, FP2Value(11, b=8))

    def test_sub_x2_mod(self) -> None:
        """
        Check if x^2 - (x^2 + 1) = 10 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, c=1)
        b = FP2Value(11, 1, 0, 1)

        self.assertEqual(a - b, FP2Value(11, 10))

    def test_sub_combined_mod(self) -> None:
        """
        Check if x^2 + 5x + 5 - (x^2 + 7x + 7) = 9x + 9 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 5, 5, 1)
        b = FP2Value(11, 7, 7, 1)

        self.assertEqual(a - b, FP2Value(11, 9, 9))

    def test_mul_unary(self) -> None:
        """
        Check if 2 * 5 = 10 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)
        b = FP2Value(11, 5)

        self.assertEqual(a * b, FP2Value(11, 10))

    def test_mul_unary_mod(self) -> None:
        """
        Check if 3 * 5 = 4 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 3)
        b = FP2Value(11, 5)

        self.assertEqual(a * b, FP2Value(11, 4))

    def test_mul_x(self) -> None:
        """
        Check if 2x * 5x = 10x^2 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=2)
        b = FP2Value(11, b=5)

        self.assertEqual(a * b, FP2Value(11, c=10))

    def test_mul_x_mod(self) -> None:
        """
        Check if 3x * 5x = 4x^2 = 7x + 7 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=3)
        b = FP2Value(11, b=5)

        self.assertEqual(a * b, FP2Value(11, c=4))
        self.assertEqual(a * b, FP2Value(11, 7, 7))

    def test_mul_combined_mod(self) -> None:
        """
        Check if (5) * (x^2 + x + 1) = 5x^2 + 5x + 5 = 0 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 5)
        b = FP2Value(11, 1, 1, 1)

        self.assertEqual(a * b, FP2Value(11, 5, 5, 5))
        self.assertEqual(a * b, FP2Value(11, 0))

    def test_div_unary(self) -> None:
        """
        Check if 9 / 3 = 3 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 9)
        b = FP2Value(11, 3)

        self.assertEqual(a // b, FP2Value(11, 3))

    def test_div_unary_mod(self) -> None:
        """
        Check if 4 / 3  = 5 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 4)
        b = FP2Value(11, 3)

        self.assertEqual((a // b).normalize(), FP2Value(11, 5))

    def test_div_x(self) -> None:
        """
        Check if 9x / 3x = 3 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=9)
        b = FP2Value(11, b=3)

        self.assertEqual((a // b).normalize(), FP2Value(11, 3))

    def test_div_x_mod(self) -> None:
        """
        Check if 4x / 3x = 5 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=4)
        b = FP2Value(11, b=3)

        self.assertEqual((a // b).normalize(), FP2Value(11, 5))

    def test_div_combined_mod(self) -> None:
        """
        Check if (x^2 + 2x + 1) / (x + 1) = x + 1 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 1, 2, 1)
        b = FP2Value(11, 1, 1)

        self.assertEqual((a // b).normalize(), FP2Value(11, 1, 1))

    def test_intpow_unary_p2(self) -> None:
        """
        Check if 2^2 = 4 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)

        self.assertEqual(a.intpow(2), FP2Value(11, 4))

    def test_intpow_unary_p3(self) -> None:
        """
        Check if 2^3 = 8 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)

        self.assertEqual(a.intpow(3), FP2Value(11, 8))

    def test_intpow_unary_p4_mod(self) -> None:
        """
        Check if 2^4 = 5 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2)

        self.assertEqual(a.intpow(4), FP2Value(11, 5))

    def test_intpow_x_p2(self) -> None:
        """
        Check if x^2 = x^2 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, b=1)

        self.assertEqual(a.intpow(2), FP2Value(11, c=1))

    def test_intpow_combined_p2(self) -> None:
        """
        Check if (x + 1)^2 = x^2 + 2x + 1 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 1, 1)

        self.assertEqual(a.intpow(2), FP2Value(11, 1, 2, 1))

    def test_intpow_negative(self) -> None:
        """
        Check if (16)^-2 = 8 mod 23 mod x^2 + x + 1.
        """
        a = FP2Value(23, 16)

        self.assertEqual(a.intpow(-2), FP2Value(23, 8))

    def test_inverse(self) -> None:
        """
        Check if (4/3)^-1 = 3/4 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 4, aC=3)

        self.assertEqual(a.inverse(), FP2Value(11, 3, aC=4))

    def test_inverse_normalized(self) -> None:
        """
        Check if (4/3)^-1 = 9 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 4, aC=3)

        self.assertEqual(a.inverse().normalize(), FP2Value(11, 9))

    def test_wp_compress_simple(self) -> None:
        """
        Check if (2 + 4x)/(1 + 2x) = 2 mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2, 4, aC=1, bC=2)

        self.assertEqual(a.wp_compress(), FP2Value(11, 2))

    def test_wp_compress_complex(self) -> None:
        """
        Check if (2 + 6x)/(1 + 2x) = 7 + 8x mod 11 mod x^2 + x + 1.
        """
        a = FP2Value(11, 2, 6, aC=1, bC=2)

        self.assertEqual(a.wp_compress(), FP2Value(11, 7, 8))

    def test_str_zero(self) -> None:
        """
        Check if (0x^2 + 0x + 0)/(0x^2 + 0x + 1) is formatted as "0".
        """
        self.assertEqual(str(FP2Value(11, 0, 0, 0, 1, 0, 0)), '0')

    def test_str_nozero(self) -> None:
        """
        Check if (0x^2 + x + 0)/(0x^2 + 0x + 1) is formatted as "x".
        """
        self.assertEqual(str(FP2Value(11, 0, 1, 0, 1, 0, 0)), 'x')

    def test_str_nozero_div(self) -> None:
        """
        Check if (0x^2 + x + 0)/(0x^2 + 0x + 2) is formatted as "(x)/(2)".
        """
        self.assertEqual(str(FP2Value(11, 0, 1, 0, 2, 0, 0)), '(x)/(2)')

    def test_str_positive_coefficient(self) -> None:
        """
        Check if (0x^2 + 2x + 0)/(0x^2 + 0x + 1) is formatted as "2x".
        """
        self.assertEqual(str(FP2Value(11, 0, 2, 0, 1, 0, 0)), '2x')

    def test_eq_other(self) -> None:
        """
        Check if an FP2Value doesn't magically equal some unrelated object.
        """
        self.assertFalse(FP2Value(11, 2).__eq__(2))
