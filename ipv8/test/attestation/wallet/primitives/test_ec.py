from .....attestation.wallet.primitives.ec import esum, weilpairing
from .....attestation.wallet.primitives.value import FP2Value
from ....base import TestBase


class TestPairing(TestBase):
    """
    Tests related to creating Weil pairings.
    """

    def test_small_weilpairing(self) -> None:
        """
        Check if Weil pairing in E[4] mod 11 of (5, 4) and (5x, 4) with S=(7, 6) equals 9 + 7x.
        """
        mod = 11
        wp = weilpairing(mod,
                         4,
                         (FP2Value(mod, 5), FP2Value(mod, 4)),
                         (FP2Value(mod, b=5), FP2Value(mod, 4)),
                         (FP2Value(mod, 7), FP2Value(mod, 6)))

        self.assertEqual(wp.a, 9)
        self.assertEqual(wp.b, 7)
        self.assertEqual(wp.c, 0)
        self.assertEqual(wp.aC, 1)
        self.assertEqual(wp.bC, 0)
        self.assertEqual(wp.cC, 0)

    def test_medium_weilpairing(self) -> None:
        """
        Check if Weil pairing in E[408] mod 1223 of (764, 140) and (18x, 84) with S=(0, 1222) equals 438 + 50x.
        """
        mod = 1223
        wp = weilpairing(mod,
                         408,
                         (FP2Value(mod, 764), FP2Value(mod, 140)),
                         (FP2Value(mod, b=18), FP2Value(mod, 84)),
                         (FP2Value(mod, 0), FP2Value(mod, 1222)))

        self.assertEqual(wp.a, 438)
        self.assertEqual(wp.b, 50)
        self.assertEqual(wp.c, 0)
        self.assertEqual(wp.aC, 1)
        self.assertEqual(wp.bC, 0)
        self.assertEqual(wp.cC, 0)

    def test_oob_esum(self) -> None:
        """
        Check if EC sum of the point of infinity with itself is the point at infinity.
        """
        self.assertEqual(esum(11, "O", "O"), "O")

    def test_spob_esum(self) -> None:
        """
        Check if EC sum of the point of infinity with another point equals the other point.
        """
        p = (FP2Value(11, 1), FP2Value(11, 2))

        self.assertEqual(esum(11, p, "O"), p)
        self.assertEqual(esum(11, "O", p), p)
