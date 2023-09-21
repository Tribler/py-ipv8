"""
Ported from "The Weil Pairing on Elliptic Curves and Its Cryptographic Applications" - Appendix D by Alex Edward Aftuk.
"""
from __future__ import annotations

from typing import Tuple, cast

from .value import FP2Value

# ruff: noqa: N802,N803,N806


def esum(mod: int, p: str | tuple[FP2Value, FP2Value],
         q: str | tuple[FP2Value, FP2Value]) -> str | tuple[FP2Value, FP2Value]:
    """
    Perform Elliptic Curve addition of points P and Q over Fp^2.
    """
    if p == "O" and q == "O":
        return "O"
    if p == "O":
        return q
    if q == "O":
        return p
    x1, y1 = cast(Tuple[FP2Value, FP2Value], p)
    x2, y2 = cast(Tuple[FP2Value, FP2Value], q)
    if x1 == x2 and y1 == FP2Value(mod, -1) * y2:
        return "O"
    if x1 == x2:
        l = ((FP2Value(mod, 3) * x1 * x1) // (FP2Value(mod, 2) * y1)).normalize()
    else:
        l = ((y1 - y2) // (x1 - x2)).normalize()
    x3 = l * l - x1 - x2
    y3 = l * (x3 - x1) + y1
    return x3.normalize(), (FP2Value(mod, -1) * y3).normalize()


def H(mod: int, p: str | tuple[FP2Value, FP2Value], q: str | tuple[FP2Value, FP2Value], x: FP2Value, y: FP2Value) -> FP2Value:
    """
    Perform the h_{T,T} function for the Miller calculation with divisors P and Q for coordinate (x,y).
    """
    x1, y1 = cast(Tuple[FP2Value, FP2Value], p)
    x2, y2 = cast(Tuple[FP2Value, FP2Value], q)
    if x1 == x2 and y1 == FP2Value(mod, -1) * y2:
        return (x - x1).normalize()
    if x1 == x2 and y1 == y2:
        l = (FP2Value(mod, 3) * x1 * x1) // (FP2Value(mod, 2) * y1)
        return ((y - y1 - l * (x - x1)) // (x + (x1 + x2) - l * l)).normalize()
    l = (y2 - y1) // (x2 - x1)
    return ((y - y1 - l * (x - x1)) // (x + (x1 + x2) - l * l)).normalize()


def millercalc(mod: int, M: int, p: tuple[FP2Value, FP2Value], R: tuple[FP2Value, FP2Value]) -> FP2Value:
    """
    Perform the Miller calculation for message M point P and coordinates given by R.
    """
    mlist = list(reversed([int(c) for c in str(bin(M))[2:]]))
    T: str | tuple[FP2Value, FP2Value] = p
    f = FP2Value(mod, 1)
    for i in reversed(list(range(len(mlist) - 1))):
        f = (f * f * H(mod, T, T, R[0], R[1])).normalize()
        T = esum(mod, T, T)
        if mlist[i] == 1:
            f = (f * H(mod, T, p, R[0], R[1])).normalize()
            T = esum(mod, T, p)
    return f


def weilpairing(mod: int, m: int, P: tuple[FP2Value, FP2Value], Q: tuple[FP2Value, FP2Value],
                S: tuple[FP2Value, FP2Value]) -> FP2Value:
    """
    Create a Weil pairing for message m, points P and Q and DH secret S.
    """
    nS = (S[0], FP2Value(mod, -1) * S[1])
    A = millercalc(mod, m, P, cast(Tuple[FP2Value, FP2Value], esum(mod, Q, S)))
    B = millercalc(mod, m, P, S)
    C = millercalc(mod, m, Q, cast(Tuple[FP2Value, FP2Value], esum(mod, P, nS)))
    D = millercalc(mod, m, Q, nS)
    wp = ((A * D) // (B * C))
    return wp.wp_nominator() * wp.wp_denom_inverse()
