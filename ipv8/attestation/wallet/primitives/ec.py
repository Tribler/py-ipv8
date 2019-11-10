"""
Ported from "The Weil Pairing on Elliptic Curves and Its Cryptographic Applications" - Appendix D by Alex Edward Aftuk.
"""
from .value import FP2Value


def esum(mod, p, q):
    """
    Perform Elliptic Curve addition of points P and Q over Fp^2.
    """
    if p == "O" and q == "O":
        return "O"
    if p == "O":
        return q
    if q == "O":
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and y1 == FP2Value(mod, -1) * y2:
        return "O"
    if x1 == x2:
        l = ((FP2Value(mod, 3) * x1 * x1) // (FP2Value(mod, 2) * y1)).normalize()
    else:
        l = ((y1 - y2) // (x1 - x2)).normalize()
    x3 = l * l - x1 - x2
    y3 = l * (x3 - x1) + y1
    return x3.normalize(), (FP2Value(mod, -1) * y3).normalize()


def H(mod, p, q, x, y):
    """
    Perform the h_{T,T} function for the Miller calculation with divisors P and Q for coordinate (x,y).
    """
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and y1 == FP2Value(mod, -1) * y2:
        return (x - x1).normalize()
    if x1 == x2 and y1 == y2:
        l = (FP2Value(mod, 3) * x1 * x1) // (FP2Value(mod, 2) * y1)
        return ((y - y1 - l * (x - x1)) // (x + (x1 + x2) - l * l)).normalize()
    l = (y2 - y1) // (x2 - x1)
    return ((y - y1 - l * (x - x1)) // (x + (x1 + x2) - l * l)).normalize()


def millercalc(mod, M, p, R):
    """
    Perform the Miller calculation for message M point P and coordinates given by R.
    """
    mlist = list(reversed([int(c) for c in str(bin(M))[2:]]))
    T = p
    f = FP2Value(mod, 1)
    for i in reversed(list(range(len(mlist) - 1))):
        f = (f * f * H(mod, T, T, R[0], R[1])).normalize()
        T = esum(mod, T, T)
        if mlist[i] == 1:
            f = (f * H(mod, T, p, R[0], R[1])).normalize()
            T = esum(mod, T, p)
    return f


def weilpairing(mod, m, P, Q, S):
    """
    Create a Weil pairing for message m, points P and Q and DH secret S.
    """
    nS = [S[0], FP2Value(mod, -1) * S[1]]
    A = millercalc(mod, m, P, esum(mod, Q, S))
    B = millercalc(mod, m, P, S)
    C = millercalc(mod, m, Q, esum(mod, P, nS))
    D = millercalc(mod, m, Q, nS)
    wp = ((A * D) // (B * C))
    return wp.wp_nominator() * wp.wp_denom_inverse()
