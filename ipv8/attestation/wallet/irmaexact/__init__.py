from __future__ import division

import os
from functools import reduce


def secure_randint(bitspace):
    delbits = 8 - (bitspace % 8)
    bytez = [(b if isinstance(b, int) else ord(b)) for b in os.urandom(bitspace // 8 + (0 if bitspace % 8 == 0 else 1))]
    if delbits > 0:
        bytez[0] &= (0xFF >> delbits)
    return reduce(lambda a, b: (a << 8) + b, bytez, 0)
