import logging
import math
import operator
import struct
from asyncio import Future, iscoroutine

logger = logging.getLogger(__name__)
maximum_integer = 2147483647

int2byte = struct.Struct(">B").pack
byte2int = operator.itemgetter(0)
cast_to_unicode = lambda x: "".join([chr(c) for c in x]) if isinstance(x, bytes) else str(x)
cast_to_bin = lambda x: x if isinstance(x, bytes) else bytes([ord(c) for c in x])
cast_to_chr = lambda x: "".join([chr(c) for c in x])
old_round = lambda x: float(math.floor((x) + math.copysign(0.5, x)))


def succeed(result):
    future = Future()
    future.set_result(result)
    return future


def fail(exception):
    future = Future()
    future.set_exception(exception)
    return future


def maybe_coroutine(func, *args, **kwargs):
    value = func(*args, **kwargs)
    if iscoroutine(value) or isinstance(value, Future):
        return value

    async def coro():
        return value
    return coro()
