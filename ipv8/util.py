from __future__ import absolute_import

import logging
from asyncio import iscoroutine, Future, coroutine, ensure_future

from six import PY2, PY3, binary_type, text_type

logger = logging.getLogger(__name__)
maximum_integer = 2147483647

try:
    cast_to_long = long  # pylint: disable=long-builtin
    cast_to_unicode = unicode  # pylint: disable=unicode-builtin
except NameError:
    cast_to_long = int
    cast_to_unicode = lambda x: "".join([chr(c) for c in x]) if isinstance(x, bytes) else str(x)

if PY3:
    import math
    cast_to_bin = lambda x: x if isinstance(x, bytes) else bytes([ord(c) for c in x])
    cast_to_chr = lambda x: "".join([chr(c) for c in x])
    old_round = lambda x: float(math.floor((x) + math.copysign(0.5, x)))
else:
    cast_to_bin = str
    cast_to_chr = lambda x: x
    old_round = round


def defaultErrback(failure):
    logger.error("Deferred errback fired: %s", failure)


def addCallback(deferred, callback, errback=defaultErrback):
    """
    This global method can be used to add a callback (and optionally an errback) to a given Deferred object.
    If no errback is provided, it uses the default errback, which simply logs the failure.
    """
    return deferred.addCallbacks(callback, errback)


def ensure_binary(s, encoding='utf-8', errors='strict'):
    """
    Copied from six 1.12 source code! Used as (temporary) workaround so we can still use six 1.11.

    Coerce **s** to six.binary_type.
    For Python 2:
      - `unicode` -> encoded to `str`
      - `str` -> `str`
    For Python 3:
      - `str` -> encoded to `bytes`
      - `bytes` -> `bytes`
    """
    if isinstance(s, text_type):
        return s.encode(encoding, errors)
    elif isinstance(s, binary_type):
        return s
    else:
        raise TypeError("not expecting type '%s'" % type(s))


def ensure_str(s, encoding='utf-8', errors='strict'):
    """
    Copied from six 1.12 source code! Used as (temporary) workaround so we can still use six 1.11.

    Coerce *s* to `str`.
    For Python 2:
      - `unicode` -> encoded to `str`
      - `str` -> `str`
    For Python 3:
      - `str` -> `str`
      - `bytes` -> decoded to `str`
    """
    if not isinstance(s, (text_type, binary_type)):
        raise TypeError("not expecting type '%s'" % type(s))
    if PY2 and isinstance(s, text_type):
        s = s.encode(encoding, errors)
    elif PY3 and isinstance(s, binary_type):
        s = s.decode(encoding, errors)
    return s


def ensure_text(s, encoding='utf-8', errors='strict'):
    """
    Copied from six 1.12 source code! Used as (temporary) workaround so we can still use six 1.11.

    Coerce *s* to six.text_type.
    For Python 2:
      - `unicode` -> `unicode`
      - `str` -> `unicode`
    For Python 3:
      - `str` -> `str`
      - `bytes` -> decoded to `str`
    """
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    elif isinstance(s, text_type):
        return s
    else:
        raise TypeError("not expecting type '%s'" % type(s))


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


def call_later(delay, func, *args, **kwargs):
    if not iscoroutine(func):
        func = coroutine(func)

    from ipv8.taskmanager import delay_runner
    return ensure_future(delay_runner(delay, func, *args, **kwargs))
