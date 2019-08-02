from __future__ import absolute_import

import logging
import traceback

from six import PY2, PY3, binary_type, text_type
from six.moves.queue import Queue

from twisted.internet import defer, reactor
from twisted.python.failure import Failure
from twisted.python.threadable import isInIOThread

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


def blocking_call_on_reactor_thread(func):
    def helper(*args, **kargs):
        return blockingCallFromThread(reactor, func, *args, **kargs)
    helper.__name__ = func.__name__
    return helper


def blockingCallFromThread(reactor, f, *args, **kwargs):
    """
    Improved version of twisted's blockingCallFromThread that shows the complete
    stacktrace when an exception is raised on the reactor's thread.
    If being called from the reactor thread already, just return the result of execution of the callable.
    """
    if isInIOThread():
        return f(*args, **kwargs)
    else:
        queue = Queue()

        def _callFromThread():
            result = defer.maybeDeferred(f, *args, **kwargs)
            result.addBoth(queue.put)
        reactor.callFromThread(_callFromThread)
        result = queue.get()
        if isinstance(result, Failure):
            other_thread_tb = traceback.extract_tb(result.getTracebackObject())
            this_thread_tb = traceback.extract_stack()
            logger.error("Exception raised on the reactor's thread %s: \"%s\".\n Traceback from this thread:\n%s\n"
                         " Traceback from the reactor's thread:\n %s", result.type.__name__, result.getErrorMessage(),
                         ''.join(traceback.format_list(this_thread_tb)), ''.join(traceback.format_list(other_thread_tb)))
            result.raiseException()
        return result


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
