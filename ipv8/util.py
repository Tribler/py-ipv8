from __future__ import absolute_import

import logging
import sys
import traceback

from six.moves.queue import Queue
from twisted.internet import reactor, defer
from twisted.python.failure import Failure
from twisted.python.threadable import isInIOThread

logger = logging.getLogger(__name__)

if sys.version_info.major > 2:
    import math
    cast_to_long = lambda x: x
    cast_to_unicode = lambda x: "".join([chr(c) for c in x]) if isinstance(x, bytes) else str(x)
    cast_to_bin = lambda x: x if isinstance(x, bytes) else bytes([ord(c) for c in x])
    cast_to_chr = lambda x: "".join([chr(c) for c in x])
    maximum_integer = sys.maxsize
    old_round = lambda x: float(math.floor((x) + math.copysign(0.5, x)))
else:
    cast_to_long = lambda x: long(x)
    cast_to_unicode = lambda x: unicode(x)
    cast_to_bin = str
    cast_to_chr = lambda x: x
    maximum_integer = sys.maxint
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
