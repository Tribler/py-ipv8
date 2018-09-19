from __future__ import absolute_import

import logging
import sys
import traceback

from twisted.internet import reactor, defer
from twisted.python import failure
from twisted.python.threadable import isInIOThread

logger = logging.getLogger(__name__)

if sys.version_info.major > 2:
    from io import StringIO
    import queue as Queue
    from urllib.parse import parse_qsl, ParseResult, unquote, urlencode, urlparse
    grange = range
    is_long_or_int = lambda x: isinstance(x, int)
    is_unicode = lambda x: isinstance(x, str)
    cast_to_long = lambda x: x
    cast_to_unicode = lambda x: str(x)
    maximum_integer = sys.maxsize
else:
    from StringIO import StringIO
    import Queue
    from urllib import unquote, urlencode
    from urlparse import urlparse, parse_qsl, ParseResult
    grange = xrange
    is_long_or_int = lambda x: isinstance(x, (int, long))
    is_unicode = lambda x: isinstance(x, unicode)
    cast_to_long = lambda x: long(x)
    cast_to_unicode = lambda x: unicode(x)
    maximum_integer = sys.maxint
StringIO = StringIO
urllib_future = type("", (), {
    "unquote": unquote,
    "urlencode": urlencode,
    "urlparse": urlparse,
    "parse_qsl": parse_qsl,
    "ParseResult": ParseResult
})


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
        queue = Queue.Queue()

        def _callFromThread():
            result = defer.maybeDeferred(f, *args, **kwargs)
            result.addBoth(queue.put)
        reactor.callFromThread(_callFromThread)
        result = queue.get()
        if isinstance(result, failure.Failure):
            other_thread_tb = traceback.extract_tb(result.getTracebackObject())
            this_thread_tb = traceback.extract_stack()
            logger.error("Exception raised on the reactor's thread %s: \"%s\".\n Traceback from this thread:\n%s\n"
                         " Traceback from the reactor's thread:\n %s", result.type.__name__, result.getErrorMessage(),
                         ''.join(traceback.format_list(this_thread_tb)), ''.join(traceback.format_list(other_thread_tb)))
            result.raiseException()
        return result
