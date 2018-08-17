from nose.twistedtools import deferred
from twisted.internet.defer import inlineCallbacks


class TimeExpired(AssertionError):
    pass


def make_decorator(func):
    """
    Wraps a test decorator so as to properly replicate metadata
    of the decorated function, including nose's additional stuff
    (namely, setup and teardown).
    """

    def decorate(newfunc):
        if hasattr(func, 'compat_func_name'):
            name = func.compat_func_name
        else:
            name = func.__name__
        newfunc.__dict__ = func.__dict__
        newfunc.__doc__ = func.__doc__
        newfunc.__module__ = func.__module__
        if not hasattr(newfunc, 'compat_co_firstlineno'):
            newfunc.compat_co_firstlineno = func.func_code.co_firstlineno
        try:
            newfunc.__name__ = name
        except TypeError:
            # can't set func name in 2.3
            newfunc.compat_func_name = name
        return newfunc

    return decorate


def twisted_wrapper(arg):
    """
    Wrap a twisted test. Optionally supply a test timeout.

    Note that arg might either be a func or the timeout.
    """
    if isinstance(arg, (int, long)):
        return lambda x: deferred(arg)(inlineCallbacks(x))
    return deferred(timeout=1)(inlineCallbacks(arg))
