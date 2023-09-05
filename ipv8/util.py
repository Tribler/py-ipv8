from __future__ import annotations

import operator
import signal
import struct
from asyncio import Event, Future, iscoroutine
from typing import Any, Awaitable, Callable, Coroutine, TypeVar

maximum_integer = 2147483647

int2byte = struct.Struct(">B").pack
byte2int = operator.itemgetter(0)

T = TypeVar("T")


def succeed(result: T) -> Future[T]:
    """
    Convert a value to a future with the value set as the result.
    """
    future: Future[T] = Future()
    future.set_result(result)
    return future


def fail(exception: type | BaseException) -> Future:
    """
    Return a future with the given exception set as its exception.
    """
    future: Future = Future()
    future.set_exception(exception)
    return future


def maybe_coroutine(func: Callable, *args: Any, **kwargs) -> Awaitable:  # noqa: ANN401
    """
    Ensure the return value of a callable is awaitable.
    """
    value = func(*args, **kwargs)
    if iscoroutine(value) or isinstance(value, Future):
        return value

    async def coro():  # noqa: ANN202
        return value
    return coro()


def coroutine(func: Callable) -> Callable[[tuple[Any, ...], dict[str, Any]], Coroutine[Any, Any, Awaitable]]:
    """
    Ensure that the given callable is awaitable.
    """
    async def call_async(*args: Any, **kwargs) -> Awaitable:  # noqa: ANN401
        return func(*args, **kwargs)
    return call_async


def strip_sha1_padding(s: bytes) -> bytes:
    """
    Strip the artificial SHA-1 prefix to make it the same byte space as SHA3-256.
    """
    return s[12:] if s.startswith(b'SHA-1\x00\x00\x00\x00\x00\x00\x00') else s


def create_event_with_signals(*args: int) -> Event:
    """
    Creates an event that gets set when certain signals are received. If signals are omitted,
    the signals SIGINT and SIGTERM will be used. If you don't need access to the event itself,
    the use of run_forever is preferred.

    :param args: signals after which the event should be set
    :type args: [int]
    :rtype: asyncio.Event
    """
    event = Event()

    for sig in (args or (signal.SIGINT, signal.SIGTERM)):
        signal.signal(sig, lambda _, __: event.set())

    return event


def run_forever() -> Coroutine:
    """
    Helper function for waiting until the user presses Ctrl+C. Commonly used
    for keeping an application alive until shutdown.

    :rtype: coroutine
    """
    return create_event_with_signals().wait()
