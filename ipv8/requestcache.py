from __future__ import annotations

import abc
import logging
from abc import ABC
from asyncio import CancelledError, Future, gather
from contextlib import contextmanager, suppress
from random import random
from threading import Lock
from typing import Generator, Iterable, TypeVar, overload

from typing_extensions import Protocol

from .taskmanager import TaskManager


class NumberCache:
    """
    A cache for state information that is uniquely identified by a prefix and a number.
    """

    def __init__(self, request_cache: RequestCache, prefix: str, number: int) -> None:
        """
        Create a new cache to be inserted in the given requestcache.
        """
        super().__init__()
        self._logger = logging.getLogger(self.__class__.__name__)

        if request_cache.has(prefix, number):
            raise RuntimeError("This number is already in use '%s'" % number)

        self._prefix = prefix
        self._number = number

        self._managed_futures: list[tuple[Future, object | None]] = []

    def register_future(self, future: Future, on_timeout: object | None = None) -> None:
        """
        Register a future for this Cache that will be canceled when this Cache times out.

        :param future: the future to register for this instance
        :param on_timeout: The value to which the future is to be set when a timeout occurs. If the value is an
                           instance of Exception, future.set_exception will be called instead of future.set_result
        """
        self._managed_futures.append((future, on_timeout))

    @property
    def managed_futures(self) -> list[tuple[Future, object | None]]:
        """
        Get a list of all managed futures.
        """
        return self._managed_futures

    @property
    def prefix(self) -> str:
        """
        Get the prefix of this cache type.
        """
        return self._prefix

    @property
    def number(self) -> int:
        """
        Get the unique number of this cache.
        """
        return self._number

    @property
    def timeout_delay(self) -> float:
        """
        The delay until this cache should be timed out.
        """
        return 10.0

    @abc.abstractmethod
    def on_timeout(self) -> None:
        """
        The logic to call when this cache times out.
        """

    def __str__(self) -> str:
        """
        Convert this cache to a printable string.
        """
        return "<%s %s-%d>" % (self.__class__.__name__, self.prefix, self.number)


class RandomNumberCache(NumberCache):
    """
    A cache with a randomly generated number.
    """

    def __init__(self, request_cache: RequestCache, prefix: str) -> None:
        """
        Create a new cache to be inserted in the given requestcache.
        """
        # find an unclaimed identifier
        number = RandomNumberCache.find_unclaimed_identifier(request_cache, prefix)
        super().__init__(request_cache, prefix, number)

    @classmethod
    def find_unclaimed_identifier(cls: type[RandomNumberCache], request_cache: RequestCache, prefix: str) -> int:
        """
        Generate a random number for use with this cache.
        """
        for _ in range(1000):
            number = int(random() * 2 ** 16)
            if not request_cache.has(prefix, number):
                break
        else:
            msg = "Could not find a number that isn't in use"
            raise RuntimeError(msg)

        return number


class CacheWithName(Protocol):
    """
    All caches with a ``name`` attribute.
    """

    name: str


CacheTypeVar = TypeVar("CacheTypeVar", bound=CacheWithName)
ACT = TypeVar("ACT", bound=NumberCache)


class NumberCacheWithName(NumberCache, CacheWithName, ABC):
    """
    A NumberCache with a ``name`` attribute.
    """


class RandomNumberCacheWithName(RandomNumberCache, CacheWithName, ABC):
    """
    A RandomNumberCache with a ``name`` attribute.
    """


class RequestCache(TaskManager):
    """
    Manager for NumberCache caches.
    """

    def __init__(self) -> None:
        """
        Creates a new RequestCache instance.
        """
        super().__init__()

        self._logger = logging.getLogger(self.__class__.__name__)

        self._identifiers: dict[str, NumberCache] = {}
        self.lock = Lock()
        self._shutdown = False

        self._timeout_override: float | None = None
        """
        If not None, this specifies the timeout to use instead of the one defined in
        the ``timeout_delay`` of a ``NumberCache``.
        This is used internally for ``passthrough()``, don't modify this directly!
        """

        self._timeout_filters: Iterable[type[NumberCache]] | None = None
        """
        If not None, this specifies the ``NumberCache`` (sub)classes to apply the
        timeout override for.
        This is used internally for ``passthrough()``, don't modify this directly!
        """

    def add(self, cache: ACT) -> ACT | None:
        """
        Add CACHE into this RequestCache instance.

        Returns CACHE when CACHE.identifier was not yet added, otherwise returns None.
        """
        assert isinstance(cache, NumberCache), type(cache)
        assert isinstance(cache.number, int), type(cache.number)
        assert isinstance(cache.prefix, str), type(cache.prefix)
        assert isinstance(cache.timeout_delay, (int, float)), type(cache.timeout_delay)
        assert cache.timeout_delay > 0.0, cache.timeout_delay

        with self.lock:
            if self._shutdown:
                self._logger.warning("Dropping %s due to shutdown!", str(cache))
                for f, _ in cache.managed_futures:
                    f.cancel()
                return None

            identifier = self._create_identifier(cache.number, cache.prefix)
            if identifier in self._identifiers:
                self._logger.error("add with duplicate identifier \"%s\"", identifier)
                return None

            self._logger.debug("add %s", cache)
            self._identifiers[identifier] = cache

            timeout_delay = cache.timeout_delay
            if (self._timeout_override is not None
                    and (self._timeout_filters is None
                         or any(issubclass(cache.__class__, f) for f in self._timeout_filters))):
                # Only overwrite the timeout if an overwrite is set.
                # Only overwrite the timeout if no class filters are set.
                # Otherwise, only overwrite the timeout if the cache class is in the filter.
                timeout_delay = self._timeout_override

            self.register_task(cache, self._on_timeout, cache, delay=timeout_delay)
            return cache

    @overload
    def has(self, prefix: str, number: int) -> bool:
        pass

    @overload
    def has(self, prefix: type[CacheTypeVar], number: int) -> bool:
        pass

    def has(self, prefix: str | type[CacheTypeVar], number: int) -> bool:
        """
        Returns True when IDENTIFIER is part of this RequestCache.
        """
        if isinstance(prefix, str):
            return self._create_identifier(number, prefix) in self._identifiers
        return self.has(prefix.name, number)

    @overload
    def get(self, prefix: str, number: int) -> NumberCache | None:
        pass

    @overload
    def get(self, prefix: type[CacheTypeVar], number: int) -> CacheTypeVar | None:
        pass

    def get(self, prefix: str | type[CacheTypeVar], number: int) -> NumberCache | CacheTypeVar | None:
        """
        Returns the Cache associated with IDENTIFIER when it exists, otherwise returns None.
        """
        if isinstance(prefix, str):
            return self._identifiers.get(self._create_identifier(number, prefix))
        return self.get(prefix.name, number)

    @overload
    def pop(self, prefix: str, number: int) -> NumberCache:
        pass

    @overload
    def pop(self, prefix: type[CacheTypeVar], number: int) -> CacheTypeVar:
        pass

    def pop(self, prefix: str | type[CacheTypeVar], number: int) -> NumberCache | CacheTypeVar:
        """
        Returns the Cache associated with IDENTIFIER, and removes it from this RequestCache, when it exists, otherwise
        raises a KeyError exception.
        """
        if isinstance(prefix, str):
            identifier = self._create_identifier(number, prefix)
            cache = self._identifiers.pop(identifier)
            self.cancel_pending_task(cache)
            return cache
        return self.pop(prefix.name, number)

    @contextmanager
    def passthrough(self,
                    cls_filter: type[NumberCache] | None = None, *filters: type[NumberCache],
                    timeout: float = 0.0) -> Generator:
        """
        A contextmanager that overwrites the timeout_delay of added NumberCaches in its scope.
        This can be used to shorten or eliminate timeouts of external code.

        ---
        Example 1: Eliminating timeouts, regardless of ``cache.timeout_delay``
        ---

         .. code-block :: Python

            with request_cache.passthrough():
                request_cache.add(cache)  # This will instantly timeout (once the main thread is yielded).

            with request_cache.passthrough():
                # Any internal call to request_cache.add() will also be instantly timed out.
                await some_function_that_uses_request_cache()

        ---
        Example 2: Modifying timeouts, regardless of ``cache.timeout_delay``
        ---

         .. code-block :: Python

            with request_cache.passthrough(timeout=0.1):
                request_cache.add(cache)  # This will timeout after 0.1 seconds.

        ---
        Example 3: Filtering for specific classes
        ---

         .. code-block :: Python

            # Only MyCacheClass, MyOtherCacheClass, YetAnotherCacheClass will have their timeout changed to 4 seconds.
            with request_cache.passthrough(MyCacheClass, MyOtherCacheClass, YetAnotherCacheClass, timeout=4.0):
                request_cache.add(cache)

        :param cls_filter: An optional class filter to specify which classes the timeout override needs to apply to.
        :param filters: Additional class filters to specify which classes the timeout override needs to apply to.
        :param timeout: The timeout in seconds to use for the ``NumberCache`` instances this applies to.
        :returns: A context manager (compatible with ``with``).
        """
        self._timeout_override = timeout
        self._timeout_filters = None if cls_filter is None else [cls_filter, *list(filters)]
        try:
            yield
        finally:
            self._timeout_override = None
            self._timeout_filters = None

    def _on_timeout(self, cache: NumberCache) -> None:
        """
        Called CACHE.timeout_delay seconds after CACHE was added to this RequestCache.

        _on_timeout is called for every Cache, except when it has been popped before the timeout expires.  When called
        _on_timeout will CACHE.on_timeout().
        """
        self._logger.debug("timeout on %s", cache)

        # the on_timeout call could have already removed the identifier from the cache using pop
        identifier = self._create_identifier(cache.number, cache.prefix)
        if identifier in self._identifiers:
            self._identifiers.pop(identifier)

        cache.on_timeout()

        for future, on_timeout in cache.managed_futures:
            if not future.done():
                if isinstance(on_timeout, Exception):
                    future.set_exception(on_timeout)
                else:
                    future.set_result(on_timeout)

        self.cancel_pending_task(cache)

    def _create_identifier(self, number: int, prefix: str) -> str:
        return f"{prefix}:{number}"

    def clear(self) -> list[Future]:
        """
        Clear the cache, canceling all pending tasks.
        """
        self._logger.debug("Clearing %s [%s]", self, len(self._identifiers))
        tasks = self.cancel_all_pending_tasks()
        self._identifiers.clear()
        return tasks

    async def shutdown(self) -> None:
        """
        Clear the cache, cancel all pending tasks and disallow new caches being added.
        """
        with self.lock:
            # Don't call TaskManager.shutdown_task_manager here since
            # we don't want to await stuff while holding a non-async lock.
            with self._task_lock:
                self._shutdown = True
                tasks = self.cancel_all_pending_tasks()

            for cache in self._identifiers.values():
                # Cancel all managed futures, and suppress the CancelledErrors
                for future, _ in cache.managed_futures:
                    future.cancel()
            self._identifiers.clear()

        if tasks:
            with suppress(CancelledError):
                await gather(*tasks)
