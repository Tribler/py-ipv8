from asyncio import Future, all_tasks, sleep

from ..requestcache import NumberCache, RandomNumberCache, RandomNumberCacheWithName, RequestCache
from .base import TestBase

CACHE_TIMEOUT = 0.01


class MockCache(RandomNumberCache):
    """
    A cache that stores a future.
    """

    def __init__(self, request_cache: RequestCache) -> None:
        """
        Create a new cache and set up the ``timed_out`` future.
        """
        super().__init__(request_cache, "mock")
        self.timed_out = Future()

    @property
    def timeout_delay(self) -> float:
        """
        Adopt the global cache timeout value.
        """
        return CACHE_TIMEOUT

    def on_timeout(self) -> None:
        """
        When actually timed out, set the result of our future to ``None``.
        """
        self.timed_out.set_result(None)


class MockRegisteredCache(RandomNumberCache):
    """
    A cache that stores a future and registers it.
    """

    def __init__(self, request_cache: RequestCache) -> None:
        """
        Create a ``timed_out`` futre and register it.
        """
        super().__init__(request_cache, "mock")
        self.timed_out = Future()
        self.register_future(self.timed_out)

    @property
    def timeout_delay(self) -> float:
        """
        Adopt the global cache timeout value.
        """
        return CACHE_TIMEOUT

    def on_timeout(self) -> None:
        """
        Don't do anything on timeout.
        """


class MockInfiniteCache(RandomNumberCache):
    """
    Create a cache that has near-infinite timeout delay.
    """

    def __init__(self, request_cache: RequestCache) -> None:
        """
        Create a flag that sets this cache to be timed out.
        """
        super().__init__(request_cache, "mock")
        self.timed_out = False

    @property
    def timeout_delay(self) -> float:
        """
        Set the timeout delay to be huge.
        """
        return 8589934592

    def on_timeout(self) -> None:
        """
        Flag the ``timed_out`` value as timed out.
        """
        self.timed_out = True


class MockNamedCache(RandomNumberCacheWithName):
    """
    A cache with a name.
    """

    name = "my-cache-name"

    def __init__(self, request_cache: RequestCache) -> None:
        """
        A typical named cache initializer.
        """
        super().__init__(request_cache, self.name)

    def on_timeout(self) -> None:
        """
        We do nothing.
        """


class TestRequestCache(TestBase):
    """
    Tests related to the request cache.
    """

    def setUp(self) -> None:
        """
        Create a new request cache, without registered caches.
        """
        super().setUp()
        self.request_cache = RequestCache()

    async def test_shutdown(self) -> None:
        """
        Test if RequestCache does not allow new Caches after shutdown().
        """
        num_tasks = len(all_tasks())  # [Background tasks (depends on test runner) + RequestCache]
        self.request_cache.add(MockCache(self.request_cache))
        self.assertEqual(len(all_tasks()), num_tasks + 1)  # [Background + RequestCache + Cache]
        await self.request_cache.shutdown()
        self.assertEqual(len(all_tasks()), num_tasks - 1)  # [Background]
        self.request_cache.add(MockCache(self.request_cache))  # No tasks should have been added
        self.assertEqual(len(all_tasks()), num_tasks - 1)  # [Background]

    async def test_timeout(self) -> None:
        """
        Test if the cache.on_timeout() is called after the cache.timeout_delay.
        """
        cache = MockCache(self.request_cache)
        self.request_cache.add(cache)
        await cache.timed_out
        await self.request_cache.shutdown()

    async def test_add_duplicate(self) -> None:
        """
        Test if adding a cache twice returns None as the newly added cache.
        """
        cache = MockCache(self.request_cache)
        self.request_cache.add(cache)

        self.assertIsNone(self.request_cache.add(cache))

        await self.request_cache.shutdown()

    async def test_timeout_future_default_value(self) -> None:
        """
        Test if a registered future gets set to None on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        self.assertEqual(None, (await cache.timed_out))
        await self.request_cache.shutdown()

    async def test_timeout_future_custom_value(self) -> None:
        """
        Test if a registered future gets set to a value on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)

        cache.managed_futures[0] = (cache.managed_futures[0][0], 123)
        self.assertEqual(123, (await cache.timed_out))

        await self.request_cache.shutdown()

    async def test_timeout_future_exception(self) -> None:
        """
        Test if a registered future raises an exception on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)

        cache.managed_futures[0] = (cache.managed_futures[0][0], RuntimeError())
        with self.assertRaises(RuntimeError):
            await cache.timed_out

        await self.request_cache.shutdown()

    async def test_cancel_future_after_shutdown(self) -> None:
        """
        Test if a registered future is cancelled when the RequestCache has shutdown.
        """
        await self.request_cache.shutdown()
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        assert cache.managed_futures[0][0].done()

    async def test_cancel_future(self) -> None:
        """
        Test if a registered future gets canceled at shutdown.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        await self.request_cache.shutdown()
        self.assertTrue(cache.timed_out.cancelled())

    async def test_passthrough_noargs(self) -> None:
        """
        Test if passthrough without arguments immediately times a cache out.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough():
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_timeout(self) -> None:
        """
        Test if passthrough respects the timeout value.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(timeout=10.0):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_filter_one_match(self) -> None:
        """
        Test if passthrough filters correctly with one filter, that matches.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockInfiniteCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_filter_one_mismatch(self) -> None:
        """
        Test if passthrough filters correctly with one filter, that doesn't match.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_filter_many_match(self) -> None:
        """
        Test if passthrough filters correctly with many filters, that all match.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockInfiniteCache, RandomNumberCache, NumberCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_filter_some_match(self) -> None:
        """
        Test if passthrough filters correctly with many filters, for which some match.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache, MockCache, RandomNumberCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_passthrough_filter_no_match(self) -> None:
        """
        Test if passthrough filters correctly with many filters, for which none match.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache, MockCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)

        await self.request_cache.shutdown()

    async def test_has_by_class(self) -> None:
        """
        Check if we can call ``.has()`` by cache class.
        """
        cache = MockNamedCache(self.request_cache)

        added = self.request_cache.add(cache)

        self.assertTrue(self.request_cache.has(MockNamedCache, added.number))

        await self.request_cache.shutdown()

    async def test_get_by_class(self) -> None:
        """
        Check if we can call ``.get()`` by cache class.
        """
        cache = MockNamedCache(self.request_cache)
        added = self.request_cache.add(cache)

        self.assertEqual(added, self.request_cache.get(MockNamedCache, added.number))

        await self.request_cache.shutdown()

    async def test_pop_by_class(self) -> None:
        """
        Check if we can call ``.pop()`` by cache class.
        """
        cache = MockNamedCache(self.request_cache)
        added = self.request_cache.add(cache)

        self.assertEqual(added, self.request_cache.pop(MockNamedCache, added.number))

        await self.request_cache.shutdown()
