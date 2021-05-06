from asyncio import Future, all_tasks, sleep

from .base import TestBase
from ..requestcache import NumberCache, RandomNumberCache, RequestCache

CACHE_TIMEOUT = 0.01


class MockCache(RandomNumberCache):

    def __init__(self, request_cache):
        super(MockCache, self).__init__(request_cache, u"mock")
        self.timed_out = Future()

    @property
    def timeout_delay(self):
        return CACHE_TIMEOUT

    def on_timeout(self):
        self.timed_out.set_result(None)


class MockRegisteredCache(RandomNumberCache):

    def __init__(self, request_cache):
        super(MockRegisteredCache, self).__init__(request_cache, u"mock")
        self.timed_out = Future()
        self.register_future(self.timed_out)

    @property
    def timeout_delay(self):
        return CACHE_TIMEOUT

    def on_timeout(self):
        pass


class MockInfiniteCache(RandomNumberCache):

    def __init__(self, request_cache):
        super().__init__(request_cache, u"mock")
        self.timed_out = False

    @property
    def timeout_delay(self):
        return 8589934592

    def on_timeout(self):
        self.timed_out = True


class TestRequestCache(TestBase):

    def setUp(self):
        super().setUp()
        self.request_cache = RequestCache()

    async def test_shutdown(self):
        """
        Test if RequestCache does not allow new Caches after shutdown().
        """
        num_tasks = len(all_tasks())
        request_cache = RequestCache()  # This adds a task, don't use ``self.request_cache`` here!
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(all_tasks()), num_tasks + 2)
        await request_cache.shutdown()
        self.assertEqual(len(all_tasks()), num_tasks)
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(all_tasks()), num_tasks)

    async def test_timeout(self):
        """
        Test if the cache.on_timeout() is called after the cache.timeout_delay.
        """
        cache = MockCache(self.request_cache)
        self.request_cache.add(cache)
        await cache.timed_out

    async def test_add_duplicate(self):
        """
        Test if adding a cache twice returns None as the newly added cache.
        """
        cache = MockCache(self.request_cache)
        self.request_cache.add(cache)

        self.assertIsNone(self.request_cache.add(cache))

        await self.request_cache.shutdown()

    async def test_timeout_future_default_value(self):
        """
        Test if a registered future gets set to None on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        self.assertEqual(None, (await cache.timed_out))
        await self.request_cache.shutdown()

    async def test_timeout_future_custom_value(self):
        """
        Test if a registered future gets set to a value on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)

        cache.managed_futures[0] = (cache.managed_futures[0][0], 123)
        self.assertEqual(123, (await cache.timed_out))

        await self.request_cache.shutdown()

    async def test_timeout_future_exception(self):
        """
        Test if a registered future raises an exception on timeout.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)

        cache.managed_futures[0] = (cache.managed_futures[0][0], RuntimeError())
        with self.assertRaises(RuntimeError):
            await cache.timed_out

        await self.request_cache.shutdown()

    async def test_cancel_future_after_shutdown(self):
        """
        Test if a registered future is cancelled when the RequestCache has shutdown.
        """
        await self.request_cache.shutdown()
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        assert cache.managed_futures[0][0].done()

    async def test_cancel_future(self):
        """
        Test if a registered future gets canceled at shutdown.
        """
        cache = MockRegisteredCache(self.request_cache)
        self.request_cache.add(cache)
        await self.request_cache.shutdown()
        self.assertTrue(cache.timed_out.cancelled())

    async def test_passthrough_noargs(self):
        """
        Test if passthrough without arguments immediately times a cache out.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough():
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

    async def test_passthrough_timeout(self):
        """
        Test if passthrough respects the timeout value.
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(timeout=10.0):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)

    async def test_passthrough_filter_one_match(self):
        """
        Test if passthrough filters correctly with one filter, that matches
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockInfiniteCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

    async def test_passthrough_filter_one_mismatch(self):
        """
        Test if passthrough filters correctly with one filter, that doesn't match
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)

    async def test_passthrough_filter_many_match(self):
        """
        Test if passthrough filters correctly with many filters, that all match
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockInfiniteCache, RandomNumberCache, NumberCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

    async def test_passthrough_filter_some_match(self):
        """
        Test if passthrough filters correctly with many filters, for which some match
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache, MockCache, RandomNumberCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertTrue(cache.timed_out)

    async def test_passthrough_filter_no_match(self):
        """
        Test if passthrough filters correctly with many filters, for which none match
        """
        cache = MockInfiniteCache(self.request_cache)

        with self.request_cache.passthrough(MockRegisteredCache, MockCache):
            self.request_cache.add(cache)
            await sleep(0.0)

        self.assertFalse(cache.timed_out)
