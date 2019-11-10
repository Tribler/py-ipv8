from asyncio import Future, all_tasks

import asynctest

from ..requestcache import RandomNumberCache, RequestCache

CACHE_TIMEOUT = 0.1


class MockCache(RandomNumberCache):

    def __init__(self, request_cache):
        super(MockCache, self).__init__(request_cache, u"mock")
        self.timed_out = Future()

    @property
    def timeout_delay(self):
        return CACHE_TIMEOUT

    def on_timeout(self):
        self.timed_out.set_result(None)


class TestRequestCache(asynctest.TestCase):

    async def test_shutdown(self):
        """
        Test if RequestCache does not allow new Caches after shutdown().
        """
        num_tasks = len(all_tasks())
        request_cache = RequestCache()
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(all_tasks()), num_tasks + 1)
        await request_cache.shutdown()
        self.assertEqual(len(all_tasks()), num_tasks)
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(all_tasks()), num_tasks)

    async def test_timeout(self):
        """
        Test if the cache.on_timeout() is called after the cache.timeout_delay.
        """
        request_cache = RequestCache()
        cache = MockCache(request_cache)
        request_cache.add(cache)
        await cache.timed_out

    async def test_add_duplicate(self):
        """
        Test if adding a cache twice returns None as the newly added cache.
        """
        request_cache = RequestCache()
        cache = MockCache(request_cache)
        request_cache.add(cache)

        self.assertIsNone(request_cache.add(cache))

        await request_cache.shutdown()
