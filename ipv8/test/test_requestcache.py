from __future__ import absolute_import

from twisted.trial import unittest
from twisted.internet import reactor
from twisted.internet.task import Clock

from ..requestcache import RandomNumberCache, RequestCache


CACHE_TIMEOUT = 5.0


class MockCache(RandomNumberCache):

    def __init__(self, request_cache):
        super(MockCache, self).__init__(request_cache, u"mock")
        self.timed_out = False

    @property
    def timeout_delay(self):
        return CACHE_TIMEOUT

    def on_timeout(self):
        self.timed_out = True


class TestRequestCache(unittest.TestCase):

    def test_shutdown(self):
        """
        Test if RequestCache does not allow new Caches after shutdown().
        """
        request_cache = RequestCache()
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(reactor.getDelayedCalls()), 1)
        request_cache.shutdown()
        self.assertEqual(len(reactor.getDelayedCalls()), 0)
        request_cache.add(MockCache(request_cache))
        self.assertEqual(len(reactor.getDelayedCalls()), 0)

    def test_timeout(self):
        """
        Test if the cache.on_timeout() is called after the cache.timeout_delay.
        """
        request_cache = RequestCache()
        fake_clock = Clock()
        request_cache._reactor = fake_clock
        cache = MockCache(request_cache)

        request_cache.add(cache)
        fake_clock.advance(CACHE_TIMEOUT + 1.0)

        self.assertTrue(cache.timed_out)

    def test_add_duplicate(self):
        """
        Test if adding a cache twice returns None as the newly added cache.
        """
        request_cache = RequestCache()
        cache = MockCache(request_cache)
        request_cache.add(cache)

        self.assertIsNone(request_cache.add(cache))

        request_cache.shutdown()
