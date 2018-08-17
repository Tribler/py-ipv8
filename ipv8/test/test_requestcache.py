import unittest

from twisted.internet import reactor

from ..requestcache import RandomNumberCache, RequestCache


class MockCache(RandomNumberCache):

    def __init__(self, request_cache):
        super(MockCache, self).__init__(request_cache, "mock")

    def on_timeout(self):
        pass


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
