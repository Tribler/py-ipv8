import logging
import sys

from twisted.internet import reactor
from twisted.python.failure import Failure

from ...requestcache import NumberCache


class HalfBlockSignCache(NumberCache):
    """
    This request cache keeps track of outstanding half block signature requests.
    """

    def __init__(self, community, half_block, sign_deferred):
        block_id_int = int(half_block.block_id.encode('hex'), 16) % 100000000L
        super(HalfBlockSignCache, self).__init__(community.request_cache, u"sign", block_id_int)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.community = community
        self.half_block = half_block
        self.sign_deferred = sign_deferred

    @property
    def timeout_delay(self):
        """
        Note that we use a very high timeout for a half block signature. Ideally, we would like to have a request
        cache without any timeouts and just keep track of outstanding signature requests but this isn't possible (yet).
        """
        return 3600.0

    def on_timeout(self):
        self._logger.info("Timeout for sign request for half block %s, note that it can still arrive!", self.half_block)
        self.sign_deferred.errback(Failure(RuntimeError("Signature request timeout")))


class CrawlRequestCache(NumberCache):
    """
    This request cache keeps track of outstanding crawl requests.
    """
    CRAWL_TIMEOUT = 5.0

    def __init__(self, community, crawl_id, crawl_deferred):
        super(CrawlRequestCache, self).__init__(community.request_cache, u"crawl", crawl_id)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.community = community
        self.crawl_deferred = crawl_deferred
        self.received_half_blocks = []
        self.total_half_blocks_expected = sys.maxint

    @property
    def timeout_delay(self):
        return CrawlRequestCache.CRAWL_TIMEOUT

    def received_block(self, block, total_count):
        self.received_half_blocks.append(block)
        self.total_half_blocks_expected = total_count

        if len(self.received_half_blocks) >= self.total_half_blocks_expected:
            self.community.request_cache.pop(u"crawl", self.number)
            reactor.callFromThread(self.crawl_deferred.callback, self.received_half_blocks)

    def on_timeout(self):
        self._logger.info("Timeout for crawl with id %d", self.number)
        self.community.request_cache.pop(u"crawl", self.number)
        self.crawl_deferred.callback(self.received_half_blocks)
