import logging
import sys

from ...requestcache import NumberCache


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
            self.crawl_deferred.callback(self.received_half_blocks)

    def on_timeout(self):
        self._logger.info("Timeout for crawl with id %d", self.number)
        self.community.request_cache.pop(u"crawl", self.number)
        self.crawl_deferred.callback(self.received_half_blocks)
