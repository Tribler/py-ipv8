from __future__ import absolute_import

from binascii import hexlify
from functools import reduce
import logging

from twisted.internet import reactor
from twisted.python.failure import Failure

from ...requestcache import NumberCache
from ...util import maximum_integer


class IntroCrawlTimeout(NumberCache):
    """
    A crawl request is sent with every introduction response. This can happen quite a lot of times per second.
    We wish to slow down the amount of crawls we do to not overload any node with database IO.
    """

    def __init__(self, community, peer):
        super(IntroCrawlTimeout, self).__init__(community.request_cache, u"introcrawltimeout",
                                                self.get_number_for(peer))

    @classmethod
    def get_number_for(cls, peer):
        """
        Convert a Peer into an int. To do this we shift every byte of the mid into an integer.
        """
        return reduce(lambda a, b: ((a << 8) | b), [ord(c) for c in peer.mid], 0)

    @property
    def timeout_delay(self):
        """
        We crawl the same peer, at most once every 60 seconds.
        :return:
        """
        return 60.0

    def on_timeout(self):
        """
        This is expected, the super class will now remove itself from the request cache.
        The node is then allowed to be crawled again.
        """
        pass


class HalfBlockSignCache(NumberCache):
    """
    This request cache keeps track of outstanding half block signature requests.
    """

    def __init__(self, community, half_block, sign_deferred):
        block_id_int = int(hexlify(half_block.block_id), 16) % 100000000
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
    CRAWL_TIMEOUT = 20.0

    def __init__(self, community, crawl_id, crawl_deferred):
        super(CrawlRequestCache, self).__init__(community.request_cache, u"crawl", crawl_id)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.community = community
        self.crawl_deferred = crawl_deferred
        self.received_half_blocks = []
        self.total_half_blocks_expected = maximum_integer

    @property
    def timeout_delay(self):
        return CrawlRequestCache.CRAWL_TIMEOUT

    def received_block(self, block, total_count):
        self.received_half_blocks.append(block)
        self.total_half_blocks_expected = total_count

        if self.total_half_blocks_expected == 0:
            self.community.request_cache.pop(u"crawl", self.number)
            reactor.callFromThread(self.crawl_deferred.callback, [])
        elif len(self.received_half_blocks) >= self.total_half_blocks_expected:
            self.community.request_cache.pop(u"crawl", self.number)
            reactor.callFromThread(self.crawl_deferred.callback, self.received_half_blocks)

    def received_empty_response(self):
        self.community.request_cache.pop(u"crawl", self.number)
        reactor.callFromThread(self.crawl_deferred.callback, self.received_half_blocks)

    def on_timeout(self):
        self._logger.info("Timeout for crawl with id %d", self.number)
        self.crawl_deferred.callback(self.received_half_blocks)
