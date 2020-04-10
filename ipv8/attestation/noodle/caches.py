import logging
from asyncio import get_event_loop
from binascii import hexlify
from functools import reduce

from ...requestcache import NumberCache
from ...util import maximum_integer


class IntroCrawlTimeout(NumberCache):
    """
    A crawl request is sent with every introduction response. This can happen quite a lot of times per second.
    We wish to slow down the amount of crawls we do to not overload any node with database IO.
    """

    def __init__(self, community, peer, identifier=u"introcrawltimeout"):
        super(IntroCrawlTimeout, self).__init__(community.request_cache, identifier,
                                                self.get_number_for(peer))

    @classmethod
    def get_number_for(cls, peer):
        """
        Convert a Peer into an int. To do this we shift every byte of the mid into an integer.
        """
        charlist = []
        for i in range(len(peer.mid)):
            charlist.append(ord(peer.mid[i:i + 1]))
        return reduce(lambda a, b: ((a << 8) | b), charlist, 0)

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


class ChainCrawlCache(IntroCrawlTimeout):
    """
    This cache keeps track of the crawl of a whole chain.
    """
    def __init__(self, community, peer, crawl_future, known_chain_length=-1):
        super(ChainCrawlCache, self).__init__(community, peer, identifier=u"chaincrawl")
        self.community = community
        self.current_crawl_future = None
        self.crawl_future = crawl_future
        self.peer = peer
        self.known_chain_length = known_chain_length

        self.current_request_range = (0, 0)
        self.current_request_attempts = 0

    @property
    def timeout_delay(self):
        return 120.0


class HalfBlockSignCache(NumberCache):
    """
    This request cache keeps track of outstanding half block signature requests.
    """

    def __init__(self, community, half_block, sign_future, socket_address, timeouts=0):
        """
        A cache to keep track of the signing of one of our blocks by a counterparty.

        :param community: the TrustChainCommunity
        :param half_block: the half_block requiring a counterparty
        :param sign_future: the Deferred to fire once this block has been double signed
        :param socket_address: the peer we sent the block to
        :param timeouts: the number of timeouts we have already had while waiting
        """
        block_id_int = int(hexlify(half_block.block_id), 16) % 100000000
        super(HalfBlockSignCache, self).__init__(community.request_cache, u"sign", block_id_int)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.community = community
        self.half_block = half_block
        self.sign_future = sign_future
        self.socket_address = socket_address
        self.timeouts = timeouts

    @property
    def timeout_delay(self):
        """
        Note that we use a very high timeout for a half block signature. Ideally, we would like to have a request
        cache without any timeouts and just keep track of outstanding signature requests but this isn't possible (yet).
        """
        return 10.0

    def on_timeout(self):
        if self.sign_future.done():
            self._logger.debug("Race condition encountered with timeout/removal of HalfBlockSignCache, recovering.")
            return
        self._logger.info("Timeout for sign request for half block %s, note that it can still arrive!", self.half_block)
        if self.timeouts < 360:
            self.community.send_block(self.half_block, address=self.socket_address)

            async def add_later():
                self.community.request_cache.add(HalfBlockSignCache(self.community, self.half_block, self.sign_future,
                                                                    self.socket_address, self.timeouts + 1))
            self.community.request_cache.register_anonymous_task("add-later", add_later, delay=0.0)
        else:
            self.sign_future.set_exception(RuntimeError("Signature request timeout"))


class CrawlRequestCache(NumberCache):
    """
    This request cache keeps track of outstanding crawl requests.
    """
    CRAWL_TIMEOUT = 20.0

    def __init__(self, community, crawl_id, crawl_future):
        super(CrawlRequestCache, self).__init__(community.request_cache, u"crawl", crawl_id)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.community = community
        self.crawl_future = crawl_future
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
            get_event_loop().call_soon_threadsafe(self.crawl_future.set_result, [])
        elif len(self.received_half_blocks) >= self.total_half_blocks_expected:
            self.community.request_cache.pop(u"crawl", self.number)
            get_event_loop().call_soon_threadsafe(self.crawl_future.set_result, self.received_half_blocks)

    def received_empty_response(self):
        self.community.request_cache.pop(u"crawl", self.number)
        get_event_loop().call_soon_threadsafe(self.crawl_future.set_result, self.received_half_blocks)

    def on_timeout(self):
        self._logger.info("Timeout for crawl with id %d", self.number)
        self.crawl_future.set_result(self.received_half_blocks)
