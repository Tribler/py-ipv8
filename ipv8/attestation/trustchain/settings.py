class TrustChainSettings(object):
    """
    This class holds various settings regarding TrustChain.
    """

    def __init__(self):
        # The set with block types that should not be broadcast
        self.block_types_bc_disabled = set()

        # The fan-out of the broadcast when a new block is created
        self.broadcast_fanout = 25

        # The amount of history to keep for broadcasts
        self.broadcast_history_size = 100000

        # How many prior blocks we require before signing a new incoming block
        self.validation_range = 5

        # The maximum number of blocks we want to store in the database
        self.max_db_blocks = 1000000

        # Whether we are a crawler (and fetching whole chains)
        self.crawler = False

        # How many blocks at most we allow others to crawl in one batch
        self.max_crawl_batch = 10

        # The delay in seconds after which we send a half block to the counterparty again
        self.sign_attempt_delay = 10

        # The timeout after which we stop trying to get the half block signed by the counterparty
        self.sign_timeout = 360
