class BobChainSettings(object):
    """
    This class holds various settings regarding TrustChain.
    """

    def __init__(self):
        # Whether we should broadcast newly created blocks to others
        self.broadcast_blocks = True

        # The fan-out of the broadcast when a new block is created
        self.broadcast_fanout = 25

        # How many prior blocks we require before signing a new incoming block
        self.validation_range = 5

        # The maximum number of blocks we want to store in the database
        self.max_db_blocks = 1000000

        # Whether we are a crawler (and fetching whole chains)
        self.crawler = False
