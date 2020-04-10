from enum import Enum


class SecurityMode(Enum):
    """
    Implementations of security implementations of Trustchain.
    """
    VANILLA = 1
    AUDIT = 2


class NoodleSettings(object):
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

        # Is the node hiding own blocks?
        self.is_hiding = False

        # TTL for informed information dissemination, depends on the topology
        self.ttl = 3

        # Use informed broadcast
        self.use_informed_broadcast = False

        # Ignore validation errors
        self.ignore_validation = False

        # Sync round time in seconds
        self.sync_time = 1

        # Security mode
        self.security_mode = SecurityMode.AUDIT

        # Security epsilon
        self.com_size = 2

        # Tolerated inconsistency risk
        self.risk = 0

        # Initial minting value
        self.initial_mint_value = 100000

        # Interval for making random transfers
        self.transfer_interval = 1

        # Minter identities that we accept (if this is an empty set, everyone is an minter)
        self.minters = []

        # Crawling identities
        self.crawlers = [
            b"4c69624e61434c504b3a60001170dcec5f4774e3ea8d5d6b89c98e5b18f10adb3e02b27137d965f1e4188d872bf6a30b6516b98fdb9839f2920ccf42a30a723ab07de7011bbbb245b20b",
            b"4c69624e61434c504b3ad87cdb35fb1025904627aa84483a19e5640a1bebb2f6081e87cd635d22bbbe7cc8467a252d9f5343e10e182939225fea982192396837e9fb4d81fb4f26b74af3"]

        # Cache timeouts (in seconds)
        self.audit_request_timeout = 0.9
        self.audit_proof_request_timeout = 2.0
        self.ping_timeout = 5.0
        self.half_block_timeout = 5.0
        self.half_block_timeout_retries = 6

        # Maximum number of peers in each SubTrust community
        self.max_peers_subtrust = 30

        # Queue interval times (in ms)
        self.transfer_queue_interval = 2
        self.block_queue_interval = 2
        self.audit_response_queue_interval = 2
