from __future__ import absolute_import

from pyipv8.ipv8.attestation.trustchain.block import TrustChainBlock
from ...messaging.serialization import default_serializer

GENESIS_HASH = b'0' * 32  # ID of the first block of the chain.
GENESIS_SEQ = 1
UNKNOWN_SEQ = 0
EMPTY_SIG = b'0' * 64
EMPTY_PK = b'0' * 74
ANY_COUNTERPARTY_PK = EMPTY_PK


class BobChainBlock(TrustChainBlock):
    """
    Container for TrustChain block information
    """

    def __init__(self, data=None, serializer=default_serializer):
        super(BobChainBlock, self).__init__(data, serializer)
