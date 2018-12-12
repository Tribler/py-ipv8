"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

from binascii import hexlify, unhexlify
import logging
import random
import struct
from functools import wraps
from threading import RLock

from ...keyvault.crypto import ECCrypto
from ...community import Community
from .payload import *
from ...peer import Peer

receive_block_lock = RLock()


def synchronized(f):
    """
    Due to database inconsistencies, we can't allow multiple threads to handle a received_half_block at the same time.
    """
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        with receive_block_lock:
            return f(self, *args, **kwargs)
    return wrapper


class BOBChainCommunity(Community):
    """
    Community for reputation based on TrustChain tamper proof interaction history.
    """
    master_peer = Peer(ECCrypto().generate_key(u"medium"))

    # DB_CLASS = TrustChainDB
    # DB_NAME = 'trustchain'
    # version = b'\x02'


