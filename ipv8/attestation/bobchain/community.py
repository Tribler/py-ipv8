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
from twisted.internet import reactor
from twisted.internet.task import LoopingCall

from pyipv8 import gui_holder
from pyipv8.ipv8.attestation.bobchain.block import BobChainBlock
from pyipv8.ipv8.attestation.trustchain.community import TrustChainCommunity
from pyipv8.ipv8.attestation.trustchain.database import TrustChainDB
from ...keyvault.crypto import ECCrypto
from ...community import Community
from ...peer import Peer
import tkinter as tk

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

    def __init__(self, *args, **kwargs):
        working_directory = kwargs.pop('working_directory', '')
        super(BOBChainCommunity, self).__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.relayed_broadcasts = []
        self.logger.debug("The trustchain community started with Public Key: %s",
                          hexlify(self.my_peer.public_key.key_to_bin()))
        self.shutting_down = False
        self.listeners_map = {}  # Map of block_type -> [callbacks]

    def started(self):
        def print_peers():
            print "I am:", self.my_peer, "\nI know:", [str(p) for p in self.get_peers()]

        def book_apartment():
            BobChainBlock.create(b'test', {b'id': 42}, self.persistence, self.my_peer.public_key.key_to_bin(), link=None)
            print "Booked apartment"

        # We register a Twisted task with this overlay.
        # This makes sure that the task ends when this overlay is unloaded.
        # We call the 'print_peers' function every 5.0 seconds, starting now.
        self.register_task("print_peers", LoopingCall(print_peers)).start(5.0, True)
        window = tk.Toplevel(gui_holder.root)
        window.geometry("500x500")
        frame = tk.Frame(window)
        frame.pack()

        button = tk.Button(frame,
                           text="Book apartment",
                           command=book_apartment)
        button.pack()
