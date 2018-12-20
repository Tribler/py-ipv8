"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

from datetime import datetime
from functools import wraps
from threading import RLock

import tkinter as tk
from twisted.internet.task import LoopingCall

from pyipv8 import gui_holder
from pyipv8.ipv8.attestation.bobchain.block import BobChainBlock
from pyipv8.ipv8.attestation.trustchain.block import ANY_COUNTERPARTY_PK
from pyipv8.ipv8.attestation.trustchain.community import TrustChainCommunity

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


class BOBChainCommunity(TrustChainCommunity):
    def _init__(self, *args, **kwargs):
        super(BOBChainCommunity, self).__init__(*args, **kwargs)

    def started(self):
        def print_peers():
            print "I am: ", self.my_peer, "\nI know: ", [str(p) for p in self.get_peers()]

        def book_apartment():
            blocks = self.persistence.get_blocks_with_type("property")
            for block in blocks:
                start_day = block.transaction["start_day"].split("-")
                end_day = block.transaction["end_day"].split("-")
                start_day_tuple = (int(start_day[0]), int(start_day[1]), int(start_day[2]))
                end_day_tuple = (int(end_day[0]), int(end_day[1]), int(end_day[2]))
                current_day = datetime.now()
                current_day_tuple = (current_day.year, current_day.month, current_day.day)
                if start_day_tuple <= current_day_tuple <= end_day_tuple:
                    print "Overbooking!"
                    return
            self.sign_block(
                block_type=b"property",
                transaction=
                {
                    b"property_id": 42,
                    b"start_day": datetime.now().strftime("%Y-%m-%d"),  # 2000-01-31
                    b"end_day": "2999-01-01",
                },
                public_key=ANY_COUNTERPARTY_PK,
                peer=None
            )
            print "Booked apartment"



        # We register a Twisted task with this overlay.
        # This makes sure that the task ends when this overlay is unloaded.
        # We call the 'print_peers' function every 5.0 seconds, starting now.
        self.register_task("print_peers", LoopingCall(print_peers)).start(5.0, True)

        # self.persistence.execute("INSERT INTO option(key, value) VALUES('database_version', '0')")
        # self.persistence.commit()

        window = tk.Toplevel(gui_holder.root)
        window.geometry("500x500")
        frame = tk.Frame(window)
        frame.pack()

        button = tk.Button(frame,
                           text="Book apartment",
                           command=book_apartment)
        button.pack()
