"""
The TrustChain Community is the first step in an incremental approach in building a new reputation system.
This reputation system builds a tamper proof interaction history contained in a chain data-structure.
Every node has a chain and these chains intertwine by blocks shared by chains.
"""
from __future__ import absolute_import

from datetime import datetime
from functools import wraps
from threading import RLock

from twisted.internet.task import LoopingCall

from pyipv8 import gui_holder
from pyipv8.ipv8.attestation.bobchain.block import BobChainBlock
from pyipv8.ipv8.attestation.trustchain.block import ANY_COUNTERPARTY_PK, ValidationResult
from pyipv8.ipv8.attestation.trustchain.community import TrustChainCommunity

receive_block_lock = RLock()

# Static block_type, using home_property instead of property to not use the same name as a property type in python
BLOCK_TYPE = b'HOME_PROPERTY'


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
            print "I am: ", self.my_peer, ". Number of peers found: ", len(self.get_peers()), "\nI know: ", [str(p) for p in self.get_peers()]

        # This function will remove all the created blocks in the bobchain community
        def remove_all_created_blocks():
            print "Going to remove all blocks"

            blocks = self.persistence.get_blocks_with_type(BLOCK_TYPE)
            print "Number of blocks found: ", len(blocks)

            for block in blocks:
                self.persistence.remove_block(block)
            blocks = self.persistence.get_blocks_with_type(BLOCK_TYPE)

            if len(blocks) == 0:
                print "All blocks have succesfully been removed"
            else:
                print "Not all blocks have been removed, number of blocks remaining: ", len(blocks)

        def print_blocks():
            transaction = {'Adres': 'Home',
                           'house number': 1}

            self.create_source_block(BLOCK_TYPE, transaction)

            blocks = self.persistence.get_blocks_with_type(BLOCK_TYPE)

            print "I am: ", self.my_peer

            print "Number of blocks found after creating one: ", len(blocks)

        def wrapper_create_and_remove_blocks():
            for i in range(0,5):
                print_blocks()

            remove_all_created_blocks()

        # We register a Twisted task with this overlay.
        # This makes sure that the task ends when this overlay is unloaded.
        # We call the 'print_peers' function every 5.0 seconds, starting now.
        # self.register_task("print_peers", LoopingCall(print_peers)).start(5.0, True)
        self.register_task("print_blocks", LoopingCall(print_blocks)).start(5.0, True)

        # name = input("Whats your name?")
        # print name

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

    def create_source_block(self, block_type=b'unknown', transaction=None):
        """
        Create a source block without any initial counterparty to sign.

        :param block_type: The type of the block to be constructed, as a string
        :param transaction: A string describing the interaction in this block
        :return: A deferred that fires with a (block, None) tuple
        """

        return self.sign_block(peer=None, public_key=ANY_COUNTERPARTY_PK,
                               block_type=block_type, transaction=transaction)

    def validate_persist_block(self, block):
        """
        Validate a block and if it's valid, persist it. Return the validation result.
        :param block: The block to validate and persist.
        :return: [ValidationResult]
        """
        validation = block.validate(self.persistence)
        if validation[0] == ValidationResult.invalid:
            pass
        elif not self.persistence.contains(block):
            self.persistence.add_block(block)
            self.notify_listeners(block)

        return validation
        # self.persistence.execute("INSERT INTO option(key, value) VALUES('database_version', '0')")
        # self.persistence.commit()
        #
        # window = tk.Toplevel(gui_holder.root)
        # window.geometry("500x500")
        # frame = tk.Frame(window)
        # frame.pack()
        #
        # button = tk.Button(frame,
        #                    text="Book apartment",
        #                    command=book_apartment)
        # button.pack()
