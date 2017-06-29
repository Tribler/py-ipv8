from time import time

from keyvault.keys import Key


class Peer(object):

    def __init__(self, key, address=("0.0.0.0", 0), intro=True):
        """
        Create a new Peer.

        :param key: the peer's key (mostly public)
        :param address: the (IP, port) tuple of this peer
        :param intro: is this peer suggested to us (otherwise it contacted us)
        """
        assert isinstance(key, Key)

        self.key = key
        self.address = address
        self.last_response = 0 if intro else time()
        self._lamport_timestamp = 0

    def update_clock(self, timestamp):
        """
        Update the Lamport timestamp for this peer. The Lamport clock dictates that the current timestamp is
        the maximum of the last known and the most recently delivered timestamp. This is useful when messages
        are delivered asynchronously.

        We also keep a real time timestamp of the last received message for timeout purposes.

        :param timestamp: a received timestamp
        """
        self._lamport_timestamp = max(self._lamport_timestamp, timestamp)
        self.last_response = time() # This is in seconds since the epoch

    def get_lamport_timestamp(self):
        return self._lamport_timestamp

    def should_drop(self):
        """
        Have we passed the time before we consider this peer to be unreachable.
        """
        return time() > self.last_response + 57.5

    def is_inactive(self):
        """
        Have we passed the time before we consider this peer to be inactive.
        """
        return time() > self.last_response + 27.5
