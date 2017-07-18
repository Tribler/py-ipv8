import abc
import logging
from time import time

from keyvault.crypto import ECCrypto
from messaging.interfaces.endpoint import EndpointListener
from messaging.serialization import Serializer
from peer import Peer
from taskmanager import TaskManager


class Overlay(EndpointListener, TaskManager):
    """
    Interface for an Internet overlay.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, master_peer, my_peer, endpoint, database, network):
        """
        Create a new overlay for the Internet.

        :param master_peer: the (public key) peer of the owner of this overlay.
        :param my_peer: the (private key) peer of this peer
        :param endpoint: the endpoint to use for messaging
        :param database: the database to use for storage
        :param network: the network graph backend
        """
        EndpointListener.__init__(self, endpoint, True)
        TaskManager.__init__(self)
        self.serializer = self.get_serializer()
        self.crypto = ECCrypto()

        self.master_peer = master_peer
        self.my_peer = my_peer

        self.endpoint.add_listener(self)

        self.logger = logging.getLogger(self.__class__.__name__)

        self.database = database
        self.network = network

    def unload(self):
        """
        Called when this overlay needs to shut down.
        """
        self.cancel_all_pending_tasks()

    def get_serializer(self):
        """
        Get a Serializer for this Overlay.
        """
        return Serializer()

    def on_packet(self, packet):
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
        """
        source_address, data = packet
        probable_peer = self.network.get_verified_by_address(source_address)
        if probable_peer:
            probable_peer.last_response = time()
        key_bin, data = self.split_key_data(data)
        key = self.crypto.key_from_public_bin(key_bin)
        self.on_data(Peer(key, source_address), data)

    @abc.abstractmethod
    def split_key_data(self, data):
        """
        Split a data string into a key string and remaining data.

        :return: (key_string, other_data)
        """
        pass

    @abc.abstractmethod
    def on_data(self, peer, data):
        """
        Callback for when a binary blob of data is received from a peer.
        """
        pass

    @property
    def global_time(self):
        return self.my_peer.get_lamport_timestamp()

    def claim_global_time(self):
        """
        Increments the current global time by one and returns this value.
        """
        self.update_global_time(self.global_time + 1)
        return self.global_time

    def update_global_time(self, global_time):
        """
        Increase the local global time if the given GLOBAL_TIME is larger.
        """
        if global_time > self.global_time:
            self.my_peer.update_clock(global_time)

    @abc.abstractmethod
    def bootstrap(self):
        """
        Perform introduction logic to get into the network.
        """
        pass

    @abc.abstractmethod
    def walk_to(self, address):
        """
        Puncture the NAT of an address.

        :param address: the address to walk to (ip, port)
        """
        pass

    @abc.abstractmethod
    def get_new_introduction(self, from_peer=None, service_id=None):
        """
        Get a new IP address to walk to from a random, or selected peer.

        :param from_peer: the peer to ask for an introduction
        :param service_id: try to get a new introduction for a certain service
        """
        pass
