import abc
import logging
from time import time

from .keyvault.crypto import ECCrypto
from .messaging.interfaces.endpoint import EndpointListener
from .messaging.serialization import Serializer
from .peer import Peer
from .taskmanager import TaskManager


class Overlay(EndpointListener, TaskManager):
    """
    Interface for an Internet overlay.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, master_peer, my_peer, endpoint, network):
        """
        Create a new overlay for the Internet.

        :param master_peer: the (public key) peer of the owner of this overlay.
        :param my_peer: the (private key) peer of this peer
        :param endpoint: the endpoint to use for messaging
        :param network: the network graph backend
        """
        EndpointListener.__init__(self, endpoint, False)
        TaskManager.__init__(self)
        self.serializer = self.get_serializer()
        self.crypto = ECCrypto()

        self.master_peer = master_peer
        self.my_peer = my_peer

        self.endpoint.add_listener(self)

        self.logger = logging.getLogger(self.__class__.__name__)

        self.network = network

    def unload(self):
        """
        Called when this overlay needs to shut down.
        """
        self.endpoint.remove_listener(self)
        self.shutdown_task_manager()

    def get_serializer(self):
        """
        Get a Serializer for this Overlay.
        """
        return Serializer()

    @abc.abstractmethod
    def on_packet(self, packet):
        """
        Callback for when data is received on this endpoint.

        :param packet: the received packet, in (source, binary string) format.
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

    @abc.abstractmethod
    def get_peers(self):
        """
        Get the peers for this specific overlay.

        :return: the peers in the Network that use this overlay
        """
        pass
