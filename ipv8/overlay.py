from __future__ import absolute_import

import abc
import logging
import six

from .keyvault.crypto import default_eccrypto
from .messaging.interfaces.endpoint import EndpointListener
from .messaging.serialization import Serializer
from .taskmanager import TaskManager


class Overlay(six.with_metaclass(abc.ABCMeta, EndpointListener, TaskManager)):
    """
    Interface for an Internet overlay.
    """

    def __init__(self, master_peer, my_peer, endpoint, network, clock):
        """
        Create a new overlay for the Internet.

        :param master_peer: the (public key) peer of the owner of this overlay.
        :param my_peer: the (private key) peer of this peer
        :param endpoint: the endpoint to use for messaging
        :param network: the network graph backend
        :param clock: the Clock object which manages callLater's
        """
        EndpointListener.__init__(self, endpoint)
        TaskManager.__init__(self, clock)
        self.serializer = self.get_serializer()
        self.crypto = default_eccrypto

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

    def get_peer_for_introduction(self, exclude=None):
        """
        Get a peer for introduction.

        :param: exclude: optionally specify a peer that is not considered eligible for introduction
        :return: a Peer to send an introduction request to, or None if there are no available
        """
        pass

    def get_trust(self, peer):
        """
        Get the trust score for a specific peer. This defaults to 1
        """
        return 1
