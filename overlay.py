import abc

from keyvault.crypto import ECCrypto
from messaging.interfaces.endpoint import EndpointListener
from messaging.serialization import Serializer
from peer import Peer


class Overlay(EndpointListener):
    """
    Interface for an Internet overlay.
    """

    __metaclass__ = abc.ABCMeta

    def __init__(self, master_key, my_key, endpoint):
        """
        Create a new overlay for the Internet.

        :param master_key: the public key of the owner of this overlay.
        :param my_key: the private key of this peer
        """
        super(Overlay, self).__init__(True)
        self.serializer = self.get_serializer()
        self.crypto = ECCrypto()

        self.master_key = master_key
        self.my_key = my_key

        self.endpoint = endpoint
        self.endpoint.add_listener(self)

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
