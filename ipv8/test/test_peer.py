from twisted.trial import unittest

from ..keyvault.crypto import ECCrypto
from ..peer import Peer


class TestPeer(unittest.TestCase):

    test_key = ECCrypto().generate_key(u"very-low")

    def setUp(self):
        super(TestPeer, self).setUp()
        self.peer = Peer(TestPeer.test_key, ("1.2.3.4", 5))

    def test_default_timestamp(self):
        """
        Check if the default Lamport timestamp of a Peer is 0.
        """
        self.assertEqual(self.peer.get_lamport_timestamp(), 0)

    def test_increment_timestamp(self):
        """
        Check if the Lamport timestamp of a Peer can be incremented.
        """
        self.peer.update_clock(1)

        self.assertEqual(self.peer.get_lamport_timestamp(), 1)

    def test_increase_timestamp(self):
        """
        Check if the Lamport timestamp of a Peer can be increased arbitrarily.
        """
        self.peer.update_clock(42)

        self.assertEqual(self.peer.get_lamport_timestamp(), 42)

    def test_decrease_timestamp(self):
        """
        Check if the Lamport timestamp of a Peer cannot be decreased.
        """
        self.peer.update_clock(-1)

        self.assertEqual(self.peer.get_lamport_timestamp(), 0)

    def test_peer_equality(self):
        """
        Check if peers with the same key and address are equal.
        """
        other = Peer(self.peer.key, self.peer.address)

        self.assertEqual(self.peer, other)

    def test_peer_inequality_key(self):
        """
        Check if peers with a different key and same address are not equal.
        """
        other = Peer(ECCrypto().generate_key(u"very-low"), self.peer.address)

        self.assertNotEqual(self.peer, other)

    def test_peer_inequality_address(self):
        """
        Check if peers with the same key and a different address are not equal.
        """
        other = Peer(self.peer.key)

        self.assertNotEqual(self.peer, other)

    def test_to_string(self):
        """
        Check if the __str__ method functions properly.
        """
        self.assertEqual(str(self.peer), "Peer<1.2.3.4:5, %s>" % self.peer.mid.encode('base64')[:-1])
