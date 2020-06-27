from base64 import b64encode

from .base import TestBase
from ..keyvault.crypto import default_eccrypto
from ..peer import Peer


class TestPeer(TestBase):

    test_key = default_eccrypto.generate_key(u"very-low")

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

        self.assertTrue(self.peer == other)
        self.assertFalse(self.peer != other)

    def test_peer_inequality_key(self):
        """
        Check if peers with a different key and same address are not equal.
        """
        other = Peer(default_eccrypto.generate_key(u"very-low"), self.peer.address)

        self.assertNotEqual(self.peer, other)

    def test_median_ping_none(self):
        """
        No ping measurements should lead to a None median ping.
        """
        self.assertIsNone(self.peer.get_median_ping())

    def test_avg_ping_none(self):
        """
        No ping measurements should lead to a None average ping.
        """
        self.assertIsNone(self.peer.get_average_ping())

    def test_median_ping_odd(self):
        """
        Median ping should return the median ping for odd length measurements.
        """
        self.peer.pings.append(2.0)
        self.peer.pings.append(3.0)
        self.peer.pings.append(4.0)
        self.assertEqual(3.0, self.peer.get_median_ping())

    def test_median_ping_even(self):
        """
        Median ping should return the median ping for even length measurements.
        """
        self.peer.pings.append(2.0)
        self.peer.pings.append(3.0)
        self.peer.pings.append(4.0)
        self.peer.pings.append(5.0)
        self.assertEqual(3.5, self.peer.get_median_ping())

    def test_avg_ping(self):
        """
        Average ping should return the average ping.
        """
        self.peer.pings.append(3.0)
        self.peer.pings.append(4.0)
        self.assertEqual(3.5, self.peer.get_average_ping())

    def test_peer_inequality_address(self):
        """
        Check if peers with the same key and a different address are equal.
        """
        other = Peer(self.peer.key)

        self.assertEqual(self.peer, other)

    def test_to_string(self):
        """
        Check if the __str__ method functions properly.
        """
        self.assertEqual(str(self.peer), "Peer<1.2.3.4:5, %s>" % b64encode(self.peer.mid).decode('utf-8'))
