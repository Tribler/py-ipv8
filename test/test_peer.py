import time
import unittest

from peer import Peer


class TestPeer(unittest.TestCase):

    def setUp(self):
        super(TestPeer, self).setUp()
        self.peer = Peer("", ("1.2.3.4", 5))

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

    def test_intro_inactive(self):
        """
        Check if introduced Peers are not be immediately dropped.
        """
        self.assertFalse(self.peer.is_inactive())
        self.assertFalse(self.peer.should_drop())

    def test_inactive(self):
        """
        Check if Peers are marked inactive after 30 seconds.
        """
        self.peer.last_response = time.time() - 30

        self.assertTrue(self.peer.is_inactive())
        self.assertFalse(self.peer.should_drop())

    def test_should_drop(self):
        """
        Check if Peers are marked should_drop after 60 seconds.
        """
        self.peer.last_response = time.time() - 60

        self.assertTrue(self.peer.is_inactive())
        self.assertTrue(self.peer.should_drop())
