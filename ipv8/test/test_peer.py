from base64 import b64encode

from .base import TestBase
from ..keyvault.crypto import default_eccrypto
from ..messaging.interfaces.udp.endpoint import UDPv4Address, UDPv6Address
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

    def test_set_address_init(self):
        """
        Check if the address property properly sets from the init.
        """
        address = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key, address)

        self.assertEqual(peer.address, address)

    def test_set_address_setter(self):
        """
        Check if the address property properly sets from the setter.
        """
        address = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key)
        peer.address = address

        self.assertEqual(peer.address, address)

    def test_set_address_add(self):
        """
        Check if the address property properly sets from add_address.
        """
        address = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key)
        peer.add_address(address)

        self.assertEqual(peer.address, address)

    def test_set_address_addv6(self):
        """
        Check if IPv6 addresses are properly returned.
        """
        address = UDPv6Address("1:2:3:4:5:6", 7)
        peer = Peer(TestPeer.test_key)
        peer.add_address(address)

        self.assertEqual(peer.address, address)

    def test_address_order1(self):
        """
        Check if IPv6 is preferred over IPv4 (append out-of-order).
        """
        address1 = UDPv4Address("1.2.3.4", 5)
        address2 = UDPv6Address("1:2:3:4:5:6", 7)
        peer = Peer(TestPeer.test_key)
        peer.add_address(address2)
        peer.add_address(address1)

        self.assertEqual(peer.address, address2)

    def test_address_order2(self):
        """
        Check if IPv6 is preferred over IPv4 (append in-order).
        """
        address1 = UDPv4Address("1.2.3.4", 5)
        address2 = UDPv6Address("1:2:3:4:5:6", 7)
        peer = Peer(TestPeer.test_key)
        peer.add_address(address1)
        peer.add_address(address2)

        self.assertEqual(peer.address, address2)

    def test_default_address(self):
        """
        Check if the default address is UDPv4Address("0.0.0.0", 0)
        """
        self.assertEqual(Peer(TestPeer.test_key).address, UDPv4Address("0.0.0.0", 0))

    def test_manual_update(self):
        """
        Check if manual updates to the addresses dictionary are caught.
        """
        address = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key)
        peer.addresses.update({UDPv4Address: address})

        self.assertEqual(peer.address, address)

    def test_manual_updates(self):
        """
        Check if manual updates to the addresses dictionary are caught (double update, out-of-order).
        """
        address1 = UDPv6Address("1:2:3:4:5:6", 7)
        address2 = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key)
        peer.addresses.update({UDPv4Address: address2})
        peer.addresses.update({UDPv6Address: address1})

        self.assertEqual(peer.address, address1)

    def test_manual_update_overwrite(self):
        """
        Check if manual updates to the addresses dictionary are caught (overwrite same class).
        """
        address = UDPv4Address("1.2.3.4", 5)
        peer = Peer(TestPeer.test_key, UDPv4Address("6.7.8.9", 10))
        peer.addresses.update({UDPv4Address: address})

        self.assertEqual(peer.address, address)
