import random
from binascii import unhexlify

from ..base import TestBase
from ...keyvault.crypto import default_eccrypto
from ...peer import Peer
from ...peerdiscovery.network import Network


def _generate_peer():
    key = default_eccrypto.generate_key(u'very-low')
    address = (".".join([str(random.randint(0, 255)) for _ in range(4)]), random.randint(0, 65535))
    return Peer(key, address)


class TestNetwork(TestBase):

    peers = [_generate_peer() for _ in range(4)]

    def setUp(self):
        super(TestNetwork, self).setUp()
        self.network = Network()

    def test_discover_address(self):
        """
        Check registration of introducer and introduced when a new address is discovered.

        The introducer should be verified and not walkable.
        The introduced should not be verified and walkable.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[1].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[1], self.network.verified_peers)
        self.assertIn(self.peers[1].address, self.network.get_introductions_from(self.peers[0]))

    def test_discover_address_duplicate(self):
        """
        Check registration of introducer and introduced when the same address is discovered twice.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.discover_address(self.peers[0], self.peers[1].address)

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[1].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[1], self.network.verified_peers)
        self.assertIn(self.peers[1].address, self.network.get_introductions_from(self.peers[0]))

    def test_discover_address_known(self):
        """
        Check if an address is already known, the network isn't updated.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.discover_address(self.peers[2], self.peers[1].address)

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[1].address, self.network.get_walkable_addresses())
        self.assertNotIn(self.peers[2].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[1], self.network.verified_peers)
        self.assertIn(self.peers[2], self.network.verified_peers)
        self.assertIn(self.peers[1].address, self.network.get_introductions_from(self.peers[0]))

    def test_discover_address_known_parent_deceased(self):
        """
        Check if an address is already known, the new introducer adopts the introduced.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.remove_peer(self.peers[0])
        self.network.discover_address(self.peers[2], self.peers[1].address)

        self.assertIn(self.peers[1].address, self.network.get_walkable_addresses())
        self.assertNotIn(self.peers[2].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[2], self.network.verified_peers)
        self.assertNotIn(self.peers[1], self.network.verified_peers)
        self.assertIn(self.peers[1].address, self.network.get_introductions_from(self.peers[2]))

    def test_discover_address_blacklist(self):
        """
        Check if an address is in the blacklist, the network isn't updated.
        """
        self.network.blacklist.append(self.peers[2].address)
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.discover_address(self.peers[0], self.peers[2].address)

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[1].address, self.network.get_walkable_addresses())
        self.assertNotIn(self.peers[2].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[1], self.network.verified_peers)
        self.assertNotIn(self.peers[2], self.network.verified_peers)
        self.assertIn(self.peers[1].address, self.network.get_introductions_from(self.peers[0]))

    def test_discover_address_multiple(self):
        """
        Check if a single peer can perform multiple introductions.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.discover_address(self.peers[0], self.peers[2].address)

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)

        for other in [1, 2]:
            self.assertIn(self.peers[other].address, self.network.get_walkable_addresses())
            self.assertNotIn(self.peers[other], self.network.verified_peers)
            self.assertIn(self.peers[other].address, self.network.get_introductions_from(self.peers[0]))

    def test_get_introductions_from_cache_no_refresh(self):
        """
        Cache entries in the introduction cache should not refresh.

        This is to avoid dead peers sticking around the cache for too long.
        """
        intro1 = ('1.2.3.4', 5)
        intro2 = ('6.7.8.9', 10)
        intro3 = ('11.12.13.14', 15)
        self.network.discover_address(self.peers[0], intro1)
        self.network.discover_address(self.peers[1], intro2)

        ilist0 = self.network.get_introductions_from(self.peers[0])
        ilist1 = self.network.get_introductions_from(self.peers[1])
        self.assertListEqual([self.peers[0], self.peers[1]], list(self.network.reverse_intro_lookup))
        self.assertListEqual([intro1], ilist0)
        self.assertListEqual([intro2], ilist1)

        # We should make a good faith attempt to update the cache with a new introduction.
        self.network.discover_address(self.peers[0], intro3)
        ilist2 = self.network.get_introductions_from(self.peers[0])
        self.assertListEqual([self.peers[0], self.peers[1]], list(self.network.reverse_intro_lookup))
        self.assertListEqual([intro1, intro3], ilist2)

    def test_discover_services(self):
        """
        Check if services are properly registered for a peer.
        """
        service = "".join([chr(i) for i in range(20)])
        self.network.discover_services(self.peers[0], [service])
        self.network.add_verified_peer(self.peers[0])

        self.assertIn(service, self.network.get_services_for_peer(self.peers[0]))
        self.assertIn(self.peers[0], self.network.get_peers_for_service(service))

    def test_discover_services_unverified(self):
        """
        Check if services are properly registered for an unverified peer.
        """
        service = "".join([chr(i) for i in range(20)])
        self.network.discover_services(self.peers[0], [service])

        self.assertIn(service, self.network.get_services_for_peer(self.peers[0]))
        self.assertNotIn(self.peers[0], self.network.get_peers_for_service(service))

    def test_discover_services_update(self):
        """
        Check if services are properly combined for a peer.
        """
        service1 = "".join([chr(i) for i in range(20)])
        service2 = "".join([chr(i) for i in range(20, 40)])
        self.network.discover_services(self.peers[0], [service1])
        self.network.discover_services(self.peers[0], [service2])
        self.network.add_verified_peer(self.peers[0])

        self.assertIn(service1, self.network.get_services_for_peer(self.peers[0]))
        self.assertIn(service2, self.network.get_services_for_peer(self.peers[0]))
        self.assertIn(self.peers[0], self.network.get_peers_for_service(service1))
        self.assertIn(self.peers[0], self.network.get_peers_for_service(service2))

    def test_discover_services_update_overlap(self):
        """
        Check if services are properly combined when discovered services overlap.
        """
        service1 = "".join([chr(i) for i in range(20)])
        service2 = "".join([chr(i) for i in range(20, 40)])
        self.network.discover_services(self.peers[0], [service1])
        self.network.discover_services(self.peers[0], [service1, service2])
        self.network.add_verified_peer(self.peers[0])

        self.assertIn(service1, self.network.get_services_for_peer(self.peers[0]))
        self.assertIn(service2, self.network.get_services_for_peer(self.peers[0]))
        self.assertIn(self.peers[0], self.network.get_peers_for_service(service1))
        self.assertIn(self.peers[0], self.network.get_peers_for_service(service2))

    def test_discover_services_cache(self):
        """
        Check if services cache updates properly.
        """
        service1 = "".join([chr(i) for i in range(20)])
        service2 = "".join([chr(i) for i in range(20, 40)])
        self.network.reverse_service_cache_size = 1
        self.network.discover_services(self.peers[0], [service1])
        self.network.add_verified_peer(self.peers[0])
        self.network.discover_services(self.peers[1], [service2])
        self.network.add_verified_peer(self.peers[1])

        self.network.get_peers_for_service(service1)
        self.network.get_peers_for_service(service2)

        self.assertListEqual([service2], list(self.network.reverse_service_lookup))

    def test_add_verified_peer_new(self):
        """
        Check if a new verified peer can be added to the network.
        """
        self.network.add_verified_peer(self.peers[0])

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertListEqual([], self.network.get_introductions_from(self.peers[0]))

    def test_add_verified_peer_blacklist(self):
        """
        Check if a new verified peer can be added to the network.
        """
        self.network.blacklist.append(self.peers[0].address)
        self.network.add_verified_peer(self.peers[0])

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertNotIn(self.peers[0], self.network.verified_peers)

    def test_add_verified_peer_duplicate(self):
        """
        Check if an already verified (by slightly changed) peer doesn't cause duplicates in the network.
        """
        self.network.add_verified_peer(self.peers[0])
        self.peers[0].update_clock(1)
        self.network.add_verified_peer(self.peers[0])

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertListEqual([], self.network.get_introductions_from(self.peers[0]))

    def test_add_verified_peer_promote(self):
        """
        Check if a peer can be promoted from an address to a verified peer.
        """
        self.network.discover_address(self.peers[1], self.peers[0].address)
        self.network.add_verified_peer(self.peers[0])

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertIn(self.peers[0], self.network.verified_peers)
        self.assertListEqual([], self.network.get_introductions_from(self.peers[0]))

    def test_get_verified_by_address(self):
        """
        Check if we can find a peer in our network by its address.
        """
        self.network.add_verified_peer(self.peers[0])

        self.assertEqual(self.peers[0], self.network.get_verified_by_address(self.peers[0].address))
        self.assertIn(self.peers[0].address, self.network.reverse_ip_lookup)

    def test_get_verified_by_address_cache_pop(self):
        """
        When the cache if full, pop the least-used entry.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.add_verified_peer(self.peers[1])
        self.network.reverse_ip_cache_size = 1

        self.network.get_verified_by_address(self.peers[1].address)  # Cache stack: [1] (full)
        self.assertListEqual([self.peers[1].address], list(self.network.reverse_ip_lookup))

        self.network.get_verified_by_address(self.peers[0].address)  # Cache stack: [0] (full)
        self.assertListEqual([self.peers[0].address], list(self.network.reverse_ip_lookup))

    def test_get_verified_by_address_cache_refresh(self):
        """
        Asking for the same peer twice should land it back on top of the cleanup stack.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.add_verified_peer(self.peers[1])
        self.network.reverse_ip_cache_size = 2

        self.network.get_verified_by_address(self.peers[1].address)  # Cache stack: [1]
        self.network.get_verified_by_address(self.peers[0].address)  # Cache stack: [1, 0] (full)
        self.network.get_verified_by_address(self.peers[1].address)  # Cache stack: [0, 1] (full)

        self.assertListEqual([self.peers[0].address, self.peers[1].address], list(self.network.reverse_ip_lookup))

    def test_get_verified_by_public_key(self):
        """
        Check if we can find a peer in our network by its public key.
        """
        self.network.add_verified_peer(self.peers[0])

        self.assertEqual(self.peers[0],
                         self.network.get_verified_by_public_key_bin(self.peers[0].public_key.key_to_bin()))

    def test_remove_by_address(self):
        """
        Check if we can remove a peer from our network by its address.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.discover_services(self.peers[0], [b"0" * 20])
        self.network.remove_by_address(self.peers[0].address)

        self.assertNotIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertEqual(set(), self.network.get_services_for_peer(self.peers[0]))

    def test_remove_by_address_unverified(self):
        """
        Check if we can remove an unverified peer from our network by its address.
        """
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.remove_by_address(self.peers[1].address)

        self.assertNotIn(self.peers[1].address, self.network.get_walkable_addresses())

    def test_remove_by_address_unknown(self):
        """
        Removing unknown peers should not affect other peers.
        """
        self.network.add_verified_peer(self.peers[0])

        previous_walkable = self.network.get_walkable_addresses()
        previous_verified = self.network.verified_peers

        self.network.remove_by_address(self.peers[1].address)

        self.assertEqual(previous_walkable, self.network.get_walkable_addresses())
        self.assertEqual(previous_verified, self.network.verified_peers)

    def test_remove_by_address_no_services(self):
        """
        Check if we can remove a peer from our network if it doesn't have services by address.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.remove_by_address(self.peers[0].address)

        self.assertNotIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())

    def test_remove_peer(self):
        """
        Check if we can remove a peer from our network.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.discover_services(self.peers[0], [b"0" * 20])
        self.network.remove_peer(self.peers[0])

        self.assertNotIn(self.peers[0], self.network.verified_peers)
        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())
        self.assertEqual(set(), self.network.get_services_for_peer(self.peers[0]))

    def test_remove_peer_external(self):
        """
        Check if we can remove an externally created peer from our network.
        """
        self.network.discover_address(self.peers[1], self.peers[0].address)
        self.network.remove_peer(self.peers[0])

        self.assertNotIn(self.peers[0].address, self.network.get_walkable_addresses())

    def test_remove_peer_unknown(self):
        """
        Removing unknown peers should not affect other peers.
        """
        self.network.add_verified_peer(self.peers[0])

        previous_walkable = self.network.get_walkable_addresses()
        previous_verified = self.network.verified_peers

        self.network.remove_peer(self.peers[1])

        self.assertEqual(previous_walkable, self.network.get_walkable_addresses())
        self.assertEqual(previous_verified, self.network.verified_peers)

    def test_get_walkable_by_service(self):
        """
        Check if we can retrieve walkable addresses by parent service id.
        """
        service = "".join([chr(i) for i in range(20)])
        self.network.discover_address(self.peers[2], self.peers[3].address)
        self.network.discover_address(self.peers[0], self.peers[1].address)
        self.network.discover_services(self.peers[0], [service])

        self.assertEqual([self.peers[1].address], self.network.get_walkable_addresses(service))

    def test_snapshot_only_verified(self):
        """
        Check if a snapshot poperly serializes verified peers.
        """
        for peer in self.peers:
            self.network.add_verified_peer(peer)
        snapshot = self.network.snapshot()

        self.assertEqual(len(snapshot), 6 * len(self.peers))

    def test_snapshot_verified_and_unverified(self):
        """
        Check if a snapshot poperly serializes only verified peers.
        """
        self.network.add_verified_peer(self.peers[0])
        self.network.discover_address(self.peers[0], self.peers[1].address)
        snapshot = self.network.snapshot()

        self.assertEqual(len(snapshot), 6)

    def test_snapshot_only_unverified(self):
        """
        Check if a snapshot is empty without verified peers.
        """
        self.network.blacklist_mids.append(self.peers[0].mid)
        for peer in self.peers[1:]:
            self.network.discover_address(self.peers[0], peer)
        snapshot = self.network.snapshot()

        self.assertEqual(len(snapshot), 0)

    def test_snapshot_no_peers(self):
        """
        Check if a snapshot is empty without verified peers.
        """
        snapshot = self.network.snapshot()

        self.assertEqual(len(snapshot), 0)

    def test_load_snapshot(self):
        """
        Check if peers can be properly loaded from a snapshot.
        """
        expected = {
            ('54.226.56.113', 57674),
            ('70.200.183.29', 60815),
            ('194.116.42.174', 21882),
            ('143.93.254.175', 41862)
        }
        snapshot = unhexlify("36e23871e14a8f5dfeafa386c2742aae557a46c8b71ded8f")

        self.network.load_snapshot(snapshot)
        peers = set(self.network.get_walkable_addresses())

        self.assertSetEqual(peers, expected)

    def test_load_snapshot_empty(self):
        """
        Check if no peers are loaded from an empty snapshot.
        """
        self.network.load_snapshot("")
        peers = set(self.network.get_walkable_addresses())

        self.assertSetEqual(peers, set())

    def test_load_snapshot_malformed(self):
        """
        Check if no peers are loaded from a malformed snapshot.
        """
        snapshot = unhexlify("36e23871e14a8f5dfeafa386c2742aae557a46c8b71ded8f")

        self.network.load_snapshot(snapshot[:-1])
        peers = set(self.network.get_walkable_addresses())

        self.assertSetEqual(peers, set())
