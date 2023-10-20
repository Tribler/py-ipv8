from __future__ import annotations

import binascii

from ...keyvault.crypto import default_eccrypto
from ...messaging.interfaces.statistics_endpoint import StatisticsEndpoint
from ...peer import Peer
from ..mocking.community import MockCommunity
from ..REST.rest_base import RESTTestBase


def hexlify(value: str) -> str:
    """
    Convert a utf-8 string into a utf-8 hex string.
    """
    return binascii.hexlify(value).decode()


class MockCommunity2(MockCommunity):
    """
    Empty Community for testing.
    """

    community_id = b'DifferentCommunityID'


class TestOverlaysEndpoint(RESTTestBase):
    """
    Tests for REST requests to the overlays endpoint.
    """

    async def setUp(self) -> None:
        """
        Set up a single node.
        """
        super().setUp()
        await self.initialize([], 1, [])
        self.ipv8 = self.node(0)

    def mount_statistics(self, i: int, add_mock_community: bool = True) -> None:
        """
        Add a statistics endpoint to the given node id and possibly load a mock community.
        """
        self.node(i).endpoint = StatisticsEndpoint(self.node(i).endpoint)
        self.node(i).rest_manager.root_endpoint.endpoints['/overlays'].statistics_supported = True

        if add_mock_community:
            self.node(i).overlay = self.add_mock_community(i)

    def add_mock_community(self, i: int, overlay_class: type[MockCommunity] = MockCommunity) -> MockCommunity:
        """
        Add a given overlay class to the given node id.
        """
        mock_community = overlay_class()
        mock_community.endpoint = self.node(i).endpoint
        self.node(i).overlays.append(mock_community)
        return mock_community

    async def test_no_overlays(self) -> None:
        """
        Check if the overlays endpoint returns no overlays if it has no overlays.
        """
        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertListEqual([], response["overlays"])

    async def test_one_overlay_no_peers(self) -> None:
        """
        Check if the overlays endpoint returns one overlay if it has one overlay.
        """
        mock_community = MockCommunity()
        expected_id = hexlify(mock_community.community_id)
        expected_peer = hexlify(mock_community.my_peer.public_key.key_to_bin())
        mock_community.update_global_time(1337)
        self.ipv8.overlays.append(mock_community)

        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertEqual(1, len(response["overlays"]))
        self.assertEqual(expected_id, response["overlays"][0]["id"])
        self.assertEqual(expected_peer, response["overlays"][0]["my_peer"])
        self.assertEqual(mock_community.global_time, response["overlays"][0]["global_time"])
        self.assertListEqual([], response["overlays"][0]["peers"])
        self.assertEqual("MockCommunity", response["overlays"][0]["overlay_name"])
        self.assertDictEqual({}, response["overlays"][0]["statistics"])

    async def test_one_overlay_one_peer(self) -> None:
        """
        Check if the overlays endpoint correctly returns its one peer for its one overlay.
        """
        mock_community = MockCommunity()
        expected_peer = Peer(default_eccrypto.generate_key("very-low"), ("1.2.3.4", 5))
        mock_community.network.add_verified_peer(expected_peer)
        mock_community.network.discover_services(expected_peer, [mock_community.community_id])
        self.ipv8.overlays.append(mock_community)

        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertEqual(1, len(response["overlays"]))
        self.assertEqual(1, len(response["overlays"][0]["peers"]))
        self.assertEqual("1.2.3.4", response["overlays"][0]["peers"][0]["ip"])
        self.assertEqual(5, response["overlays"][0]["peers"][0]["port"])
        self.assertEqual(hexlify(expected_peer.public_key.key_to_bin()),
                         response["overlays"][0]["peers"][0]["public_key"])

    async def test_one_overlay_multiple_peers(self) -> None:
        """
        Check if the overlays endpoint correctly returns its peers for its one overlay.
        """
        mock_community = MockCommunity()
        peer_count = 3
        for _ in range(peer_count):
            expected_peer = Peer(default_eccrypto.generate_key("very-low"), ("1.2.3.4", 5))
            mock_community.network.add_verified_peer(expected_peer)
            mock_community.network.discover_services(expected_peer, [mock_community.community_id])
        self.ipv8.overlays.append(mock_community)

        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertEqual(1, len(response["overlays"]))
        self.assertEqual(peer_count, len(response["overlays"][0]["peers"]))

        # peer_count peers with the same address and distinct keys:
        known_keys = set()
        for i in range(peer_count):
            self.assertEqual("1.2.3.4", response["overlays"][0]["peers"][i]["ip"])
            self.assertEqual(5, response["overlays"][0]["peers"][i]["port"])
            self.assertNotIn(response["overlays"][0]["peers"][i]["public_key"], known_keys)
            known_keys.add(response["overlays"][0]["peers"][i]["public_key"])

    async def test_one_overlay_statistics(self) -> None:
        """
        Check if the overlays endpoint returns overlay statistics correctly for one overlay.
        """
        self.mount_statistics(0)
        self.node(0).endpoint.add_sent_stat(self.overlay(0).get_prefix(), 245, 1337)

        expected_stats = {
            'bytes_down': 0,
            'bytes_up': 1337,
            'diff_time': 0.0,
            'num_down': 0,
            'num_up': 1
        }

        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertEqual(1, len(response["overlays"]))
        self.assertDictEqual(expected_stats, response["overlays"][0]["statistics"])

    async def test_multiple_overlays(self) -> None:
        """
        Check if the overlays endpoint returns multiple overlays.
        """
        expected_id = hexlify(MockCommunity.community_id)
        overlay_count = 3
        for i in range(overlay_count):
            mock_community = MockCommunity()
            mock_community.update_global_time(100 * i)
            self.ipv8.overlays.append(mock_community)

        response = await self.make_request(self.ipv8, "overlays", "GET")

        self.assertIn("overlays", response)
        self.assertEqual(3, len(response["overlays"]))

        # overlay_count overlays with the same community_id and distinct global_time:
        known_global_times = set()
        for i in range(overlay_count):
            self.assertEqual(expected_id, response["overlays"][i]["id"])
            self.assertNotIn(response["overlays"][i]["global_time"], known_global_times)
            known_global_times.add(response["overlays"][i]["global_time"])

    async def test_statistics_no_overlays(self) -> None:
        """
        Check if no statistics are returned if no overlays are loaded.
        """
        response = await self.make_request(self.ipv8, "overlays/statistics", "GET")

        self.assertIn("statistics", response)
        self.assertListEqual([], response["statistics"])

    async def test_statistics_one_overlay(self) -> None:
        """
        Check if statistics are returned for one loaded overlay.
        """
        self.mount_statistics(0)
        self.node(0).endpoint.add_sent_stat(self.overlay(0).get_prefix(), 245, 1337, 42.0)

        expected_stats = {
            'identifier': 245,
            'bytes_down': 0,
            'bytes_up': 1337,
            'num_down': 0,
            'num_up': 1,
            'first_measured_up': 42.0,
            'first_measured_down': 0,
            'last_measured_up': 42.0,
            'last_measured_down': 0
        }

        response = await self.make_request(self.ipv8, "overlays/statistics", "GET")

        self.assertIn("statistics", response)
        self.assertEqual(1, len(response["statistics"]))
        self.assertIn("MockCommunity", response["statistics"][0])
        self.assertEqual(1, len(response["statistics"][0]["MockCommunity"]))
        self.assertIn("245:on_old_introduction_response", response["statistics"][0]["MockCommunity"])
        self.assertDictEqual(expected_stats,
                             response["statistics"][0]["MockCommunity"]["245:on_old_introduction_response"])

    async def test_statistics_one_overlay_with_unknown(self) -> None:
        """
        Check if statistics are returned for one loaded overlay, with an unknown message.
        """
        self.mount_statistics(0)
        self.node(0).endpoint.add_sent_stat(self.overlay(0).get_prefix(), 245, 1337, 42.0)
        self.node(0).endpoint.add_sent_stat(self.overlay(0).get_prefix(), 69, 1492, 7.0)  # 69 does not exist!

        self.assertIsNone(self.overlay(0).decode_map[69])  # Test invariant, use a number that does not exist.

        response = await self.make_request(self.ipv8, "overlays/statistics", "GET")

        self.assertIn("statistics", response)
        self.assertEqual(1, len(response["statistics"]))
        self.assertIn("MockCommunity", response["statistics"][0])
        self.assertEqual(2, len(response["statistics"][0]["MockCommunity"]))
        self.assertIn("245:on_old_introduction_response", response["statistics"][0]["MockCommunity"])
        self.assertIn("69:unknown", response["statistics"][0]["MockCommunity"])

    async def test_enable_stats_not_supported(self) -> None:
        """
        Check if stats cannot be enabled on an endpoint that is not a StatisticsEndpoint.
        """
        response = await self.make_request(self.ipv8, "overlays/statistics", "POST", json={'enable': 'true'},
                                           expected_status=412)

        self.assertFalse(response["success"])

    async def test_enable_stats_no_enable_param(self) -> None:
        """
        Check if stats cannot be enabled when the "enable" parameter is missing.
        """
        self.mount_statistics(0)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST", json={},
                                           expected_status=400)

        self.assertFalse(response["success"])

    async def test_enable_stats_no_target(self) -> None:
        """
        Check if stats cannot be enabled without specifying what overlay(s) to use.
        """
        self.mount_statistics(0)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST", json={'enable': 'true'},
                                           expected_status=412)

        self.assertFalse(response["success"])

    async def test_enable_stats_all(self) -> None:
        """
        Check if stats are correctly returned for one "all" overlays.
        """
        self.mount_statistics(0)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST",
                                           json={'enable': 'true', 'all': 'true'})

        self.assertTrue(response["success"])
        self.assertIn(self.overlay(0).get_prefix(), self.overlay(0).endpoint.statistics)

    async def test_enable_stats_all_many(self) -> None:
        """
        Check if stats are correctly returned for all overlays.
        """
        self.mount_statistics(0)
        mock_community2 = self.add_mock_community(0, MockCommunity2)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST",
                                           json={'enable': 'true', 'all': 'true'})

        self.assertTrue(response["success"])
        self.assertIn(self.overlay(0).get_prefix(), self.overlay(0).endpoint.statistics)
        self.assertIn(mock_community2.get_prefix(), self.overlay(0).endpoint.statistics)

    async def test_enable_stats_one_exclude(self) -> None:
        """
        Check if stats are correctly returned for a specific overlay, excluding another.
        """
        self.mount_statistics(0)
        mock_community2 = self.add_mock_community(0, MockCommunity2)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST",
                                           json={'enable': 'true', 'overlay_name': 'MockCommunity'})

        self.assertTrue(response["success"])
        self.assertIn(self.overlay(0).get_prefix(), self.overlay(0).endpoint.statistics)
        self.assertNotIn(mock_community2.get_prefix(), self.overlay(0).endpoint.statistics)

    async def test_enable_stats_one_include(self) -> None:
        """
        Check if stats are correctly returned for a specific overlay, including another.
        """
        self.mount_statistics(0)
        mock_community2 = self.add_mock_community(0, MockCommunity2)

        response = await self.make_request(self.ipv8, "overlays/statistics", "POST",
                                           json={'enable': 'true', 'overlay_name': 'MockCommunity'})
        response2 = await self.make_request(self.ipv8, "overlays/statistics", "POST",
                                            json={'enable': 'true', 'overlay_name': 'MockCommunity2'})

        self.assertTrue(response["success"])
        self.assertTrue(response2["success"])
        self.assertIn(self.overlay(0).get_prefix(), self.overlay(0).endpoint.statistics)
        self.assertIn(mock_community2.get_prefix(), self.overlay(0).endpoint.statistics)
