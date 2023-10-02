import base64
import random

from ...keyvault.crypto import default_eccrypto
from ...peer import Peer
from ..REST.rest_base import RESTTestBase


class TestNetworkEndpoint(RESTTestBase):
    """
    Tests related to the network REST endpoint.
    """

    mock_peer = Peer(default_eccrypto.generate_key("curve25519"), address=("1.2.3.4", 5))
    mock_b64mid = base64.b64encode(mock_peer.mid).decode()
    mock_b64pubkey = base64.b64encode(mock_peer.public_key.key_to_bin()).decode()

    async def setUp(self) -> None:
        """
        Create a single node.
        """
        super().setUp()
        await self.initialize([], 1, [])
        self.ipv8 = self.node(0)

    async def test_no_peers(self) -> None:
        """
        Check if the network endpoint returns no peers if it has no peers.
        """
        peer_response = await self.make_request(self.ipv8, "network", "GET")

        self.assertIn("peers", peer_response)
        self.assertDictEqual({}, peer_response["peers"])

    async def test_one_peer_no_services(self) -> None:
        """
        Check if the network endpoint returns its one known peer with no services.
        """
        self.ipv8.network.add_verified_peer(self.mock_peer)

        peer_response = await self.make_request(self.ipv8, "network", "GET")

        self.assertIn("peers", peer_response)
        self.assertIn(self.mock_b64mid, peer_response["peers"])
        self.assertEqual("1.2.3.4", peer_response["peers"][self.mock_b64mid]["ip"])
        self.assertEqual(5, peer_response["peers"][self.mock_b64mid]["port"])
        self.assertEqual(self.mock_b64pubkey, peer_response["peers"][self.mock_b64mid]["public_key"])
        self.assertListEqual([], peer_response["peers"][self.mock_b64mid]["services"])

    async def test_one_peer_one_service(self) -> None:
        """
        Check if the network endpoint returns its one known peer with one service.
        """
        self.ipv8.network.add_verified_peer(self.mock_peer)
        mock_service = bytes(list(range(20)))
        mock_b64service = base64.b64encode(mock_service).decode()
        self.ipv8.network.discover_services(self.mock_peer, [mock_service])

        peer_response = await self.make_request(self.ipv8, "network", "GET")

        self.assertIn("peers", peer_response)
        self.assertIn(self.mock_b64mid, peer_response["peers"])
        self.assertEqual("1.2.3.4", peer_response["peers"][self.mock_b64mid]["ip"])
        self.assertEqual(5, peer_response["peers"][self.mock_b64mid]["port"])
        self.assertEqual(self.mock_b64pubkey, peer_response["peers"][self.mock_b64mid]["public_key"])
        self.assertListEqual([mock_b64service], peer_response["peers"][self.mock_b64mid]["services"])

    async def test_one_peer_multiple_services(self) -> None:
        """
        Check if the network endpoint returns its one known peer with multiple services.
        """
        self.ipv8.network.add_verified_peer(self.mock_peer)
        mock_services = [bytes([random.randint(0, 255) for _ in range(20)]) for __ in range(30)]
        mock_b64services = [base64.b64encode(mock_service).decode() for mock_service in mock_services]
        self.ipv8.network.discover_services(self.mock_peer, mock_services)

        peer_response = await self.make_request(self.ipv8, "network", "GET")

        self.assertIn("peers", peer_response)
        self.assertIn(self.mock_b64mid, peer_response["peers"])
        self.assertEqual("1.2.3.4", peer_response["peers"][self.mock_b64mid]["ip"])
        self.assertEqual(5, peer_response["peers"][self.mock_b64mid]["port"])
        self.assertEqual(self.mock_b64pubkey, peer_response["peers"][self.mock_b64mid]["public_key"])
        self.assertSetEqual(set(mock_b64services), set(peer_response["peers"][self.mock_b64mid]["services"]))

    async def test_multiple_peers_multiple_services(self) -> None:
        """
        Check if the network endpoint returns multiple peers with distinct services.
        """
        mock_peers = [Peer(default_eccrypto.generate_key("curve25519")) for _ in range(20)]
        mock_b64services = {}
        for mock_peer in mock_peers:
            b64mid = base64.b64encode(mock_peer.mid).decode()
            self.ipv8.network.add_verified_peer(mock_peer)
            local_services = [bytes([random.randint(0, 255) for _ in range(20)]) for __ in range(30)]
            mock_b64services[b64mid] = [base64.b64encode(s).decode() for s in local_services]
            self.ipv8.network.discover_services(mock_peer, local_services)

        peer_response = await self.make_request(self.ipv8, "network", "GET")

        self.assertIn("peers", peer_response)
        for b64mid, peer_descriptor in peer_response["peers"].items():
            self.assertIn(b64mid, [base64.b64encode(p.mid).decode() for p in mock_peers])
            self.assertIn(peer_descriptor["public_key"],
                          [base64.b64encode(p.public_key.key_to_bin()).decode() for p in mock_peers])
            self.assertEqual("0.0.0.0", peer_descriptor["ip"])
            self.assertEqual(0, peer_descriptor["port"])
            self.assertSetEqual(set(mock_b64services[b64mid]), set(peer_descriptor["services"]))
