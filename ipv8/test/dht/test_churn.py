import time

from ...dht.churn import PingChurn
from ...dht.community import DHTCommunity
from .base import TestDHTBase


class TestPingChurn(TestDHTBase[DHTCommunity]):
    """
    Tests for pinging nodes in the DHT community.
    """

    def setUp(self) -> None:
        """
        Create two nodes with a ping churn strategy.
        """
        super().setUp()
        self.initialize(DHTCommunity, 2)
        self.strategies = [PingChurn(self.overlay(i), ping_interval=0.0) for i in range(2)]

    async def test_ping_all(self) -> None:
        """
        Check if a failed node without a previous response is pinged and if it responds.
        """
        await self.introduce_nodes()
        bucket = self.routing_table(0).trie['']

        node1 = bucket.get(self.my_node_id(1))
        node1.failed = 1
        node1.last_response = 0

        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertTrue(node1.failed == 0)
        self.assertNotEqual(node1.last_response, 0)

    async def test_ping_all_skip(self) -> None:
        """
        Check if a failed node that recently responded is not spammed with a ping.
        """
        await self.introduce_nodes()
        bucket = self.routing_table(0).trie['']
        node1 = bucket.get(self.my_node_id(1))
        node1.failed = 1
        node1.last_response = time.time() + 5

        self.strategies[0].take_step()
        self.assertTrue(node1.failed == 1)
