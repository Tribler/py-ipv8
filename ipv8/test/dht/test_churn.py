import time

from ..base import TestBase
from ...dht.churn import PingChurn
from ...dht.community import DHTCommunity


class TestPingChurn(TestBase):

    def setUp(self):
        super(TestPingChurn, self).setUp()
        self.initialize(DHTCommunity, 2)

        self.strategies = []
        for i in range(2):
            self.strategies.append(PingChurn(self.overlay(i), ping_interval=0.0))

    async def test_ping_all(self):
        await self.introduce_nodes()
        bucket = self.overlay(0).routing_table.trie[u'']

        node1 = bucket.get(self.overlay(1).my_node_id)
        node1.failed = 1
        node1.last_response = 0

        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertTrue(node1.failed == 0)
        self.assertNotEqual(node1.last_response, 0)

    async def test_ping_all_skip(self):
        await self.introduce_nodes()
        bucket = self.overlay(0).routing_table.trie[u'']
        node1 = bucket.get(self.overlay(1).my_node_id)
        node1.failed = 1
        node1.last_response = time.time() + 5

        self.strategies[0].take_step()
        self.assertTrue(node1.failed == 1)
