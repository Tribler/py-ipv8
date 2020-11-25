import time

from .base import TestDHTBase
from ...dht.churn import PingChurn
from ...dht.community import DHTCommunity


class TestPingChurn(TestDHTBase):

    def setUp(self):
        super(TestPingChurn, self).setUp()
        self.initialize(DHTCommunity, 2)

        self.strategies = []
        for i in range(2):
            self.strategies.append(PingChurn(self.overlay(i), ping_interval=0.0))

    async def test_ping_all(self):
        await self.introduce_nodes()
        bucket = self.routing_table(0).trie[u'']

        node1 = bucket.get(self.my_node_id(1))
        node1.failed = 1
        node1.last_response = 0

        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertTrue(node1.failed == 0)
        self.assertNotEqual(node1.last_response, 0)

    async def test_ping_all_skip(self):
        await self.introduce_nodes()
        bucket = self.routing_table(0).trie[u'']
        node1 = bucket.get(self.my_node_id(1))
        node1.failed = 1
        node1.last_response = time.time() + 5

        self.strategies[0].take_step()
        self.assertTrue(node1.failed == 1)
