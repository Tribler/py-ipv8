import time

from ..base import TestBase
from ..mocking.ipv8 import MockIPv8
from ...dht.churn import PingChurn
from ...dht.community import DHTCommunity


class TestPingChurn(TestBase):

    def setUp(self):
        super(TestPingChurn, self).setUp()

        self.overlays = []
        self.strategies = []

        self.initialize(DHTCommunity, 2)

    def create_node(self, *args, **kwargs):
        peer = MockIPv8(u"low", DHTCommunity)

        self.overlays.append(peer.overlay)
        self.strategies.append(PingChurn(peer.overlay, ping_interval=0.0))

        return peer

    async def test_ping_all(self):
        await self.introduce_nodes()
        bucket = self.overlays[0].routing_table.trie[u'']

        node1 = bucket.get(self.overlays[1].my_node_id)
        node1.failed = 1
        node1.last_response = 0

        self.strategies[0].take_step()
        await self.deliver_messages()

        self.assertTrue(node1.failed == 0)
        self.assertNotEqual(node1.last_response, 0)

    async def test_ping_all_skip(self):
        await self.introduce_nodes()
        bucket = self.overlays[0].routing_table.trie[u'']
        node1 = bucket.get(self.overlays[1].my_node_id)
        node1.failed = 1
        node1.last_response = time.time() + 5

        self.strategies[0].take_step()
        self.assertTrue(node1.failed == 1)
