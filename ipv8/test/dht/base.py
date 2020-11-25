from ..base import TestBase


class TestDHTBase(TestBase):

    def routing_table(self, i):
        return self.nodes[i].overlay.get_routing_table(self.my_peer(i))

    def storage(self, i):
        return self.nodes[i].overlay.get_storage(self.my_peer(i))

    def my_node_id(self, i):
        return self.nodes[i].overlay.get_my_node_id(self.my_peer(i))
