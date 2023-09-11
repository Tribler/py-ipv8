from typing import TypeVar

from ...dht.routing import Node, RoutingTable
from ...dht.storage import Storage
from ...types import DHTCommunity
from ..base import TestBase

OT = TypeVar("OT", bound=DHTCommunity)


class TestDHTBase(TestBase[OT]):
    """
    Extension to TestBase that provides common DHT shortcuts.
    """

    def dht_node(self, i: int) -> Node:
        """
        Get the node instance of node i.
        """
        address_cls = self.overlay(i).get_address_class(self.my_peer(i))
        address = self.my_peer(i).addresses.get(address_cls, self.overlay(i).my_estimated_wan)
        return Node(self.private_key(i), address)

    def routing_table(self, i: int) -> RoutingTable:
        """
        Get the routing table of node i.
        """
        return self.overlay(i).get_routing_table(self.dht_node(i))

    def storage(self, i: int) -> Storage:
        """
        Get the storage of node i.
        """
        return self.overlay(i).get_storage(self.dht_node(i))

    def my_node_id(self, i: int) -> bytes:
        """
        Get the DHT node id of node i.
        """
        return self.overlay(i).get_my_node_id(self.my_peer(i))
