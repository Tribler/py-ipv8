import time
from binascii import unhexlify

from ...dht.routing import NODE_STATUS_BAD, NODE_STATUS_GOOD, NODE_STATUS_UNKNOWN, Bucket, Node, RoutingTable
from ...keyvault.private.libnaclkey import LibNaCLSK
from ..base import TestBase


class FakeNode(Node):
    """
    A fake node.
    """

    def __init__(self, binary_prefix: str) -> None:
        """
        Create a fake node with a given prefix.
        """
        id_binary = int(binary_prefix + '0' * (160 - len(binary_prefix)), 2)
        super().__init__(LibNaCLSK(b'LibNaCLSK:' + id_binary.to_bytes(64, "big")), ('1.1.1.1', 1))
        id_hex = '%x' % id_binary
        id_hex = '0' + id_hex if len(id_hex) % 2 != 0 else id_hex

        self._id = unhexlify(id_hex)

    @property
    def id(self) -> bytes:  # noqa: A003
        """
        Our fixed testing id.
        """
        return self._id

    @property
    def status(self) -> int:
        """
        Always return a good status.
        """
        return NODE_STATUS_GOOD


class TestNode(TestBase):
    """
    Tests related to the states of nodes.
    """

    def setUp(self) -> None:
        """
        Create a single node.
        """
        super().setUp()
        self.key = LibNaCLSK(b'\x01' * 64)
        self.node = Node(self.key, ('1.1.1.1', 1))

    def test_init(self) -> None:
        """
        Check if the defaults values of nodes are properly initialized.
        """
        self.assertEqual(self.node.bucket, None)
        self.assertEqual(self.node.last_response, 0)
        self.assertEqual(self.node.last_query, 0)
        self.assertEqual(self.node.failed, 0)
        self.assertEqual(self.node.id, unhexlify('f626d35b16b30807cdcb11f8214a5eb762c0dc19'))

    def test_status(self) -> None:
        """
        Check if the status of nodes is correctly returned.
        """
        self.node.last_response = time.time()
        self.assertEqual(self.node.status, NODE_STATUS_GOOD)

        self.node.last_response = 1
        self.node.last_queries.append(time.time())
        self.assertEqual(self.node.status, NODE_STATUS_GOOD)

        self.node.last_queries.clear()
        self.assertEqual(self.node.status, NODE_STATUS_UNKNOWN)

        self.node.failed += 3
        self.assertEqual(self.node.status, NODE_STATUS_BAD)

    def test_last_contact(self) -> None:
        """
        Check if the last contact property is properly derived from the last queries and last response.
        """
        self.node.last_queries.append(5)
        self.assertEqual(self.node.last_contact, 5)

        self.node.last_response = 10
        self.assertEqual(self.node.last_contact, 10)


class TestBucket(TestBase):
    """
    Tests related to Buckets.
    """

    def setUp(self) -> None:
        """
        Create a single bucket with a prefix id of ``01`` and maximum size of 8.
        """
        super().setUp()
        self.bucket = Bucket('01', max_size=8)

    def test_owns(self) -> None:
        """
        Check if a Bucket correctly identifies that prefixes that it should "own".
        """
        pad_and_convert = lambda b: unhexlify('{:<040X}'.format(int(b.ljust(160, '0'), 2)))
        self.assertTrue(self.bucket.owns(pad_and_convert('01')))
        self.assertTrue(self.bucket.owns(pad_and_convert('010')))
        self.assertFalse(self.bucket.owns(pad_and_convert('00')))
        self.assertFalse(self.bucket.owns(pad_and_convert('11')))

    def test_get(self) -> None:
        """
        Check if nodes can be retrieved by their id.
        """
        node = FakeNode('01')
        self.bucket.nodes[bytes(1)] = node
        self.assertEqual(self.bucket.get(bytes(1)), node)
        self.assertEqual(self.bucket.get(bytes(2)), None)

    def test_add(self) -> None:
        """
        Check if adding a node to a bucket that it belongs to succeeds.
        """
        node = FakeNode('01')
        self.assertTrue(self.bucket.add(node))
        self.assertEqual(self.bucket.get(node.id), node)

    def test_add_fail(self) -> None:
        """
        Check if adding a node to a bucket that it does not belong to fails.
        """
        node = FakeNode('11')
        self.assertFalse(self.bucket.add(node))
        self.assertEqual(self.bucket.get(node.id), None)

    def test_add_update(self) -> None:
        """
        Check if nodes are merged together with their most recent data.
        """
        node1 = FakeNode('01')
        node2 = FakeNode('01')
        node2.address = ('1.2.3.4', 1)
        self.assertEqual(self.bucket.last_changed, 0)
        self.bucket.add(node1)
        self.bucket.add(node2)
        self.assertEqual(self.bucket.get(node1.id), node1)
        self.assertEqual(self.bucket.get(node1.id).address, ('1.2.3.4', 1))
        self.assertNotEqual(self.bucket.last_changed, 0)

    def test_add_full(self) -> None:
        """
        Check if nodes are not added to an already-full bucket.
        """
        self.bucket.max_size = 1
        node1 = FakeNode('011')
        node2 = FakeNode('010')
        self.bucket.add(node1)
        self.bucket.add(node2)
        self.assertEqual(self.bucket.get(node1.id), node1)
        self.assertEqual(self.bucket.get(node2.id), None)

    def test_add_cleanup(self) -> None:
        """
        Check if nodes are not added to an already-full bucket, even if the existing nodes should be cleaned.
        """
        self.bucket.max_size = 1
        node1 = FakeNode('011')
        node2 = FakeNode('010')
        self.bucket.add(node1)
        node1.failed += 3
        self.bucket.add(node2)
        self.assertEqual(self.bucket.get(node1.id), node1)
        self.assertEqual(self.bucket.get(node2.id), None)

    def test_split(self) -> None:
        """
        Check if buckets properly split into other buckets.
        """
        self.bucket.max_size = 1
        node = FakeNode('011')
        self.bucket.add(node)

        b010, b011 = self.bucket.split()
        self.assertIsInstance(b010, Bucket)
        self.assertIsInstance(b011, Bucket)
        self.assertEqual(b010.get(node.id), None)
        self.assertEqual(b010.prefix_id, '010')
        self.assertEqual(b011.get(node.id), node)
        self.assertEqual(b011.prefix_id, '011')

    def test_split_not_full(self) -> None:
        """
        Check that non-full buckets do not allow splits.
        """
        self.assertFalse(self.bucket.split())


class TestRoutingTable(TestBase):
    """
    Tests for routing tables.
    """

    def setUp(self) -> None:
        """
        Create a routing table for a fake node with prefix 1111111111111111111111111111111111111111.
        """
        super().setUp()
        self.my_node = FakeNode('11' * 20)
        self.routing_table = RoutingTable(self.my_node.id)
        self.trie = self.routing_table.trie

    def test_add_single_node(self) -> None:
        """
        Check that adding a node to the routing table inserts it into the trie.
        """
        node = FakeNode('0')
        self.routing_table.add(node)

        self.assertTrue(self.trie[''].get(node.id))

    def test_add_multiple_nodes(self) -> None:
        """
        Check that adding multiple nodes causes them to be inserted into the trie.
        """
        node1 = FakeNode('00')
        node2 = FakeNode('01')

        self.routing_table.add(node1)
        self.routing_table.add(node2)

        self.assertTrue(self.trie[''].get(node1.id))
        self.assertTrue(self.trie[''].get(node2.id))

    def test_add_node_with_bucket_split(self) -> None:
        """
        Check that overflowing the max size of a trie splits it.
        """
        self.trie[''].max_size = 1

        node1 = FakeNode('0')
        node2 = FakeNode('1')

        self.routing_table.add(node1)
        self.routing_table.add(node2)

        self.assertTrue(self.trie['0'].get(node1.id))
        self.assertTrue(self.trie['1'].get(node2.id))

    def test_add_node_full(self) -> None:
        """
        Check that a node is dropped if another node already serves its (max size) prefix.
        """
        self.trie[''].max_size = 1

        node1 = FakeNode('1')
        node2 = FakeNode('00')
        node3 = FakeNode('01')

        self.routing_table.add(node1)
        self.routing_table.add(node2)
        # This time the bucket should not be split. Instead the node should be dropped.
        self.routing_table.add(node3)

        self.assertTrue(self.trie['1'].get(node1.id))
        self.assertTrue(self.trie['0'].get(node2.id))
        self.assertFalse(self.trie['0'].get(node3.id))

    def test_closest_nodes_single_bucket(self) -> None:
        """
        Check if we can retrieve the closest nodes, in order, to a given id.
        """
        node1 = FakeNode('00')
        node2 = FakeNode('10')
        node3 = FakeNode('01')

        self.routing_table.add(node1)
        self.routing_table.add(node2)
        self.routing_table.add(node3)

        closest_nodes = self.routing_table.closest_nodes(b'\00' * 20)
        self.assertEqual(closest_nodes[0], node1)
        self.assertEqual(closest_nodes[1], node3)
        self.assertEqual(closest_nodes[2], node2)

    def test_closest_nodes_multiple_buckets(self) -> None:
        """
        Check if we can retrieve the closest nodes, in order, to a given id after a trie split.
        """
        self.trie[''].max_size = 1

        node1 = FakeNode('11')
        node2 = FakeNode('10')
        node3 = FakeNode('01')

        self.routing_table.add(node1)
        self.routing_table.add(node2)
        self.routing_table.add(node3)

        closest_nodes = self.routing_table.closest_nodes(b'\00' * 20)
        self.assertEqual(closest_nodes[0], node3)
        self.assertEqual(closest_nodes[1], node2)
        self.assertEqual(closest_nodes[2], node1)

    def test_closest_nodes_no_nodes(self) -> None:
        """
        Check if we return False if no nodes are available as closest nodes.
        """
        self.assertFalse(self.routing_table.closest_nodes(b'\00' * 20))
