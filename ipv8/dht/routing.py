from __future__ import annotations

import binascii
import random
import socket
import time
from collections import deque
from threading import RLock
from typing import TYPE_CHECKING, cast

from ..messaging.interfaces.udp.endpoint import UDPv4Address, UDPv6Address
from ..peer import Peer
from .trie import Trie

if TYPE_CHECKING:
    from ..types import Address, Key

# By default we allow a maximum number of 10 queries during a 5s interval.
# Additional queries will be dropped.
NODE_LIMIT_INTERVAL = 5
NODE_LIMIT_QUERIES = 10

NODE_STATUS_GOOD = 2
NODE_STATUS_UNKNOWN = 1
NODE_STATUS_BAD = 0

MAX_BUCKET_SIZE = 8


def id_to_binary_string(node_id: bytes) -> str:
    """
    Convert a node id to a string.
    """
    return format(int(binascii.hexlify(node_id), 16), '0160b')


def distance(a: bytes, b: bytes) -> int:
    """
    Get the XOR between two bytes strings, encoded as in int.
    """
    return int(binascii.hexlify(a), 16) ^ int(binascii.hexlify(b), 16)


def calc_node_id(address: Address | UDPv4Address | UDPv6Address, mid: bytes) -> bytes:
    """
    Loosely based on the Bittorrent DHT (https://libtorrent.org/dht_sec.html), the node id is calculated as
    follows for IPv4: first 3 bytes of crc32c(ip & 0x030f3fff) + first 17 bytes of sha1(public_key).
    """
    if isinstance(address, UDPv6Address):
        ip_bin = socket.inet_pton(socket.AF_INET6, address.ip)
        ip_mask = b'\x01\x03\x07\x0f\x1f\x3f\x7f\xff'
        ip_masked = bytes([ip_bin[i] & ip_mask[i] for i in range(8)])
    else:
        ip_bin = socket.inet_aton(address[0])
        ip_mask = b'\x03\x0f\x3f\xff'
        ip_masked = bytes([ip_bin[i] & ip_mask[i] for i in range(4)])

    crc32_unsigned = binascii.crc32(ip_masked) % (2 ** 32)
    crc32_bin = binascii.unhexlify('%08x' % crc32_unsigned)

    return crc32_bin[:3] + mid[:17]


class Node(Peer):
    """
    The Node class represents a peer within the DHT community.
    """

    def __init__(self, key: Key | bytes, address: Address | None = None, intro: bool = True) -> None:
        """
        Create a new Node instance.
        """
        super().__init__(key, address, intro)
        self.bucket: Bucket | None = None
        self.last_response: float = 0
        self.last_queries: deque[float] = deque(maxlen=NODE_LIMIT_QUERIES)
        self.last_ping_sent: float = 0
        self.failed: int = 0
        self.rtt: float = 0

    @property
    def id(self) -> bytes:  # noqa: A003
        """
        The id of this node.
        """
        return calc_node_id(self.address, self.mid)

    @property
    def last_contact(self) -> float:
        """
        The last timestamp (in seconds) that we interacted with this node.
        """
        return max(self.last_response, self.last_query)

    @property
    def last_query(self) -> float:
        """
        The last timestamp (in seconds) that we queried this node.
        """
        return self.last_queries[-1] if self.last_queries else 0

    @property
    def blocked(self) -> bool:
        """
        Whether this node is blocked.
        """
        if len(self.last_queries) < cast(int, self.last_queries.maxlen):
            return False
        return time.time() - self.last_queries[0] < NODE_LIMIT_INTERVAL

    @property
    def status(self) -> int:
        """
        A good node is a node has responded to one of our queries within the last 15 minutes, or has ever responded
        to one of our queries and has sent us a query within the last 15 minutes. This is the same logic as
        used in BEP-5.
        """
        now = time.time()
        if self.failed >= 2:
            return NODE_STATUS_BAD
        if ((now - self.last_response) < 15 * 60) or (self.last_response > 0 and (now - self.last_query) < 15 * 60):
            return NODE_STATUS_GOOD
        return NODE_STATUS_UNKNOWN

    def distance(self, other_node: Node | bytes) -> int:
        """
        The distance to another node.
        """
        return distance(self.id, other_node.id if isinstance(other_node, Node) else other_node)


class Bucket:
    """
    The Bucket class stores nodes that share common prefix ID.
    """

    def __init__(self, prefix_id: str, max_size: int = MAX_BUCKET_SIZE) -> None:
        """
        Create a new bucket.
        """
        self.nodes: dict[bytes, Node] = {}
        self.prefix_id: str = prefix_id
        self.max_size: int = max_size
        self.last_changed: float = 0

    def generate_id(self) -> bytes:
        """
        Generate a new id.
        """
        rand_node_id_bin = format(random.randint(0, 2 ** (160 - len(self.prefix_id))), '0160b')
        return binascii.unhexlify(format(int(rand_node_id_bin, 2), '040X'))

    def owns(self, node_id: bytes) -> bool:
        """
        Whether the given node id is in this bucket.
        """
        node_id_binary = id_to_binary_string(node_id)
        return node_id_binary.startswith(self.prefix_id)

    def get(self, node_id: bytes) -> Node | None:
        """
        Get the object belonging to the given node id.
        """
        return self.nodes.get(node_id)

    def add(self, node: Node) -> bool:
        """
        Attempt to add the given node to this bucket.

        :param node: the node to add.
        :return: whether the addition was successful.
        """
        # Is this node allowed to be in this bucket?
        if not self.owns(node.id):
            return False

        # Update existing node
        if node.id in self.nodes:
            curr_node = self.nodes[node.id]
            curr_node.address = node.address
            self.last_changed = time.time()
            return True

        # Make room if needed
        if len(self.nodes) >= self.max_size:
            for n in list(self.nodes.values()):
                if n.status == NODE_STATUS_BAD:
                    self.nodes.pop(n.id)
                    break

            for n in list(self.nodes.values()):
                if node.rtt and n.rtt / node.rtt >= 2.0:
                    self.nodes.pop(n.id)
                    break

        # Insert
        if len(self.nodes) < self.max_size:
            self.nodes[node.id] = node
            node.bucket = self
            self.last_changed = time.time()
            return True

        return False

    def split(self) -> tuple[Bucket, Bucket] | None:
        """
        Split this bucket in two.

        :return: the new buckets.
        """
        if len(self.nodes) < self.max_size:
            return None

        b_0 = Bucket(self.prefix_id + '0', self.max_size)
        b_1 = Bucket(self.prefix_id + '1', self.max_size)
        for node in list(self.nodes.values()):
            if b_0.owns(node.id):
                b_0.add(node)
            elif b_1.owns(node.id):
                b_1.add(node)
            else:
                import logging
                logging.exception('Failed to place node into bucket while splitting')
        return b_0, b_1


class RoutingTable:
    """
    The RoutingTable is a binary tree that keeps track of Nodes that we have a connection to.
    """

    def __init__(self, my_node_id: bytes) -> None:
        """
        Construct a new routing table for our own node id.
        """
        self.my_node_id = my_node_id
        self.trie = Trie[Bucket]('01')
        self.trie[''] = Bucket('')
        self.lock = RLock()

    def get_bucket(self, node_id: bytes) -> Bucket:
        """
        Get the bucket that a given node id belongs to.
        """
        node_id_binary = id_to_binary_string(node_id)
        return self.trie.longest_prefix_value(node_id_binary, default=None) or self.trie['']

    def add(self, node: Node) -> Node | None:
        """
        Add the given node to the routing table.
        """
        with self.lock:
            bucket = self.get_bucket(node.id)

            # Add/update node
            if not bucket.add(node):
                # If adding the node failed, split the bucket
                # Splitting is only allowed if our own node_id falls within this bucket
                if bucket.owns(self.my_node_id):
                    split = bucket.split()
                    if split is None:
                        return None
                    bucket_0, bucket_1 = split
                    self.trie[bucket.prefix_id + '0'] = bucket_0
                    self.trie[bucket.prefix_id + '1'] = bucket_1
                    del self.trie[bucket.prefix_id]

                    # Retry
                    return self.add(node)
                return None
            return bucket.get(node.id)

    def remove_bad_nodes(self) -> list[Node]:
        """
        Remove nodes that have the BAD status.
        """
        with self.lock:
            removed = []
            for bucket in self.trie.values():
                for node_id, node in list(bucket.nodes.items()):
                    if node.status == NODE_STATUS_BAD:
                        bucket.nodes.pop(node_id, None)
                        removed.append(node)
            return removed

    def has(self, node_id: bytes) -> bool:
        """
        Check if a node id is known.
        """
        return bool(self.get(node_id))

    def get(self, node_id: bytes) -> Node | None:
        """
        Return a node belonging to an id, if it exists.
        """
        return self.get_bucket(node_id).get(node_id)

    def closest_nodes(self, node_id: bytes, max_nodes: int = 8, exclude_node: Node | None = None) -> list[Node]:
        """
        Return the nodes closes to a node id.
        """
        with self.lock:
            hash_binary = id_to_binary_string(node_id)
            prefix = self.trie.longest_prefix(hash_binary, default='')

            nodes = set()
            for i in reversed(range(len(prefix) + 1)):
                for suffix in self.trie.suffixes(prefix[:i]):
                    bucket = self.trie[prefix[:i] + suffix]
                    nodes |= {node for node in list(bucket.nodes.values())
                              if node.status != NODE_STATUS_BAD and (exclude_node is None
                                                                     or node.id != exclude_node.id)}

                # Limit number of nodes returned
                if len(nodes) > max_nodes:
                    break

            # Ensure nodes are sorted by distance
            return sorted(nodes, key=lambda n: (distance(n.id, node_id), n.status))[:max_nodes]
