import binascii
import random
import time
from collections import deque
from socket import inet_aton
from threading import RLock

from .trie import Trie
from ..peer import Peer

# By default we allow a maximum number of 10 queries during a 5s interval.
# Additional queries will be dropped.
NODE_LIMIT_INTERVAL = 5
NODE_LIMIT_QUERIES = 10

NODE_STATUS_GOOD = 2
NODE_STATUS_UNKNOWN = 1
NODE_STATUS_BAD = 0

MAX_BUCKET_SIZE = 8


def id_to_binary_string(node_id):
    return format(int(binascii.hexlify(node_id), 16), '0160b')


def distance(a, b):
    return int(binascii.hexlify(a), 16) ^ int(binascii.hexlify(b), 16)


def calc_node_id(ip, mid):
    # Loosely based on the Bittorrent DHT (https://libtorrent.org/dht_sec.html), the node id is calculated as follows:
    # first 3 bytes of crc32c(ip & 0x030f3fff) + first 17 bytes of sha1(public_key)
    ip_bin = inet_aton(ip)
    ip_mask = b'\x03\x0f\x3f\0xff'
    ip_masked = bytes([ip_bin[i] & ip_mask[i] for i in range(4)])

    crc32_unsigned = binascii.crc32(ip_masked) % (2 ** 32)
    crc32_bin = binascii.unhexlify('%08x' % crc32_unsigned)

    return crc32_bin[:3] + mid[:17]


class Node(Peer):
    """
    The Node class represents a peer within the DHT community
    """

    def __init__(self, *args, **kwargs):
        super(Node, self).__init__(*args, **kwargs)
        self.bucket = None
        self.last_response = 0
        self.last_queries = deque(maxlen=NODE_LIMIT_QUERIES)
        self.last_ping_sent = 0
        self.failed = 0
        self.rtt = 0

    @property
    def id(self):
        return calc_node_id(self.address[0], self.mid)

    @property
    def last_contact(self):
        return max(self.last_response, self.last_query)

    @property
    def last_query(self):
        return self.last_queries[-1] if self.last_queries else 0

    @property
    def blocked(self):
        if len(self.last_queries) < self.last_queries.maxlen:
            return False
        return time.time() - self.last_queries[0] < NODE_LIMIT_INTERVAL

    @property
    def status(self):
        # A good node is a node has responded to one of our queries within the last 15 minutes, or has ever responded
        # to one of our queries and has sent us a query within the last 15 minutes. This is the same logic as
        # used in BEP-5
        now = time.time()
        if self.failed >= 2:
            return NODE_STATUS_BAD
        elif ((now - self.last_response) < 15 * 60) or (self.last_response > 0 and (now - self.last_query) < 15 * 60):
            return NODE_STATUS_GOOD
        return NODE_STATUS_UNKNOWN

    def distance(self, other_node):
        return distance(self.id, other_node.id if isinstance(other_node, Node) else other_node)


class Bucket(object):
    """
    The Bucket class stores nodes that share common prefix ID.
    """

    def __init__(self, prefix_id, max_size=MAX_BUCKET_SIZE):
        self.nodes = {}
        self.prefix_id = prefix_id
        self.max_size = max_size
        self.last_changed = 0

    def generate_id(self):
        rand_node_id_bin = format(random.randint(0, 2 ** (160 - len(self.prefix_id))), '0160b')
        return binascii.unhexlify(format(int(rand_node_id_bin, 2), '040X'))

    def owns(self, node_id):
        node_id_binary = id_to_binary_string(node_id)
        return node_id_binary.startswith(self.prefix_id)

    def get(self, node_id):
        return self.nodes.get(node_id)

    def add(self, node):
        # Is this node allowed to be in this bucket?
        if not self.owns(node.id):
            return False

        # Update existing node
        elif node.id in self.nodes:
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

    def split(self):
        if len(self.nodes) < self.max_size:
            return False

        b_0 = Bucket(self.prefix_id + '0', self.max_size)
        b_1 = Bucket(self.prefix_id + '1', self.max_size)
        for node in list(self.nodes.values()):
            if b_0.owns(node.id):
                b_0.add(node)
            elif b_1.owns(node.id):
                b_1.add(node)
            else:
                import logging
                logging.error('Failed to place node into bucket while splitting')
        return b_0, b_1


class RoutingTable(object):
    """
    The RoutingTable is a binary tree that keeps track of Nodes that we have a connection to.
    """

    def __init__(self, my_node_id):
        self.my_node_id = my_node_id
        self.trie = Trie('01')
        self.trie[''] = Bucket('')
        self.lock = RLock()

    def get_bucket(self, node_id):
        node_id_binary = id_to_binary_string(node_id)
        return self.trie.longest_prefix_value(node_id_binary, default=None) or self.trie['']

    def add(self, node):
        with self.lock:
            bucket = self.get_bucket(node.id)

            # Add/update node
            if not bucket.add(node):
                # If adding the node failed, split the bucket
                # Splitting is only allowed if our own node_id falls within this bucket
                if bucket.owns(self.my_node_id):
                    bucket_0, bucket_1 = bucket.split()
                    self.trie[bucket.prefix_id + '0'] = bucket_0
                    self.trie[bucket.prefix_id + '1'] = bucket_1
                    del self.trie[bucket.prefix_id]

                    # Retry
                    return self.add(node)
            else:
                return bucket.get(node.id)

    def remove_bad_nodes(self):
        with self.lock:
            removed = []
            for bucket in self.trie.values():
                for node_id, node in list(bucket.nodes.items()):
                    if node.status == NODE_STATUS_BAD:
                        bucket.nodes.pop(node_id, None)
                        removed.append(node)
            return removed

    def has(self, node_id):
        return bool(self.get(node_id))

    def get(self, node_id):
        return self.get_bucket(node_id).get(node_id)

    def closest_nodes(self, node_id, max_nodes=8, exclude_node=None):
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
