from __future__ import absolute_import

from base64 import b64decode, b64encode
from collections import deque
from hashlib import sha1

from twisted.internet.defer import inlineCallbacks

from .rest_peer_communication import HTTPGetRequesterDHT
from ...attestation.trustchain.test_block import TestBlock
from ...mocking.rest.base import RESTTestBase
from ...mocking.rest.comunities import TestDHTCommunity, TestTrustchainCommunity
from ...mocking.rest.rest_api_peer import RestTestPeer
from ...mocking.rest.rest_peer_communication import string_to_url
from ....REST.dht_endpoint import DHTBlockEndpoint
from ....attestation.trustchain.community import TrustChainCommunity
from ....attestation.trustchain.payload import DHTBlockPayload, HalfBlockPayload
from ....dht.community import DHTCommunity
from ....messaging.serialization import Serializer


class TestDHTEndpoint(RESTTestBase):
    """
    Class for testing the DHT Endpoint in the REST API of the IPv8 object
    """

    def setUp(self):
        super(TestDHTEndpoint, self).setUp()
        self.initialize_configurations([(2, RestTestPeer)], HTTPGetRequesterDHT(), None)
        self.serializer = Serializer()

    def create_new_peer(self, peer_cls, port, *args, **kwargs):
        self._create_new_peer_inner(peer_cls, port, [TestDHTCommunity, TestTrustchainCommunity], *args, **kwargs)

    @inlineCallbacks
    def publish_to_DHT(self, peer, key, data, numeric_version, omit_last_chunk=False):
        """
        Publish data to the DHT via a peer.

        :param peer: the peer via which the data is published to the DHT
        :param key: the key of the added data
        :param data: the data itself; should be a string
        :param numeric_version: the version of the data
        :param omit_last_chunk: boolean which indicates whether the last chunk of the block should not be published
        :return: None
        """
        my_private_key = peer.get_keys()['my_peer'].key

        # Get the total number of chunks in this blocks
        total_chunks = len(data) // DHTBlockEndpoint.CHUNK_SIZE
        total_chunks += 1 if len(data) % DHTBlockEndpoint.CHUNK_SIZE != 0 else 0
        published_chunks = total_chunks if not omit_last_chunk else (total_chunks - 1)

        # To make this faster we'll use addition instead of multiplication, and use a pointer
        slice_pointer = 0

        for i in range(published_chunks):
            chunk = data[slice_pointer: slice_pointer + DHTBlockEndpoint.CHUNK_SIZE]
            slice_pointer += DHTBlockEndpoint.CHUNK_SIZE
            pre_signed_content = self.serializer.pack_multiple([('H', numeric_version), ('H', i), ('H', total_chunks),
                                                                ('raw', chunk)])[0]
            signature = my_private_key.signature(pre_signed_content)

            blob_chunk = self.serializer.pack_multiple(DHTBlockPayload(signature, numeric_version, i, total_chunks,
                                                                       chunk).to_pack_list())
            yield peer.get_overlay_by_class(DHTCommunity).store_value(key, blob_chunk[0])

    def deserialize_payload(self, serializables, data):
        """
        Deserialize data.

        :param serializables: the list of serializable formats
        :param data: the serialized data
        :return: The payload obtained from deserializing the data
        """
        payload = self.serializer.unpack_to_serializables(serializables, data)
        return payload[:-1][0]

    def _increase_request_limit(self, new_request_limit):
        for node in self.nodes:
            routing_table = node.get_overlay_by_class(DHTCommunity).routing_table
            for other in routing_table.closest_nodes(routing_table.my_node_id):
                if other != node:
                    routing_table.get(other.id).last_queries = deque(maxlen=new_request_limit)

    @inlineCallbacks
    def test_added_block_explicit(self):
        """
        Test the publication of a block which has been added by hand to the DHT.
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        # Manually add a block to the Trustchain
        original_block = TestBlock()
        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        yield self.publish_to_DHT(self.nodes[0], hash_key, original_block.pack(), 4536)

        # Get the block through the REST API
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue('block' in response and response['block'], "Response is not as expected: %s" % response)
        response = b64decode(response['block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).get_block_class(payload.type) \
            .from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, original_block, "The received block was not the one which was expected")

    @inlineCallbacks
    def test_added_block_implicit(self):
        """
        Test the publication of a block which has been added implicitly to the DHT
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        publisher_pk = self.nodes[0].get_overlay_by_class(TrustChainCommunity).my_peer.public_key.key_to_bin()

        yield self.nodes[0].get_overlay_by_class(TrustChainCommunity).create_source_block(b'test', {})
        original_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).persistence.get(publisher_pk, 1)
        yield self.deliver_messages()
        yield self.sleep()

        # Get the block through the REST API
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue('block' in response and response['block'], "Response is not as expected: %s" % response)
        response = b64decode(response['block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).get_block_class(payload.type) \
            .from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, original_block, "The received block was not the one which was expected")

    @inlineCallbacks
    def test_latest_block(self):
        """
        Test the retrieval of the latest block via the DHT, when there is
        more than one block in the DHT under the same key
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes and increase the size of the request queues
        yield self.introduce_nodes(DHTCommunity)
        self._increase_request_limit(20)

        # Manually add a block to the Trustchain
        original_block_1 = TestBlock(transaction={1: 'asd'})
        original_block_2 = TestBlock(transaction={1: 'mmm'})
        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        # Publish the two blocks under the same key in the first peer
        yield self.publish_to_DHT(self.nodes[0], hash_key, original_block_1.pack(), 4536)
        yield self.publish_to_DHT(self.nodes[0], hash_key, original_block_2.pack(), 7636)

        # Get the block through the REST API from the second peer
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue('block' in response and response['block'], "Response is not as expected: %s" % response)
        response = b64decode(response['block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).get_block_class(
            payload.type).from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, original_block_2, "The received block was not equal to the latest block")
        self.assertNotEqual(reconstructed_block, original_block_1, "The received block was equal to the older block")

    @inlineCallbacks
    def test_block_duplication_explicit(self):
        """
        Test that a block which has already been published in the DHT (explicitly) will not be republished again;
        i.e. no duplicate blocks in the DHT under different (embedded) versions.
        """
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        # Manually create and add a block to the TrustChain
        original_block = TestBlock(key=self.nodes[0].get_keys()['my_peer'].key)
        self.nodes[0].get_overlay_by_class(TrustChainCommunity).persistence.add_block(original_block)

        # Publish the node to the DHT
        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertEqual(result, [], "There shouldn't be any blocks for this key")

        yield self.publish_to_DHT(self.nodes[0], hash_key, original_block.pack(), 4536)

        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertNotEqual(result, [], "There should be at least one chunk for this key")

        chunk_number = len(result)

        # Force call the method which publishes the latest block to the DHT and check that it did not affect the DHT
        self.nodes[0].get_overlay_by_class(TrustChainCommunity) \
            .notify_listeners(TestBlock(TrustChainCommunity.UNIVERSAL_BLOCK_LISTENER))
        yield self.deliver_messages()
        yield self.sleep()

        # Query the DHT again
        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertEqual(len(result), chunk_number, "The contents of the DHT have been changed. This should not happen")

    @inlineCallbacks
    def test_block_duplication_implicit(self):
        """
        Test that a block which has already been published in the DHT (implicitly) will not be republished again;
        i.e. no duplicate blocks in the DHT under different (embedded) versions.
        """
        # Introduce the nodes
        yield self.introduce_nodes(DHTCommunity)

        # Publish the node to the DHT
        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertEqual(result, [], "There shouldn't be any blocks for this key")

        # Create a source block, and implicitly disseminate it
        yield self.nodes[0].get_overlay_by_class(TrustChainCommunity).create_source_block(b'test', {})
        yield self.deliver_messages()
        yield self.sleep()

        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertNotEqual(result, [], "There should be at least one chunk for this key")

        chunk_number = len(result)

        # Force call the method which publishes the latest block to the DHT and check that it did not affect the DHT
        self.nodes[0].get_overlay_by_class(TrustChainCommunity) \
            .notify_listeners(TestBlock(TrustChainCommunity.UNIVERSAL_BLOCK_LISTENER))
        yield self.deliver_messages()
        yield self.sleep()

        # Query the DHT again
        result = yield self.nodes[1].get_overlay_by_class(DHTCommunity).find_values(hash_key)
        self.assertEqual(len(result), chunk_number, "The contents of the DHT have been changed. This should not happen")

    @inlineCallbacks
    def test_many_blocks(self):
        """
        Test the retrieval of large blocks, which do not fit into one DHT query frame. It should be noted that the
        test does not actually retrieve the latest absolute block. It only tries to fetch the greatest block it has
        heard of via its queries. Hence, it will not work past 9 blocks, as this is the limit after which it does
        not hear about any new nodes.
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }

        # Introduce the nodes and increase the size of the request queues
        yield self.introduce_nodes(DHTCommunity)
        self._increase_request_limit(100)

        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        # Create some blocks
        block_array = [(i, TestBlock(transaction={1: 'asd{}'.format(i)})) for i in range(5, 0, -1)]

        # Publish the blocks, such that the latest block is last
        for version, block in block_array:
            yield self.publish_to_DHT(self.nodes[0], hash_key, block.pack(), version)

        # Get the block through the REST API from the second peer
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue('block' in response and response['block'], "Response is not as expected: %s" % response)
        response = b64decode(response['block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).get_block_class(
            payload.type).from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, block_array[0][1], "The received block was not equal to the latest block")

    @inlineCallbacks
    def test_many_blocks_with_single_omission(self):
        """
        Test the retrieval of large blocks when the latest block is incomplete.
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes and increase the size of the request queues
        yield self.introduce_nodes(DHTCommunity)

        self._increase_request_limit(100)

        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        # Create some blocks
        block_array = [(i, TestBlock(transaction={1: 'asd{}'.format(i)})) for i in range(5, 0, -1)]

        # Publish the blocks, such that the latest block is last
        yield self.publish_to_DHT(self.nodes[0], hash_key, block_array[0][1].pack(), block_array[0][0],
                                  omit_last_chunk=True)
        block_array.pop(0)
        for version, block in block_array:
            yield self.publish_to_DHT(self.nodes[0], hash_key, block.pack(), version)

        # Get the block through the REST API from the second peer
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertTrue('block' in response and response['block'], "Response is not as expected: %s" % response)
        response = b64decode(response['block'])

        # Reconstruct the block from what was received in the response
        payload = self.deserialize_payload((HalfBlockPayload,), response)
        reconstructed_block = self.nodes[0].get_overlay_by_class(TrustChainCommunity).get_block_class(
            payload.type).from_payload(payload, self.serializer)

        self.assertEqual(reconstructed_block, block_array[0][1], "The received block was not equal to the latest block")

    @inlineCallbacks
    def test_non_existent_block(self):
        """
        Test the block retrieval operation when the block in question does not exist.
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes and increase the size of the request queues
        yield self.introduce_nodes(DHTCommunity)

        # Get the block through the REST API from the second peer
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertEqual(response.get('error', {'message': ''}).get('message', ''),
                         'Could not find any blocks for the specified key.',
                         "The returned error is not as expected.")

    @inlineCallbacks
    def test_many_blocks_with_omissions(self):
        """
        Test the retrieval of large blocks when all the blocks are incomplete.
        """
        param_dict = {
            'port': self.nodes[1].port,
            'interface': self.nodes[1].interface,
            'endpoint': 'dht/block',
            'public_key': string_to_url(b64encode(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()))
        }
        # Introduce the nodes and increase the size of the request queues
        yield self.introduce_nodes(DHTCommunity)

        self._increase_request_limit(100)

        hash_key = sha1(self.nodes[0].get_keys()['my_peer'].public_key.key_to_bin()
                        + DHTBlockEndpoint.KEY_SUFFIX).digest()

        # Create some blocks and publish them
        block_array = [(i, TestBlock(transaction={1: 'asd{}'.format(i)})) for i in range(5, 0, -1)]

        block_array.pop(0)
        for version, block in block_array:
            yield self.publish_to_DHT(self.nodes[0], hash_key, block.pack(), version, omit_last_chunk=True)

        # Get the block through the REST API from the second peer
        response = yield self._get_style_requests.make_dht_block(param_dict)
        self.assertEqual(response.get('error', {'message': ''}).get('message', ''),
                         'Could not reconstruct any block successfully.',
                         "The returned error is not as expected.")
