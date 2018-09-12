import os
from twisted.internet.defer import inlineCallbacks

from ....attestation.wallet.database import AttestationsDB
from ....attestation.wallet.primitives.attestation import binary_relativity_sha256_4
from ....attestation.wallet.community import Attestation, AttestationCommunity, BonehPrivateKey

from ...base import MockIPv8, TestBase


class TestCommunity(TestBase):

    private_key = BonehPrivateKey.unserialize(("01064c65dcb113f901064228da3ea57101064793a4f9c77901062b083e8690fb0" +
                                               "106408293c67e9f010601d1a9d3744901030f4243").decode('hex'))

    def setUp(self):
        super(TestCommunity, self).setUp()
        self.initialize(AttestationCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", AttestationCommunity, working_directory=u":memory:")

    @inlineCallbacks
    def test_request_attestation_callback(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name, metadata):
            self.assertEqual(peer.address, self.nodes[1].endpoint.wan_address)
            self.assertEqual(attribute_name, "MyAttribute")
            self.assertDictEqual(metadata, {})

            f.called = True
        f.called = False

        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(f)

        self.nodes[1].overlay.request_attestation(self.nodes[0].overlay.my_peer,
                                                  "MyAttribute",
                                                  TestCommunity.private_key)

        yield self.deliver_messages()

        self.assertTrue(f.called)
        # Request for attribute attestation goes unanswered
        self.nodes[1].overlay.request_cache.clear()

    @inlineCallbacks
    def test_request_attestation_callback_metadata(self):
        """
        Check if the request_attestation callback is correctly called with metadata.
        """

        def f(peer, attribute_name, metadata):
            self.assertEqual(peer.address, self.nodes[1].endpoint.wan_address)
            self.assertEqual(attribute_name, "MyAttribute")
            self.assertDictEqual(metadata, {'test': 123})

            f.called = True

        f.called = False

        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(f)

        self.nodes[1].overlay.request_attestation(self.nodes[0].overlay.my_peer,
                                                  "MyAttribute",
                                                  TestCommunity.private_key,
                                                  {'test': 123})

        yield self.deliver_messages()

        self.assertTrue(f.called)
        # Request for attribute attestation goes unanswered
        self.nodes[1].overlay.request_cache.clear()

    @inlineCallbacks
    def test_request_attestation(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name, _, __=None):
            self.assertEqual(peer.address, self.nodes[1].endpoint.wan_address)
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True
        f.called = False

        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(lambda x, y, z: y)
        self.nodes[0].overlay.set_attestation_request_complete_callback(f)

        self.nodes[1].overlay.request_attestation(self.nodes[0].overlay.my_peer,
                                                  "MyAttribute",
                                                  TestCommunity.private_key)

        yield self.deliver_messages(0.5)

        db_entries = self.nodes[1].overlay.database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

    @inlineCallbacks
    def test_verify_attestation(self):
        """
        Check if an attestation can be verified.
        """
        serialized = ""
        filename = os.path.join(os.path.dirname(__file__), 'attestation.txt')
        with open(filename, 'r') as f:
            serialized = f.read().strip().decode('hex')
        attestation = Attestation.unserialize(serialized)
        attestation_hash = '9019195eb75c07ec3e86a62c314dcf5ef2bbcc0d'.decode('hex')
        self.nodes[0].overlay.database.insert_attestation(attestation, TestCommunity.private_key)
        self.nodes[0].overlay.attestation_keys[attestation_hash] = TestCommunity.private_key

        def callback(rhash, values):
            self.assertEqual(attestation_hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True
        callback.called = False
        self.nodes[1].overlay.verify_attestation_values(self.nodes[0].endpoint.wan_address,
                                                        attestation_hash,
                                                        [binary_relativity_sha256_4("MyAttribute")],
                                                        callback)

        yield self.deliver_messages(0.5)

        self.assertTrue(callback.called)
        self.nodes[1].overlay.request_cache.clear()

    def test_load_key(self):
        """
        Check if we can load the community correctly after shut down.
        """
        # Write to a temporary folder.
        overlay = self.nodes[0].overlay
        temp_folder = self.temporary_directory()
        overlay.database = AttestationsDB(temp_folder, "test")

        # Create an attestation and write it to file.
        # Then close the database.
        attestation = Attestation(TestCommunity.private_key.public_key(), [])
        overlay.on_attestation_complete(attestation, TestCommunity.private_key, None, "test", "a"*20)
        overlay.database.close(True)

        # Reload the community with the same database.
        self.nodes[0].overlay.__init__(self.nodes[0].my_peer, self.nodes[0].endpoint, self.nodes[0].network,
                                       working_directory=temp_folder, db_name="test")

        # The attestation should persist
        db_entries = self.nodes[0].overlay.database.get_all()
        self.assertEqual(1, len(db_entries))
