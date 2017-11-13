import os

from ipv8.attestation.wallet.primitives.attestation import binary_relativity_sha512
from ipv8.attestation.wallet.community import Attestation, AttestationCommunity, BonehPrivateKey

from test.base import MockIPv8, TestBase
from test.util import twisted_test


class TestCommunity(TestBase):

    private_key = BonehPrivateKey.unserialize(("01064c65dcb113f901064228da3ea57101064793a4f9c77901062b083e8690fb0" +
                                               "106408293c67e9f010601d1a9d3744901030f4243").decode('hex'))

    def setUp(self):
        super(TestCommunity, self).setUp()
        self.initialize(AttestationCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", AttestationCommunity, working_directory=u":memory:")

    @twisted_test
    def test_request_attestation_callback(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name):
            self.assertEqual(peer.address, self.nodes[1].endpoint.wan_address)
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True
        f.called = False

        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(f)

        self.nodes[1].overlay.request_attestation(self.nodes[0].endpoint.wan_address,
                                                  "MyAttribute",
                                                  TestCommunity.private_key)

        yield self.deliver_messages()

        self.assertTrue(f.called)
        # Request for attribute attestation goes unanswered
        self.nodes[1].overlay.request_cache.clear()

    @twisted_test(4)
    def test_request_attestation(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name, _):
            self.assertEqual(peer.address, self.nodes[1].endpoint.wan_address)
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True
        f.called = False

        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(lambda x, y: y)
        self.nodes[0].overlay.set_attestation_request_complete_callback(f)

        self.nodes[1].overlay.request_attestation(self.nodes[0].endpoint.wan_address,
                                                  "MyAttribute",
                                                  TestCommunity.private_key)

        yield self.deliver_messages(3)

        db_entries = self.nodes[1].overlay.database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

    @twisted_test(4)
    def test_verify_attestation(self):
        """
        Check if an attestation can be verified.
        """
        serialized = ""
        filename = os.path.join(os.path.dirname(__file__), 'attestation.txt')
        with open(filename, 'r') as f:
            serialized = f.read().decode('hex')
        attestation = Attestation.unserialize(serialized)
        hash = '470be47c5076348b497410b3f2741bba7a00d0f1'.decode('hex')
        self.nodes[0].overlay.database.insert_attestation(attestation, TestCommunity.private_key)
        self.nodes[0].overlay.attestation_keys[hash] = TestCommunity.private_key

        def callback(rhash, values):
            self.assertEqual(hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True
        callback.called = False
        self.nodes[1].overlay.verify_attestation_values(self.nodes[0].endpoint.wan_address,
                                                        hash,
                                                        [binary_relativity_sha512("MyAttribute")],
                                                        callback)

        yield self.deliver_messages(3)

        self.assertTrue(callback.called)
        self.nodes[1].overlay.request_cache.clear()
