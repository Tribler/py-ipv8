import os

from ipv8.attestation.wallet.primitives.attestation import binary_relativity_sha512
from ipv8.attestation.wallet.community import Attestation, AttestationCommunity, BonehPrivateKey

from test.base import MockIPv8, TestBase
from test.util import twisted_test


class TestCommunity(TestBase):

    private_key = BonehPrivateKey.unserialize(('0106b5e9e99724e301073bb0c0a5981a7b01071125faddfe03f901070b4ad6668f' +
                                               '4dad010716e5ee49d979f0010702522d2e41f7c201030f4291').decode('hex'))

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

    @twisted_test(4)
    def test_request_attestation(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        yield self.introduce_nodes()

        self.nodes[0].overlay.set_attestation_request_callback(lambda x, y: y)

        self.nodes[1].overlay.request_attestation(self.nodes[0].endpoint.wan_address,
                                                  "MyAttribute",
                                                  TestCommunity.private_key)

        yield self.deliver_messages(3)

        db_entries = self.nodes[1].overlay.database.get_all()
        self.assertEqual(1, len(db_entries))

    @twisted_test(4)
    def test_verify_attestation(self):
        """
        Check if an attestation can be verified.
        """
        serialized = ""
        filename = os.path.join(os.path.dirname(__file__), 'attestation.txt')
        with open(filename, 'rb') as f:
            serialized = f.read()[:-1].decode('hex')
        attestation = Attestation.unserialize(serialized)
        hash = '0927415c9484638c38185dbac8df645404065df5'.decode('hex')
        self.nodes[0].overlay.database.insert_attestation(attestation, TestCommunity.private_key)
        self.nodes[0].overlay.attestation_keys[hash] = TestCommunity.private_key

        def callback(rhash, values):
            self.assertEqual(hash, rhash)
            self.assertListEqual([1.0], values)
            callback.called = True
        callback.called = False
        self.nodes[1].overlay.verify_attestation_values(self.nodes[0].endpoint.wan_address,
                                                        hash,
                                                        [binary_relativity_sha512("MyAttribute", )],
                                                        callback)

        yield self.deliver_messages(3)

        self.assertTrue(callback.called)
