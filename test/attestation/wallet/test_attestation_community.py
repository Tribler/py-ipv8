from ipv8.attestation.wallet.community import AttestationCommunity, BonehPrivateKey

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
