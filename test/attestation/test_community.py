from attestation.trustchain.community import TrustChainCommunity
from test.base import TestBase
from test.mocking.ipv8 import MockIPv8
from test.util import twisted_test


class TestTrustChainCommunity(TestBase):

    def setUp(self):
        super(TestTrustChainCommunity, self).setUp()
        self.initialize(TrustChainCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", TrustChainCommunity, working_directory=u":memory:")

    @twisted_test
    def test_sign_block(self):
        yield self.introduce_nodes()

        his_pubkey = self.nodes[0].network.verified_peers[0].public_key.key_to_bin()
        self.nodes[0].overlay.sign_block(self.nodes[0].network.verified_peers[0], public_key=his_pubkey,
                                         transaction={})

        yield self.deliver_messages()

        my_pubkey = self.nodes[0].my_peer.public_key.key_to_bin()

        self.assertIsNotNone(self.nodes[0].overlay.persistence.get(my_pubkey, 1))
        self.assertIsNotNone(self.nodes[1].overlay.persistence.get(my_pubkey, 1))
