from ipv8.test.base import TestBase
from ipv8.test.mocking.ipv8 import MockIPv8
from ipv8.test.util import twisted_wrapper
from ipv8.xdr.community import XDRCommunity


class TestXDRCommunity(TestBase):

    def setUp(self):
        super(TestXDRCommunity, self).setUp()
        self.initialize(XDRCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", XDRCommunity)

    @twisted_wrapper
    def test_speed_xdr(self):
        yield self.introduce_nodes()

        self.nodes[0].overlay.send_xdr_payload(self.nodes[1].my_peer.address)

        yield self.nodes[1].overlay.xdr_deferred

    @twisted_wrapper
    def test_speed_normal(self):
        yield self.introduce_nodes()

        self.nodes[0].overlay.send_normal_payload(self.nodes[1].my_peer.address)

        yield self.nodes[1].overlay.normal_deferred
