from twisted.internet.defer import Deferred

from ipv8.deprecated.payload_headers import GlobalTimeDistributionPayload
from .payload import XDRPayload, NormalPayload
from ..deprecated.community import Community
from ..peer import Peer


class XDRCommunity(Community):

    master_peer = Peer(("3081a7301006072a8648ce3d020106052b810400270381920004009ad2a2e35c328a3e92019873820d70b53b" +
                        "82a752490febbce8bbbe2531a06a165121b8068e674236f26055a59b12c2139445f14dd86c4c3c9598e8c999" +
                        "109f184556dac595f69001b5b16d2c14fe5f641f1a25227152df1989f0c8fb71a107ec55e8e67f464391491c" +
                        "2390bb53fc9b314c7eeb46be1955024ad9e632130e4e92e61295ed1bb1783663fd47fae71293").decode("HEX"))

    def __init__(self, *args, **kwargs):
        super(XDRCommunity, self).__init__(*args, **kwargs)

        self.decode_map.update({
            chr(1): self.received_xdr_payload,
            chr(2): self.received_normal_payload
        })

        self.received_xdr_payloads = 0
        self.received_normal_payloads = 0
        self.xdr_deferred = Deferred()
        self.normal_deferred = Deferred()

    def send_xdr_payload(self, address):
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        payload = XDRPayload().to_pack_list()
        packet = self._ez_pack(self._prefix, 1, [dist, payload], False)
        self.endpoint.send(address, packet)

    def send_normal_payload(self, address):
        global_time = self.claim_global_time()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()
        payload = NormalPayload().to_pack_list()
        packet = self._ez_pack(self._prefix, 2, [dist, payload], False)
        self.endpoint.send(address, packet)

    def received_xdr_payload(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(XDRPayload, data)
        self.received_xdr_payloads += 1
        if self.received_xdr_payloads == 10000:
            self.xdr_deferred.callback(None)
        else:
            self.send_xdr_payload(source_address)

    def received_normal_payload(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(NormalPayload, data)
        self.received_normal_payloads += 1
        if self.received_normal_payloads == 10000:
            self.normal_deferred.callback(None)
        else:
            self.send_normal_payload(source_address)
