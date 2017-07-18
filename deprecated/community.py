"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from random import choice
from time import time

from keyvault.crypto import ECCrypto
from overlay import Overlay
from peer import Peer
from .payload import IntroductionRequestPayload, IntroductionResponsePayload, PuncturePayload, PunctureRequestPayload
from .payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload


class EZPackOverlay(Overlay):

    def _ez_pack(self, prefix, msg_num, format_list_list, sig=True):
        packet = prefix + chr(msg_num)
        for format_list in format_list_list:
            packet += self.serializer.pack_multiple(format_list)
        if sig:
            packet += ECCrypto().create_signature(self.my_peer.key, packet)
        return packet

    def _verify_signature(self, auth, data):
        ec = ECCrypto()
        public_key = ec.key_from_public_bin(auth.public_key_bin)
        signature_length = ec.get_signature_length(public_key)
        remainder = data[2 + len(auth.public_key_bin):-signature_length]
        signature = data[-signature_length:]
        return ec.is_valid_signature(public_key, remainder, signature), remainder

    def _ez_unpack_auth(self, payload_class, data):
        # UNPACK
        auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data)
        signature_valid, remainder = self._verify_signature(auth, data)
        format = [GlobalTimeDistributionPayload, payload_class]
        dist, payload, unknown_data = self.serializer.unpack_to_serializables(format, remainder)
        # ASSERT
        assert len(unknown_data) == 0, "GOT EXTRA DATA: %s" % repr(unknown_data)
        assert signature_valid
        #print payload
        # PRODUCE
        return auth, dist, payload

    def _ez_unpack_noauth(self, payload_class, data):
        # UNPACK
        format = [GlobalTimeDistributionPayload, payload_class]
        dist, payload, unknown_data = self.serializer.unpack_to_serializables(format, data)
        # ASSERT
        assert len(unknown_data) == 0, "GOT EXTRA DATA: %s" % repr(unknown_data)
        #print payload
        # PRODUCE
        return dist, payload


class Community(EZPackOverlay):

    version = '\x00'
    master_peer = ""

    def __init__(self, my_peer, endpoint, database):
        super(Community, self).__init__(self.master_peer, my_peer, endpoint, database)

        self._prefix = '\x00' + self.version + self.master_peer.key.key_to_hash()

        self.contacted_addresses = []

        self.decode_map = {
            #chr(254): self.on_missing_sequence,
            chr(250): self.on_puncture_request,
            chr(249): self.on_puncture,
            #chr(248): self.on_identity,
            #chr(247): self.on_missing_identity,
            chr(246): self.on_introduction_request,
            chr(245): self.on_introduction_response,
            #chr(239): self.on_missing_message,

            chr(255): self.on_deprecated_message,
            chr(253): self.on_deprecated_message,
            chr(252): self.on_deprecated_message,
            chr(251): self.on_deprecated_message,
            chr(244): self.on_deprecated_message,
            chr(243): self.on_deprecated_message,
            chr(242): self.on_deprecated_message,
            chr(241): self.on_deprecated_message,
            chr(240): self.on_deprecated_message,
            chr(238): self.on_deprecated_message,
            chr(237): self.on_deprecated_message,
            chr(236): self.on_deprecated_message,
            chr(235): self.on_deprecated_message
        }

    def on_deprecated_message(self, source_address, data):
        name_map = {
            chr(255): "reserved-255",
            chr(253): "missing-proof",
            chr(252): "signature-request",
            chr(251): "signature-response",
            chr(244): "destroy-community",
            chr(243): "authorize",
            chr(242): "revoke",
            chr(241): "subjective-set",
            chr(240): "missing-subjective-set",
            chr(238): "undo-own",
            chr(237): "undo-other",
            chr(236): "dynamic-settings",
            chr(235): "missing-last-message"
        }
        self.logger.warning("Received deprecated message: %s from (%s, %d)", name_map[data[22]], *source_address)

    def create_introduction_request(self, socket_address):
        global_time = self.claim_global_time()
        payload = IntroductionRequestPayload(socket_address,
                                             self.my_estimated_lan,
                                             self.my_estimated_wan,
                                             True,
                                             u"unknown",
                                             False,
                                             global_time).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 246, [auth, dist, payload])

    def create_introduction_response(self, lan_socket_address, socket_address, identifier):
        global_time = self.claim_global_time()
        introduction_lan = ("0.0.0.0",0)
        introduction_wan = ("0.0.0.0",0)
        introduced = False
        if self.network.verified_peers:
            introduction = choice(self.network.verified_peers).address
            if self.address_is_lan(introduction[0]):
                introduction_lan = introduction
                introduction_wan = (self.my_estimated_wan[0], introduction_lan[1])
            else:
                introduction_wan = introduction
            introduced = True
        payload = IntroductionResponsePayload(socket_address,
                                              self.my_estimated_lan,
                                              self.my_estimated_wan,
                                              introduction_lan,
                                              introduction_wan,
                                              u"unknown",
                                              False,
                                              identifier).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if introduced:
            packet = self.create_puncture_request(lan_socket_address, socket_address, identifier)
            self.endpoint.send(introduction_wan if introduction_lan == ("0.0.0.0",0) else introduction_lan, packet)

        return self._ez_pack(self._prefix, 245, [auth, dist, payload])

    def create_puncture(self, lan_walker, wan_walker, identifier):
        global_time = self.claim_global_time()
        payload = PuncturePayload(lan_walker, wan_walker, identifier).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 249, [auth, dist, payload])

    def create_puncture_request(self, lan_walker, wan_walker, identifier):
        global_time = self.claim_global_time()
        payload = PunctureRequestPayload(lan_walker, wan_walker, identifier).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 250, [dist, payload], False)

    def on_introduction_request(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(IntroductionRequestPayload, data)

        peer = Peer(auth.public_key_bin, source_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

        packet = self.create_introduction_response(payload.destination_address, source_address, payload.identifier)
        self.endpoint.send(source_address, packet)

    def on_introduction_response(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(IntroductionResponsePayload, data)

        self.my_estimated_wan = payload.destination_address

        peer = Peer(auth.public_key_bin, source_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])
        if (payload.wan_introduction_address != ("0.0.0.0", 0)) and\
                (payload.wan_introduction_address[0] != self.my_estimated_wan[0]):
            self.network.discover_address(Peer(auth.public_key_bin, source_address),
                                          payload.wan_introduction_address)
        else:
            self.network.discover_address(Peer(auth.public_key_bin, source_address),
                                          payload.lan_introduction_address)

    def on_puncture(self, source_address, data):
        auth, dist, payload = self._ez_unpack_auth(PuncturePayload, data)

        peer = Peer(auth.public_key_bin, source_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

    def on_puncture_request(self, source_address, data):
        dist, payload = self._ez_unpack_noauth(PunctureRequestPayload, data)

        target = payload.wan_walker_address
        if payload.wan_walker_address[0] == self.my_estimated_wan[0]:
            target = payload.lan_walker_address

        packet = self.create_puncture(self.my_estimated_lan, payload.wan_walker_address, payload.identifier)
        self.endpoint.send(target, packet)

    def on_packet(self, packet):
        source_address, data = packet
        probable_peer = self.network.get_verified_by_address(source_address)
        if probable_peer:
            probable_peer.last_response = time()
        if self._prefix != data[:22]:
            return
        if data[22] in self.decode_map:
            self.decode_map[data[22]](source_address, data[23:])
        else:
            self.logger.warning("Received unknown message: %s from (%s, %d)", ord(data[22]), *source_address)

    def split_key_data(self, data):
        pass

    def on_data(self, peer, data):
        pass

    def walk_to(self, address):
        packet = self.create_introduction_request(address)
        self.endpoint.send(address, packet)

    def get_new_introduction(self, from_peer=None):
        if not from_peer:
            available = self.network.get_walkable_addresses()
            if available:
                from_peer = choice(available)
            else:
                self.bootstrap()
                return

        packet = self.create_introduction_request(from_peer)
        self.endpoint.send(from_peer, packet)
