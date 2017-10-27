"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from random import choice
import sys
from time import time
from traceback import format_exception

from ..keyvault.crypto import ECCrypto
from ..overlay import Overlay
from ..peer import Peer
from .payload import IntroductionRequestPayload, IntroductionResponsePayload, PuncturePayload, PunctureRequestPayload
from .payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload


class PacketDecodingError(RuntimeError):
    pass


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
        return ec.is_valid_signature(public_key, data[:-signature_length], signature), remainder

    def _ez_unpack_auth(self, payload_class, data):
        # UNPACK
        auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data[23:])
        signature_valid, remainder = self._verify_signature(auth, data)
        format = [GlobalTimeDistributionPayload, payload_class]
        dist, payload, unknown_data = self.serializer.unpack_to_serializables(format, remainder[23:])
        # ASSERT
        if len(unknown_data) != 0:
            raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                      (payload_class.__name__,
                                       data.encode('HEX'),
                                       unknown_data.encode('HEX')))

        if not signature_valid:
            raise PacketDecodingError("Incoming packet %s has an invalid signature" % payload_class.__name__)
        # PRODUCE
        return auth, dist, payload

    def _ez_unpack_noauth(self, payload_class, data):
        # UNPACK
        format = [GlobalTimeDistributionPayload, payload_class]
        dist, payload, unknown_data = self.serializer.unpack_to_serializables(format, data[23:])
        # ASSERT
        if len(unknown_data) != 0:
            raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                      (payload_class.__name__,
                                       data.encode('HEX'),
                                       unknown_data.encode('HEX')))
        # PRODUCE
        return dist, payload


class Community(EZPackOverlay):

    version = '\x00'
    master_peer = ""

    def __init__(self, my_peer, endpoint, network):
        super(Community, self).__init__(self.master_peer, my_peer, endpoint, network)

        self._prefix = '\x00' + self.version + self.master_peer.key.key_to_hash()
        self.network.register_service_provider(self.master_peer.mid, self)

        self.decode_map = {
            chr(250): self.on_puncture_request,
            chr(249): self.on_puncture,
            chr(246): self.on_introduction_request,
            chr(245): self.on_introduction_response,

            chr(255): self.on_deprecated_message,
            chr(254): self.on_deprecated_message,
            chr(253): self.on_deprecated_message,
            chr(252): self.on_deprecated_message,
            chr(251): self.on_deprecated_message,
            chr(248): self.on_deprecated_message,
            chr(247): self.on_deprecated_message,
            chr(244): self.on_deprecated_message,
            chr(243): self.on_deprecated_message,
            chr(242): self.on_deprecated_message,
            chr(241): self.on_deprecated_message,
            chr(240): self.on_deprecated_message,
            chr(239): self.on_deprecated_message,
            chr(238): self.on_deprecated_message,
            chr(237): self.on_deprecated_message,
            chr(236): self.on_deprecated_message,
            chr(235): self.on_deprecated_message
        }

        self.deprecated_message_names = {
            chr(255): "reserved-255",
            chr(254): "on-missing-sequence",
            chr(253): "missing-proof",
            chr(252): "signature-request",
            chr(251): "signature-response",
            chr(248): "on-identity",
            chr(247): "on-missing-identity",
            chr(244): "destroy-community",
            chr(243): "authorize",
            chr(242): "revoke",
            chr(241): "subjective-set",
            chr(240): "missing-subjective-set",
            chr(239): "on-missing-message",
            chr(238): "undo-own",
            chr(237): "undo-other",
            chr(236): "dynamic-settings",
            chr(235): "missing-last-message"
        }

    def on_deprecated_message(self, source_address, data):
        self.logger.warning("Received deprecated message: %s from (%s, %d)",
                            self.deprecated_message_names[data[22]], *source_address)

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
        other = self.network.get_verified_by_address(socket_address)
        available = [p for p in self.network.verified_peers if p != other]
        if available:
            introduction = choice(available).address
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
        elif (payload.lan_introduction_address != ("0.0.0.0", 0)):
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

    def on_packet(self, packet, warn_unknown=True):
        source_address, data = packet
        probable_peer = self.network.get_verified_by_address(source_address)
        if probable_peer:
            probable_peer.last_response = time()
        if self._prefix != data[:22]:
            return
        if data[22] in self.decode_map:
            try:
                self.decode_map[data[22]](source_address, data)
            except:
                self.logger.error("Exception occurred while handling packet!\n" +
                                  ''.join(format_exception(*sys.exc_info())))
        elif warn_unknown:
            self.logger.warning("Received unknown message: %s from (%s, %d)", ord(data[22]), *source_address)

    def walk_to(self, address):
        packet = self.create_introduction_request(address)
        self.endpoint.send(address, packet)

    def get_new_introduction(self, from_peer=None, service_id=None):
        if not from_peer:
            available = self.network.verified_peers
            if available:
                from_peer = choice(available).address
            else:
                self.bootstrap()
                return

        packet = self.create_introduction_request(from_peer)

        if service_id:
            packet = packet[:2] + service_id + packet[23:]

        self.endpoint.send(from_peer, packet)
