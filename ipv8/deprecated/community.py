"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from random import choice, random
from socket import error, gethostbyname
import sys
from time import time
from traceback import format_exception

from ..keyvault.crypto import ECCrypto
from ..overlay import Overlay
from ..peer import Peer
from .payload import IntroductionRequestPayload, IntroductionResponsePayload, PuncturePayload, PunctureRequestPayload
from .payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload


_DEFAULT_ADDRESSES = [
    ("130.161.119.206", 6421),
    ("130.161.119.206", 6422),
    ("131.180.27.155", 6423),
    ("83.149.70.6", 6424),
    ("95.211.155.142", 6427),
    ("95.211.155.131", 6428),
]


_DNS_ADDRESSES = [
    ("dispersy1.tribler.org", 6421),
    ("dispersy2.tribler.org", 6422),
    ("dispersy3.tribler.org", 6423),
    ("dispersy4.tribler.org", 6424),
    ("dispersy7.tribler.org", 6427),
    ("dispersy8.tribler.org", 6428),
    ("dispersy1.st.tudelft.nl", 6421),
    ("dispersy2.st.tudelft.nl", 6422),
    ("dispersy3.st.tudelft.nl", 6423)
]


BOOTSTRAP_TIMEOUT = 30.0 # Timeout before we bootstrap again (bootstrap kills performance)


def lazy_wrapper(*payloads):
    """
    This function wrapper will unpack the BinMemberAuthenticationPayload for you.

    You can now write your authenticated and signed functions as follows:

    ::

        @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(peer, payload1, payload2):
            '''
            :type peer: Peer
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):
            # UNPACK
            auth, remainder = self.serializer.unpack_to_serializables([BinMemberAuthenticationPayload, ], data[23:])
            signature_valid, remainder = self._verify_signature(auth, data)
            unpacked = self.serializer.unpack_to_serializables(payloads, remainder[23:])
            output, unknown_data = unpacked[:-1], unpacked[-1]
            # ASSERT
            if len(unknown_data) != 0:
                raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                          (str([payload_class.__name__ for payload_class in payloads]),
                                           data.encode('HEX'),
                                           unknown_data.encode('HEX')))

            if not signature_valid:
                raise PacketDecodingError("Incoming packet %s has an invalid signature" % \
                                          str([payload_class.__name__ for payload_class in payloads]))
            # PRODUCE
            return func(self, Peer(auth.public_key_bin, source_address), *output)
        return wrapper
    return decorator


def lazy_wrapper_unsigned(*payloads):
    """
    This function wrapper will unpack just the normal payloads for you.

    You can now write your non-authenticated and signed functions as follows:

    ::

        @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload, IntroductionResponsePayload)
        def on_message(source_address, payload1, payload2):
            '''
            :type source_address: str
            :type payload1: IntroductionRequestPayload
            :type payload2: IntroductionResponsePayload
            '''
            pass
    """
    def decorator(func):
        def wrapper(self, source_address, data):
            # UNPACK
            unpacked = self.serializer.unpack_to_serializables(payloads, data[23:])
            output, unknown_data = unpacked[:-1], unpacked[-1]
            # ASSERT
            if len(unknown_data) != 0:
                raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                          (str([payload_class.__name__ for payload_class in payloads]),
                                           data.encode('HEX'),
                                           unknown_data.encode('HEX')))

            # PRODUCE
            return func(self, source_address, *output)
        return wrapper
    return decorator


class PacketDecodingError(RuntimeError):
    pass


class EZPackOverlay(Overlay):

    def _ez_pack(self, prefix, msg_num, format_list_list, sig=True):
        packet = prefix + bytes([msg_num])
        for format_list in format_list_list:
            packet += self.serializer.pack_multiple(format_list)[0]
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

    def _ez_unpack_noauth(self, payload_class, data, global_time=True):
        # UNPACK
        format = [GlobalTimeDistributionPayload, payload_class] if global_time else [payload_class]
        unpacked = self.serializer.unpack_to_serializables(format, data[23:])
        unknown_data = unpacked.pop()
        # ASSERT
        if len(unknown_data) != 0:
            raise PacketDecodingError("Incoming packet %s (%s) has extra data: (%s)" %
                                      (payload_class.__name__,
                                       data.encode('HEX'),
                                       unknown_data.encode('HEX')))
        # PRODUCE
        return unpacked if global_time else unpacked[0]



class Community(EZPackOverlay):

    version = b'\x02'
    master_peer = ""

    def __init__(self, my_peer, endpoint, network):
        super(Community, self).__init__(self.master_peer, my_peer, endpoint, network)

        self._prefix = b'\x00' + self.version + self.master_peer.key.key_to_hash()
        self.logger.debug("Launching %s with prefix %s.", self.__class__.__name__, self._prefix.hex())
        self.network.register_service_provider(self.master_peer.mid, self)
        self.network.blacklist_mids.append(my_peer.mid)
        self.network.blacklist.extend(_DEFAULT_ADDRESSES)

        self.last_bootstrap = 0

        self.decode_map = {
            250: self.on_puncture_request,
            249: self.on_puncture,
            246: self.on_introduction_request,
            245: self.on_introduction_response,

            255: self.on_deprecated_message,
            254: self.on_deprecated_message,
            253: self.on_deprecated_message,
            252: self.on_deprecated_message,
            251: self.on_deprecated_message,
            248: self.on_deprecated_message,
            247: self.on_deprecated_message,
            244: self.on_deprecated_message,
            243: self.on_deprecated_message,
            242: self.on_deprecated_message,
            241: self.on_deprecated_message,
            240: self.on_deprecated_message,
            239: self.on_deprecated_message,
            238: self.on_deprecated_message,
            237: self.on_deprecated_message,
            236: self.on_deprecated_message,
            235: self.on_deprecated_message
        }

        self.deprecated_message_names = {
            255: "reserved-255",
            254: "on-missing-sequence",
            253: "missing-proof",
            252: "signature-request",
            251: "signature-response",
            248: "on-identity",
            247: "on-missing-identity",
            244: "destroy-community",
            243: "authorize",
            242: "revoke",
            241: "subjective-set",
            240: "missing-subjective-set",
            239: "on-missing-message",
            238: "undo-own",
            237: "undo-other",
            236: "dynamic-settings",
            235: "missing-last-message"
        }

    def on_deprecated_message(self, source_address, data):
        self.logger.warning("Received deprecated message: %s from (%s, %d)",
                            self.deprecated_message_names[data[22]], *source_address)

    def bootstrap(self):
        if time() - self.last_bootstrap < BOOTSTRAP_TIMEOUT:
            return
        self.logger.debug("Bootstrapping %s, current peers %d", self.__class__.__name__, len(self.get_peers()))
        self.last_bootstrap = time()
        for socket_address in _DEFAULT_ADDRESSES:
            self.walk_to(socket_address)

    def resolve_dns_bootstrap_addresses(self):
        for (address, port) in _DNS_ADDRESSES:
            try:
                _DEFAULT_ADDRESSES.append((gethostbyname(address), port))
            except error:
                self.logger.info("Unable to resolve (%s, %d)", address, port)

    def create_introduction_request(self, socket_address, extra_bytes=''):
        global_time = self.claim_global_time()
        payload = IntroductionRequestPayload(socket_address,
                                             self.my_estimated_lan,
                                             self.my_estimated_wan,
                                             True,
                                             "unknown",
                                             global_time,
                                             extra_bytes).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 246, [auth, dist, payload])

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=''):
        global_time = self.claim_global_time()
        introduction_lan = ("0.0.0.0",0)
        introduction_wan = ("0.0.0.0",0)
        introduced = False
        other = self.network.get_verified_by_address(socket_address)
        if not introduction:
            introduction = self.get_peer_for_introduction(exclude=other)
        if introduction:
            if self.address_is_lan(introduction.address[0]):
                introduction_lan = introduction.address
                introduction_wan = (self.my_estimated_wan[0], introduction_lan[1])
            else:
                introduction_wan = introduction.address
            introduced = True
        payload = IntroductionResponsePayload(socket_address,
                                              self.my_estimated_lan,
                                              self.my_estimated_wan,
                                              introduction_lan,
                                              introduction_wan,
                                              "unknown",
                                              False,
                                              identifier,
                                              extra_bytes).to_pack_list()
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

    def introduction_request_callback(self, peer, dist, payload):
        """
        Callback that gets called after an introduction-request has been processed.
        If you want to some action to trigger upon receipt of an introduction-request,
        this would be the place to do so.

        :param peer the peer that send us an introduction-request
        :param dist the GlobalTimeDistributionPayload
        :param payload the IntroductionRequestPayload
        """
        pass

    def introduction_response_callback(self, peer, dist, payload):
        """
        Callback that gets called after an introduction-response has been processed.
        If you want to some action to trigger upon receipt of an introduction-response,
        this would be the place to do so.

        :param peer the peer that send us an introduction-response
        :param dist the GlobalTimeDistributionPayload
        :param payload the IntroductionResponsePayload
        """
        pass

    @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload)
    def on_introduction_request(self, peer, dist, payload):
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

        packet = self.create_introduction_response(payload.destination_address, peer.address, payload.identifier)
        self.endpoint.send(peer.address, packet)

        self.introduction_request_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionResponsePayload)
    def on_introduction_response(self, peer, dist, payload):
        self.my_estimated_wan = payload.destination_address

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])
        if (payload.wan_introduction_address != ("0.0.0.0", 0)) and \
                (payload.wan_introduction_address[0] != self.my_estimated_wan[0]):
            self.network.discover_address(peer, payload.wan_introduction_address)
        elif payload.lan_introduction_address != ("0.0.0.0", 0):
            self.network.discover_address(peer, payload.lan_introduction_address)

        self.introduction_response_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, PuncturePayload)
    def on_puncture(self, peer, _, __):
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PunctureRequestPayload)
    def on_puncture_request(self, source_address, dist, payload):
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
            self.logger.warning("Received unknown message: %s from (%s, %d)", data[22], *source_address)

    def walk_to(self, address):
        packet = self.create_introduction_request(address)
        self.endpoint.send(address, packet)

    def send_introduction_request(self, peer, service_id=None):
        """
        Send an introduction request to a specific peer.
        """
        packet = self.create_introduction_request(peer.address)

        if service_id:
            packet = packet[:2] + service_id + packet[22:]

        self.endpoint.send(peer.address, packet)

    def get_new_introduction(self, from_peer=None, service_id=None):
        """
        Get a new introduction, or bootstrap if there are no available peers.
        """
        if not from_peer:
            available = self.get_peers()
            if available:
                # With a small chance, try to remedy any disconnected network phenomena.
                if _DEFAULT_ADDRESSES and random() < 0.05:
                    from_peer = choice(_DEFAULT_ADDRESSES)
                else:
                    from_peer = choice(available).address
            else:
                self.bootstrap()
                return

        packet = self.create_introduction_request(from_peer)

        if service_id:
            packet = packet[:2] + service_id + packet[22:]

        self.endpoint.send(from_peer, packet)

    def get_peer_for_introduction(self, exclude=None):
        """
        Return a random peer to send an introduction request to.
        """
        available = [p for p in self.get_peers() if p != exclude]
        return choice(available) if available else None

    def get_peers(self):
        return self.network.get_peers_for_service(self.master_peer.key.key_to_hash())
