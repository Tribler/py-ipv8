"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
import sys
from asyncio import ensure_future, iscoroutine
from binascii import hexlify
from random import choice, random
from socket import error, gethostbyname
from time import time
from traceback import format_exception

from .lazy_community import EZPackOverlay, lazy_wrapper, lazy_wrapper_unsigned
from .messaging.anonymization.endpoint import TunnelEndpoint
from .messaging.payload import (IntroductionRequestPayload, IntroductionResponsePayload, PuncturePayload,
                                PunctureRequestPayload)
from .messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload

_DEFAULT_ADDRESSES = [
    # Dispersy
    ("130.161.119.206", 6421),
    ("130.161.119.206", 6422),
    ("131.180.27.155", 6423),
    ("131.180.27.156", 6424),
    ("131.180.27.161", 6427),
    # IPv8
    ("131.180.27.161", 6521),
    ("131.180.27.161", 6522),
    ("131.180.27.162", 6523),
    ("131.180.27.162", 6524),
    ("130.161.119.215", 6525),
    ("130.161.119.215", 6526),
    ("81.171.27.194", 6527),
    ("81.171.27.194", 6528)
]


_DNS_ADDRESSES = [
    # Dispersy
    (u"dispersy1.tribler.org", 6421), (u"dispersy1.st.tudelft.nl", 6421),
    (u"dispersy2.tribler.org", 6422), (u"dispersy2.st.tudelft.nl", 6422),
    (u"dispersy3.tribler.org", 6423), (u"dispersy3.st.tudelft.nl", 6423),
    (u"dispersy4.tribler.org", 6424),
    # IPv8
    (u"tracker1.ip-v8.org", 6521),
    (u"tracker2.ip-v8.org", 6522),
    (u"tracker3.ip-v8.org", 6523),
    (u"tracker4.ip-v8.org", 6524),
    (u"tracker5.ip-v8.org", 6525),
    (u"tracker6.ip-v8.org", 6526),
    (u"tracker7.ip-v8.org", 6527),
    (u"tracker8.ip-v8.org", 6528)
]


BOOTSTRAP_TIMEOUT = 30.0  # Timeout before we bootstrap again (bootstrap kills performance)
DEFAULT_MAX_PEERS = 30


class Community(EZPackOverlay):

    version = b'\x02'
    master_peer = ""

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False):
        super(Community, self).__init__(self.master_peer, my_peer, endpoint, network)

        self._prefix = b'\x00' + self.version + self.master_peer.mid
        self.endpoint.remove_listener(self)
        self.endpoint.add_prefix_listener(self, self._prefix)
        self.logger.debug("Launching %s with prefix %s.", self.__class__.__name__, hexlify(self._prefix))

        self.max_peers = max_peers
        self.anonymize = anonymize

        if anonymize:
            if isinstance(self.endpoint, TunnelEndpoint):
                self.endpoint.set_anonymity(self._prefix, True)
            else:
                self.logger.warning('Cannot anonymize community traffic without TunnelEndpoint')

        self.network.register_service_provider(self.master_peer.mid, self)
        self.network.blacklist_mids.append(my_peer.mid)
        self.network.blacklist.extend(_DEFAULT_ADDRESSES)

        self.last_bootstrap = 0

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

    def get_prefix(self):
        return self._prefix

    def add_message_handler(self, msg_num, callback):
        """
        Add a handler for a message identifier. Any messages coming in with this identifier will be delivered to
        the specified callback function.

        :param msg_num: the message id to listen for (or a Payload object with a msg_id field)
        :type msg_num: int or object
        :param callback: the callback function for this message id
        :type callback: function
        :returns: None
        """
        if not isinstance(msg_num, int):
            if not hasattr(msg_num, "msg_id"):
                raise RuntimeError("Attempted to add a handler for Payload %s, which does not specify a msg_id!"
                                   % msg_num)
            msg_num = msg_num.msg_id
        if msg_num < 0 or msg_num > 255:
            raise RuntimeError("Attempted to add a handler for message number %d, which is not a byte!" % msg_num)
        if chr(msg_num) in self.decode_map:
            raise RuntimeError("Attempted to add a handler for message number %d, already mapped to %s!" %
                               (msg_num, self.decode_map[chr(msg_num)]))
        self.decode_map[chr(msg_num)] = callback

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

    def create_introduction_request(self, socket_address, extra_bytes=b''):
        global_time = self.claim_global_time()
        payload = IntroductionRequestPayload(socket_address,
                                             self.my_estimated_lan,
                                             self.my_estimated_wan,
                                             True,
                                             u"unknown",
                                             global_time,
                                             extra_bytes).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 246, [auth, dist, payload])

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b'', prefix=None):
        global_time = self.claim_global_time()
        introduction_lan = ("0.0.0.0", 0)
        introduction_wan = ("0.0.0.0", 0)
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
                                              u"unknown",
                                              False,
                                              identifier,
                                              extra_bytes).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        if introduced:
            packet = self.create_puncture_request(lan_socket_address, socket_address, identifier, prefix=prefix)
            self.endpoint.send(introduction_wan if introduction_lan == ("0.0.0.0", 0) else introduction_lan, packet)

        return self._ez_pack(prefix or self._prefix, 245, [auth, dist, payload])

    def create_puncture(self, lan_walker, wan_walker, identifier):
        global_time = self.claim_global_time()
        payload = PuncturePayload(lan_walker, wan_walker, identifier).to_pack_list()
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin()).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(self._prefix, 249, [auth, dist, payload])

    def create_puncture_request(self, lan_walker, wan_walker, identifier, prefix=None):
        global_time = self.claim_global_time()
        payload = PunctureRequestPayload(lan_walker, wan_walker, identifier).to_pack_list()
        dist = GlobalTimeDistributionPayload(global_time).to_pack_list()

        return self._ez_pack(prefix or self._prefix, 250, [dist, payload], False)

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
        if self.max_peers >= 0 and len(self.get_peers()) > self.max_peers:
            self.logger.info("Dropping introduction request from (%s, %d): too many peers!",
                             peer.address[0], peer.address[1])
            return

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

        packet = self.create_introduction_response(payload.destination_address, peer.address, payload.identifier)
        self.endpoint.send(peer.address, packet)

        self.introduction_request_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionResponsePayload)
    def on_introduction_response(self, peer, dist, payload):
        if not self.address_is_lan(payload.destination_address[0]):
            self.my_estimated_wan = payload.destination_address

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.master_peer.mid, ])

        if (payload.wan_introduction_address != ("0.0.0.0", 0)
                and payload.wan_introduction_address[0] != self.my_estimated_wan[0]):
            if payload.lan_introduction_address != ("0.0.0.0", 0):
                self.network.discover_address(peer, payload.lan_introduction_address, self.master_peer.mid)
            self.network.discover_address(peer, payload.wan_introduction_address, self.master_peer.mid)
        elif (payload.lan_introduction_address != ("0.0.0.0", 0)
              and payload.wan_introduction_address[0] == self.my_estimated_wan[0]):
            self.network.discover_address(peer, payload.lan_introduction_address, self.master_peer.mid)
        elif payload.wan_introduction_address != ("0.0.0.0", 0):
            self.network.discover_address(peer, payload.wan_introduction_address, self.master_peer.mid)
            self.network.discover_address(peer, (self.my_estimated_lan[0], payload.wan_introduction_address[1]),
                                          self.master_peer.mid)

        self.introduction_response_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, PuncturePayload)
    def on_puncture(self, peer, dist, payload):
        pass

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
        msg_id = chr(ord(data[22:23]))
        if msg_id in self.decode_map:
            handler = self.decode_map[msg_id]
            try:
                result = handler(source_address, data)
                if iscoroutine(result):
                    self.register_anonymous_task('on_packet', ensure_future(result), ignore=(Exception,))
            except Exception:
                self.logger.error("Exception occurred while handling packet!\n"
                                  + ''.join(format_exception(*sys.exc_info())))
        elif warn_unknown:
            self.logger.warning("Received unknown message: %d from (%s, %d)", ord(msg_id), *source_address)

    def walk_to(self, address):
        packet = self.create_introduction_request(address)
        self.endpoint.send(address, packet)

    def send_introduction_request(self, peer):
        """
        Send an introduction request to a specific peer.
        """
        packet = self.create_introduction_request(peer.address)
        self.endpoint.send(peer.address, packet)

    def get_new_introduction(self, from_peer=None):
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
        self.endpoint.send(from_peer, packet)

    def get_peer_for_introduction(self, exclude=None):
        """
        Return a random peer to send an introduction request to.
        """
        available = [p for p in self.get_peers() if p != exclude]
        return choice(available) if available else None

    def get_walkable_addresses(self):
        return self.network.get_walkable_addresses(self.master_peer.mid)

    def get_peers(self):
        return self.network.get_peers_for_service(self.master_peer.mid)
