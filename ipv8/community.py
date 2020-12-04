"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
import logging
import sys
from asyncio import ensure_future, iscoroutine
from binascii import hexlify
from random import choice, random
from socket import error, gethostbyname
from threading import Thread
from time import time
from traceback import format_exception

from .lazy_community import EZPackOverlay, lazy_wrapper, lazy_wrapper_unsigned
from .messaging.anonymization.endpoint import TunnelEndpoint
from .messaging.interfaces.dispatcher.endpoint import FAST_ADDR_TO_INTERFACE, INTERFACES
from .messaging.interfaces.udp.endpoint import UDPv4Address, UDPv4LANAddress, UDPv6Address
from .messaging.payload import (IntroductionRequestPayload, IntroductionResponsePayload,
                                NewIntroductionRequestPayload, NewIntroductionResponsePayload,
                                NewPuncturePayload, NewPunctureRequestPayload,
                                PuncturePayload, PunctureRequestPayload)
from .messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .peer import Peer

_DEFAULT_ADDRESSES = [
    # Dispersy
    UDPv4Address("130.161.119.206", 6421),
    UDPv4Address("130.161.119.206", 6422),
    UDPv4Address("131.180.27.155", 6423),
    UDPv4Address("131.180.27.156", 6424),
    UDPv4Address("131.180.27.161", 6427),
    # IPv8
    UDPv4Address("131.180.27.161", 6521),
    UDPv4Address("131.180.27.161", 6522),
    UDPv4Address("131.180.27.162", 6523),
    UDPv4Address("131.180.27.162", 6524),
    UDPv4Address("130.161.119.215", 6525),
    UDPv4Address("130.161.119.215", 6526),
    UDPv4Address("130.161.119.201", 6527),
    UDPv4Address("130.161.119.201", 6528)
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


_UNUSED_FLAGS_REQ = {'flag0': 0, 'flag1': 0, 'flag2': 0, 'flag3': 0, 'flag4': 0, 'flag5': 0, 'flag6': 0, 'flag7': 0}
_UNUSED_FLAGS_RESP = {'flag1': 0, 'flag2': 0, 'flag3': 0, 'flag4': 0, 'flag5': 0, 'flag6': 0, 'flag7': 0}


BOOTSTRAP_TIMEOUT = 30.0  # Timeout before we bootstrap again (bootstrap kills performance)
DEFAULT_MAX_PEERS = 30


class Community(EZPackOverlay):

    version = b'\x02'
    community_id = b''

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False):
        super().__init__(self.community_id, my_peer, endpoint, network)

        self._prefix = b'\x00' + self.version + self.community_id
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

        self.network.register_service_provider(self.community_id, self)
        self.network.blacklist_mids.append(my_peer.mid)
        self.network.blacklist.extend(_DEFAULT_ADDRESSES)

        self.last_bootstrap = 0
        self.decode_map = [None] * 256

        self.add_message_handler(PunctureRequestPayload, self.on_old_puncture_request)
        self.add_message_handler(PuncturePayload, self.on_puncture)
        self.add_message_handler(NewPunctureRequestPayload, self.on_new_puncture_request)
        self.add_message_handler(NewPuncturePayload, self.on_new_puncture)
        self.add_message_handler(IntroductionRequestPayload, self.on_old_introduction_request)
        self.add_message_handler(IntroductionResponsePayload, self.on_old_introduction_response)
        self.add_message_handler(NewIntroductionRequestPayload, self.on_new_introduction_request)
        self.add_message_handler(NewIntroductionResponsePayload, self.on_new_introduction_response)

        self.add_message_handler(255, self.on_deprecated_message)
        self.add_message_handler(254, self.on_deprecated_message)
        self.add_message_handler(253, self.on_deprecated_message)
        self.add_message_handler(252, self.on_deprecated_message)
        self.add_message_handler(251, self.on_deprecated_message)
        self.add_message_handler(248, self.on_deprecated_message)
        self.add_message_handler(247, self.on_deprecated_message)
        self.add_message_handler(244, self.on_deprecated_message)
        self.add_message_handler(243, self.on_deprecated_message)
        self.add_message_handler(242, self.on_deprecated_message)
        self.add_message_handler(241, self.on_deprecated_message)
        self.add_message_handler(240, self.on_deprecated_message)
        self.add_message_handler(239, self.on_deprecated_message)
        self.add_message_handler(238, self.on_deprecated_message)
        self.add_message_handler(237, self.on_deprecated_message)
        self.add_message_handler(236, self.on_deprecated_message)
        self.add_message_handler(235, self.on_deprecated_message)

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
        if self.decode_map[msg_num]:
            raise RuntimeError("Attempted to add a handler for message number %d, already mapped to %s!" %
                               (msg_num, self.decode_map[msg_num]))
        self.decode_map[msg_num] = callback

    def on_deprecated_message(self, source_address, data):
        self.logger.warning("Received deprecated message: %s from (%s, %d)",
                            self.deprecated_message_names[data[22]], *source_address)

    def bootstrap(self):
        if time() - self.last_bootstrap < BOOTSTRAP_TIMEOUT:
            return
        self.logger.debug("Bootstrapping %s, current peers %d", self.__class__.__name__, len(self.get_peers()))
        self.last_bootstrap = time()
        for socket_address in _DEFAULT_ADDRESSES:
            self._ensure_blacklisted(socket_address)
            self.walk_to(socket_address)

    def _ensure_blacklisted(self, address):
        if address not in self.network.blacklist:
            self.network.blacklist.append(address)

    def resolve_dns_bootstrap_addresses(self):
        """
        Resolve the bootstrap server DNS names defined in ``_DNS_ADDRESSES`` and insert them into
        ``_DEFAULT_ADDRESSES``.
        """
        def resolve_addresses(dns_names):
            current_addresses = _DEFAULT_ADDRESSES[:]  # Copy the existing addresses (don't loop through our additions)
            for (address, port) in dns_names:
                try:
                    resolved_address = UDPv4Address(gethostbyname(address), port)
                    if resolved_address not in current_addresses:
                        # NOTE: append() is thread-safe. Don't call remove() here!
                        _DEFAULT_ADDRESSES.append(resolved_address)
                except error:
                    logging.info("Unable to resolve bootstrap DNS address (%s, %d)", address, port)

        resolution_thread = Thread(name="resolve_dns_bootstrap_addresses",
                                   target=resolve_addresses,
                                   args=(_DNS_ADDRESSES, ),
                                   daemon=True)
        resolution_thread.start()

    def guess_address(self, interface):
        if interface == "UDPIPv4":
            return UDPv4Address(*self._get_lan_address())
        elif interface == "UDPIPv6":
            return UDPv6Address(self.get_ipv6_address(), self.endpoint.get_address(interface)[1])
        else:
            return None

    def my_preferred_address(self):
        interfaces = getattr(self.endpoint, "interfaces", [])
        if not interfaces:
            return self.my_estimated_wan
        for interface in interfaces:
            if INTERFACES[interface] not in self.my_peer.addresses:
                self.my_peer.address = self.guess_address(interface)
        return self.my_peer.address

    def create_introduction_request(self, socket_address, extra_bytes=b'', new_style=False):
        global_time = self.claim_global_time() % 65536
        if new_style or isinstance(socket_address, UDPv6Address):
            payload = NewIntroductionRequestPayload(socket_address, self.my_estimated_lan, self.my_preferred_address(),
                                                    global_time, **_UNUSED_FLAGS_REQ, extra_bytes=extra_bytes)
        else:
            # Only supports IPv4 addresses as tuple or UDPv4Address instances.
            payload = IntroductionRequestPayload(socket_address,
                                                 self.my_estimated_lan,
                                                 self.my_estimated_wan,
                                                 True,
                                                 u"unknown",
                                                 global_time,
                                                 extra_bytes,
                                                 supports_new_style=new_style)
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(self._prefix, payload.msg_id, [auth, dist, payload])

    def create_introduction_response(self, lan_socket_address, socket_address, identifier,
                                     introduction=None, extra_bytes=b'', prefix=None, new_style=False):
        global_time = self.claim_global_time() % 65536
        introduction_lan = ("0.0.0.0", 0)
        introduction_wan = ("0.0.0.0", 0)
        introduced = False
        other = self.network.get_verified_by_address(socket_address)
        if not introduction:
            introduction = self.get_peer_for_introduction(exclude=other, new_style=new_style)
        if introduction:
            if isinstance(introduction.address, UDPv4Address) and self.address_is_lan(introduction.address[0]):
                introduction_lan = introduction.address
                introduction_wan = (self.my_estimated_wan[0], introduction_lan[1])
            else:
                introduction_lan = introduction.addresses.get(UDPv4LANAddress, introduction_lan)
                introduction_wan = introduction.address
            introduced = True
        new_style_intro = introduction.new_style_intro if introduction else False
        if new_style:
            payload = NewIntroductionResponsePayload(socket_address, self.my_estimated_lan, self.my_preferred_address(),
                                                     introduction_lan, introduction_wan, identifier,
                                                     new_style_intro, **_UNUSED_FLAGS_RESP, extra_bytes=extra_bytes)
        else:
            payload = IntroductionResponsePayload(socket_address,
                                                  self.my_estimated_lan,
                                                  self.my_estimated_wan,
                                                  introduction_lan,
                                                  introduction_wan,
                                                  u"unknown",
                                                  False,
                                                  identifier,
                                                  extra_bytes,
                                                  intro_supports_new_style=new_style_intro)
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        if introduced:
            packet = self.create_puncture_request(lan_socket_address, socket_address, identifier, prefix=prefix,
                                                  new_style=new_style)
            self.endpoint.send(introduction_wan if introduction_lan == ("0.0.0.0", 0) else introduction_lan, packet)

        return self._ez_pack(prefix or self._prefix, payload.msg_id, [auth, dist, payload])

    def create_puncture(self, lan_walker, wan_walker, identifier, new_style=False):
        global_time = self.claim_global_time()
        if new_style:
            payload = NewPuncturePayload(lan_walker, wan_walker, identifier)
        else:
            payload = PuncturePayload(lan_walker, wan_walker, identifier)
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(self._prefix, payload.msg_id, [auth, dist, payload])

    def create_puncture_request(self, lan_walker, wan_walker, identifier, prefix=None, new_style=False):
        global_time = self.claim_global_time()
        if new_style or not isinstance(lan_walker, UDPv4Address) or not isinstance(wan_walker, UDPv4Address):
            payload = NewPunctureRequestPayload(lan_walker, wan_walker, identifier)
        else:
            payload = PunctureRequestPayload(lan_walker, wan_walker, identifier)
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(prefix or self._prefix, payload.msg_id, [dist, payload], False)

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
    def on_old_introduction_request(self, peer, dist, payload):
        if payload.supports_new_style:
            peer.new_style_intro = True
        self.on_introduction_request(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, NewIntroductionRequestPayload)
    def on_new_introduction_request(self, peer, dist, payload):
        peer.new_style_intro = True
        self.on_introduction_request(peer, dist, payload)

    def on_introduction_request(self, peer, dist, payload):
        if self.max_peers >= 0 and len(self.get_peers()) > self.max_peers:
            self.logger.debug("Dropping introduction request from (%s, %d): too many peers!",
                              peer.address[0], peer.address[1])
            return

        if isinstance(payload.source_lan_address, UDPv4Address):
            peer.address = UDPv4LANAddress(*payload.source_lan_address)
        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.community_id, ])

        packet = self.create_introduction_response(payload.destination_address, peer.address, payload.identifier,
                                                   new_style=peer.new_style_intro)
        self.endpoint.send(peer.address, packet)

        self.introduction_request_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionResponsePayload)
    def on_old_introduction_response(self, peer, dist, payload):
        if payload.supports_new_style:
            peer.new_style_intro = True
        self.on_introduction_response(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, NewIntroductionResponsePayload)
    def on_new_introduction_response(self, peer, dist, payload):
        peer.new_style_intro = True
        self.on_introduction_response(peer, dist, payload)

    def on_introduction_response(self, peer, dist, payload):
        if (isinstance(payload.destination_address, UDPv4Address)
                and not self.address_is_lan(payload.destination_address[0])):
            self.my_estimated_wan = payload.destination_address
        self.my_peer.address = payload.destination_address

        if peer.new_style_intro:
            # Peer wants to use a different interface which we support, so let's try to switch interfaces.
            requested_interface = payload.source_wan_address.__class__
            used_interface = peer.address.__class__
            if (requested_interface != used_interface
                    and payload.source_wan_address != peer.address
                    and FAST_ADDR_TO_INTERFACE[requested_interface] in self.endpoint.interfaces):
                self.network.discover_address(peer, payload.source_wan_address, self.community_id, True)

                my_address = self.my_peer.addresses.get(requested_interface,
                                                        self.guess_address(FAST_ADDR_TO_INTERFACE[requested_interface]))
                if my_address:
                    packet = self.create_puncture_request(("0.0.0.0", 0), my_address, payload.identifier,
                                                          new_style=True)
                    self.endpoint.send(peer.address, packet)

        self.network.add_verified_peer(peer)
        self.network.discover_services(peer, [self.community_id, ])

        introductions = []

        if (payload.wan_introduction_address != ("0.0.0.0", 0)
                and payload.wan_introduction_address[0] != self.my_estimated_wan[0]):
            if payload.lan_introduction_address != ("0.0.0.0", 0):
                introductions.append(payload.lan_introduction_address)
            introductions.append(payload.wan_introduction_address)
        elif (payload.lan_introduction_address != ("0.0.0.0", 0)
              and payload.wan_introduction_address[0] == self.my_estimated_wan[0]):
            introductions.append(payload.lan_introduction_address)
        elif payload.wan_introduction_address != ("0.0.0.0", 0):
            introductions.append(payload.wan_introduction_address)
            introductions.append(UDPv4Address(self.my_estimated_lan[0], payload.wan_introduction_address[1]))

        for introduction in introductions:
            self.network.discover_address(peer, introduction, self.community_id, payload.intro_supports_new_style)

        self.introduction_response_callback(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, PuncturePayload)
    def on_puncture(self, peer, dist, payload):
        pass

    @lazy_wrapper(GlobalTimeDistributionPayload, NewPuncturePayload)
    def on_new_puncture(self, peer, dist, payload):
        pass

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PunctureRequestPayload)
    def on_old_puncture_request(self, source_address, dist, payload):
        self.on_puncture_request(source_address, dist, payload)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, NewPunctureRequestPayload)
    def on_new_puncture_request(self, source_address, dist, payload):
        self.on_puncture_request(source_address, dist, payload, True)

    def on_puncture_request(self, source_address, dist, payload, new_style=False):
        target = payload.wan_walker_address
        if payload.wan_walker_address[0] == self.my_estimated_wan[0]:
            target = payload.lan_walker_address

        packet = self.create_puncture(self.my_estimated_lan, payload.wan_walker_address, payload.identifier,
                                      new_style)
        self.endpoint.send(target, packet)

    def on_packet(self, packet, warn_unknown=True):
        source_address, data = packet
        probable_peer = self.network.get_verified_by_address(source_address)
        if probable_peer:
            probable_peer.last_response = time()
        if self._prefix != data[:22]:
            return
        msg_id = data[22]
        if self.decode_map[msg_id]:
            handler = self.decode_map[msg_id]
            try:
                result = handler(source_address, data)
                if iscoroutine(result):
                    self.register_anonymous_task('on_packet', ensure_future(result), ignore=(Exception,))
            except Exception:
                self.logger.error("Exception occurred while handling packet!\n"
                                  + ''.join(format_exception(*sys.exc_info())))
        elif warn_unknown:
            self.logger.warning("Received unknown message: %d from (%s, %d)", msg_id, *source_address)

    def walk_to(self, address):
        packet = self.create_introduction_request(address, new_style=self.network.is_new_style(address))
        self.endpoint.send(address, packet)

    def send_introduction_request(self, peer):
        """
        Send an introduction request to a specific peer.
        """
        packet = self.create_introduction_request(peer.address, new_style=peer.new_style_intro)
        self.endpoint.send(peer.address, packet)

    def get_new_introduction(self, from_peer: Peer = None):
        """
        Get a new introduction, or bootstrap if there are no available peers.
        """
        if not from_peer:
            available = self.get_peers()
            if available:
                # With a small chance, try to remedy any disconnected network phenomena.
                if _DEFAULT_ADDRESSES and random() < 0.05:
                    address = choice(_DEFAULT_ADDRESSES)
                    self._ensure_blacklisted(address)
                    packet = self.create_introduction_request(address)
                    self.endpoint.send(address, packet)
                    return
                else:
                    from_peer = choice(available)
            else:
                self.bootstrap()
                return
        self.send_introduction_request(from_peer)

    def get_peer_for_introduction(self, exclude=None, new_style=False):
        """
        Return a random peer to send an introduction request to.
        """
        available = [p for p in self.get_peers() if p != exclude and not
                     (not new_style and not isinstance(p.address, UDPv4Address))]
        return choice(available) if available else None

    def get_walkable_addresses(self):
        return self.network.get_walkable_addresses(self.community_id)

    def get_peers(self):
        return self.network.get_peers_for_service(self.community_id)
