"""
the community module provides the Community base class that should be used when a new Community is
implemented.  It provides a simplified interface between the Dispersy instance and a running
Community instance.

@author: Boudewijn Schoon
@organization: Technical University Delft
@contact: dispersy@frayja.com
"""
from __future__ import annotations

import sys
from asyncio import ensure_future, iscoroutine
from binascii import hexlify
from itertools import islice
from random import choice, random
from time import time
from traceback import format_exception
from typing import TYPE_CHECKING, Awaitable, Callable, cast

from .lazy_community import EZPackOverlay, lazy_wrapper, lazy_wrapper_unsigned
from .messaging.anonymization.endpoint import TunnelEndpoint
from .messaging.interfaces.dispatcher.endpoint import FAST_ADDR_TO_INTERFACE, INTERFACES, DispatcherEndpoint
from .messaging.interfaces.udp.endpoint import UDPv4Address, UDPv4LANAddress, UDPv6Address
from .messaging.payload import (
    IntroductionRequestPayload,
    IntroductionResponsePayload,
    NewIntroductionRequestPayload,
    NewIntroductionResponsePayload,
    NewPuncturePayload,
    NewPunctureRequestPayload,
    PuncturePayload,
    PunctureRequestPayload,
)
from .messaging.payload_headers import BinMemberAuthenticationPayload, GlobalTimeDistributionPayload
from .overlay import Settings
from .types import Address, MessageHandlerFunction

if TYPE_CHECKING:
    from .bootstrapping.bootstrapper_interface import Bootstrapper
    from .peer import Peer
    from .types import Payload

_UNUSED_FLAGS_REQ = {'connection_type_0': 0, 'connection_type_1': 0, 'supports_new_style': 0, 'dflag1': 0, 'dflag2': 0,
                     'tunnel': 0, 'sync': 0, 'advice': 0}
_UNUSED_FLAGS_RESP = {'flag1': 0, 'flag2': 0, 'flag3': 0, 'flag4': 0, 'flag5': 0, 'flag6': 0, 'flag7': 0}

DEFAULT_MAX_PEERS = 30


class CommunitySettings(Settings):
    """
    Community settings, extensible for Community subclasses.
    """

    max_peers: int = DEFAULT_MAX_PEERS
    """The number of peers we will grow to before we start rejecting new connections."""

    anonymize: bool = False
    """Request use of a ``TunnelEndpoint`` to anonymize all our traffic."""


class Community(EZPackOverlay):
    """
    Base class for overlay functionality with a rich set of defaults.

    Inherit from this class if you want IPv8 to handle peer introduction logic for you.
    """

    version = b'\x02'
    community_id: bytes
    settings_class = CommunitySettings

    def __init__(self, settings: CommunitySettings) -> None:
        """
        Create a new (still inert) community.
        """
        if not hasattr(self, "community_id") or self.community_id is None:
            msg = f"Attempted to launch {self.__class__.__name__} without a community_id!"
            raise RuntimeError(msg)
        if not isinstance(self.community_id, bytes):
            msg = (f"Attempted to launch {self.__class__.__name__} with a community_id that is not bytes!"
                   f"\n{self.community_id!r}")
            raise RuntimeError(msg)  # noqa: TRY004

        settings.community_id = self.community_id
        super().__init__(settings)

        self._prefix = b'\x00' + self.version + self.community_id
        self.endpoint.remove_listener(self)
        self.endpoint.add_prefix_listener(self, self._prefix)
        self.logger.debug("Launching %s with prefix %s.", self.__class__.__name__, hexlify(self._prefix).decode())

        self.max_peers = settings.max_peers
        self.anonymize = settings.anonymize

        if settings.anonymize:
            if isinstance(self.endpoint, TunnelEndpoint):
                self.endpoint.set_anonymity(self._prefix, True)
            else:
                self.logger.warning('Cannot anonymize community traffic without TunnelEndpoint')

        self.network.register_service_provider(self.community_id, self)
        self.network.blacklist_mids.append(settings.my_peer.mid)

        self.bootstrappers: list[Bootstrapper] = []

        self.decode_map: list[MessageHandlerFunction | None] = [None] * 256

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

    def get_prefix(self) -> bytes:
        """
        Get the prefix for all data that is to be routed to this Community.

        Note that this can be shared with other communities. This is used, for example, for statistics tracking.
        """
        return self._prefix

    async def unload(self) -> None:
        """
        Perform a clean exit of this Community.

        Clean shutdown consists of three steps:
        - First, unload the bootstrappers.
        - Second, stop listening on the endpoint.
        - Last, disallow new tasks from being registered.
        """
        while self.bootstrappers:
            bootstrapper = self.bootstrappers.pop()
            bootstrapper.unload()
        await super().unload()

    def add_message_handler(self, msg_num: int | type[Payload], callback: MessageHandlerFunction) -> None:
        """
        Add a handler for a message identifier. Any messages coming in with this identifier will be delivered to
        the specified callback function.

        :param msg_num: the message id to listen for (or a Payload object with a msg_id field)
        :param callback: the callback function for this message id
        """
        actual_msg_num: int = 256
        if not isinstance(msg_num, int):
            if not hasattr(msg_num, "msg_id"):
                raise RuntimeError("Attempted to add a handler for Payload %s, which does not specify a msg_id!"
                                   % msg_num)
            actual_msg_num = cast(int, msg_num.msg_id)  # type: ignore[attr-defined]
        else:
            if msg_num < 0 or msg_num > 255:
                raise RuntimeError("Attempted to add a handler for message number %d, which is not a byte!" % msg_num)
            actual_msg_num = msg_num

        if self.decode_map[actual_msg_num]:
            raise RuntimeError("Attempted to add a handler for message number %d, already mapped to %s!" %
                               (actual_msg_num, self.decode_map[actual_msg_num]))
        self.decode_map[actual_msg_num] = callback

    def on_deprecated_message(self, source_address: Address, data: bytes) -> None:
        """
        Callback for when we receive a known-to-be-deprecated message.
        """
        self.logger.warning("Received deprecated message: %s from (%s, %d)",
                            self.deprecated_message_names[data[22]], *source_address)

    def bootstrap(self) -> None:
        """
        Contact the bootstrappers for new peers, initialize the bootstrappers if necessary.
        """
        for bootstrapper in self.bootstrappers:
            self.register_anonymous_task(f'bootstrap {bootstrapper!r}', self._bootstrap, bootstrapper)

    async def _bootstrap(self, bootstrapper: Bootstrapper) -> None:
        """
        Contact a single bootstrapper for new peers and initialize if necessary.
        """
        task = ensure_future(bootstrapper.initialize(self))

        addresses = await bootstrapper.get_addresses(self, 60.0)
        for address in (addresses if self.max_peers > 0 else islice(addresses, self.max_peers)):
            self.walk_to(address)

        await task

    def ensure_blacklisted(self, address: Address) -> None:
        """
        Add an address to the blacklist, if it is not already there.
        """
        if address not in self.network.blacklist:
            self.network.blacklist.append(address)

    def guess_address(self, interface: str) -> Address | None:
        """
        GUESS our own address.

        There is no way to be sure this address is "correct". There may not even BE a consistent address that other
        peers can contact us by.
        """
        if interface == "UDPIPv4":
            return UDPv4Address(*self._get_lan_address())
        if interface == "UDPIPv6":
            return UDPv6Address(*self.get_ipv6_address())
        return None

    def my_preferred_address(self) -> Address:
        """
        Get our own preferred address or ``("0.0.0.0", 0)`` if we don't know of any of our own addresses.
        """
        interfaces = getattr(self.endpoint, "interfaces", [])
        if not interfaces:
            return self.my_estimated_wan
        for interface in interfaces:
            if INTERFACES[interface] not in self.my_peer.addresses:
                address = self.guess_address(interface)
                if address is not None:
                    self.my_peer.address = address
        return self.my_peer.address

    def create_introduction_request(self, socket_address: Address, extra_bytes: bytes = b'', new_style: bool = False,
                                    prefix: bytes | None = None) -> bytes:
        """
        Create a new introduction request message, without sending it.

        :param socket_address: The address to send to.
        :param extra_bytes: The extra bytes to piggyback onto this message.
        :param new_style: Whether we support "new style" (non-IPv4) introduction requests.
        :param prefix: Send to a different community id (EXPERT USE ONLY).
        """
        global_time = self.claim_global_time() % 65536
        payload: IntroductionRequestPayload | NewIntroductionRequestPayload
        if new_style or isinstance(socket_address, UDPv6Address):
            payload = NewIntroductionRequestPayload(socket_address, self.my_estimated_lan, self.my_preferred_address(),
                                                    global_time, **_UNUSED_FLAGS_REQ, extra_bytes=extra_bytes)
        else:
            # Only supports IPv4 addresses as tuple or UDPv4Address instances.
            payload = IntroductionRequestPayload(socket_address,
                                                 self.my_estimated_lan,
                                                 self.my_estimated_wan,
                                                 True,
                                                 "unknown",
                                                 global_time,
                                                 extra_bytes,
                                                 supports_new_style=new_style)
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(prefix or self._prefix, payload.msg_id, [auth, dist, payload])

    def create_introduction_response(self, lan_socket_address: Address, socket_address: Address,  # noqa: PLR0913
                                     identifier: int, introduction: Peer | None = None, extra_bytes: bytes = b'',
                                     prefix: bytes | None = None, new_style: bool = False) -> bytes:
        """
        Create a new introduction response message, without sending it.

        :param lan_socket_address: What the request sender thinks our address is.
        :param socket_address: The request sender's address.
        :param identifier: The introduction request identifier that we are responding to.
        :param introduction: Introduce the request sender to this given peer.
        :param extra_bytes: The extra bytes to piggyback onto this message.
        :param prefix: Send to a different community id (EXPERT USE ONLY).
        :param new_style: Whether we support "new style" (non-IPv4) introduction requests.
        """
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
        payload: IntroductionResponsePayload | NewIntroductionResponsePayload
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
                                                  "unknown",
                                                  identifier,
                                                  extra_bytes,
                                                  intro_supports_new_style=new_style_intro,
                                                  peer_limit_reached=0 <= self.max_peers <= len(self.get_peers()))
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        if introduced and introduction is not None:
            packet = self.create_puncture_request(lan_socket_address, socket_address, identifier, prefix=prefix,
                                                  new_style=new_style)
            self.endpoint.send(introduction.address, packet)

        return self._ez_pack(prefix or self._prefix, payload.msg_id, [auth, dist, payload])

    def create_puncture(self, lan_walker: Address, wan_walker: Address, identifier: int,
                        new_style: bool = False) -> bytes:
        """
        Create a puncture message for the given LAN/WAN address.

        :param lan_walker: The LAN address to puncture.
        :param wan_walker: The WAN address to puncture.
        :param identifier: The PunctureRequest identifier we are responding to.
        :param new_style: Whether we support "new style" (non-IPv4) introduction requests.
        """
        global_time = self.claim_global_time()
        payload: PuncturePayload | NewPuncturePayload
        if new_style:
            payload = NewPuncturePayload(lan_walker, wan_walker, identifier)
        else:
            payload = PuncturePayload(lan_walker, wan_walker, identifier)
        auth = BinMemberAuthenticationPayload(self.my_peer.public_key.key_to_bin())
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(self._prefix, payload.msg_id, [auth, dist, payload])

    def create_puncture_request(self, lan_walker: Address, wan_walker: Address, identifier: int,
                                prefix: bytes | None = None, new_style: bool = False) -> bytes:
        """
        Create a request for another peer to puncture a given LAN/WAN address pair.

        :param lan_walker: The LAN address to request puncturing for.
        :param wan_walker: The WAN address to request puncturing for.
        :param identifier: The identifier to use for this message.
        :param prefix: Send to a different community id (EXPERT USE ONLY).
        :param new_style: Whether we support "new style" (non-IPv4) introduction requests.
        """
        global_time = self.claim_global_time()
        payload: PunctureRequestPayload | NewPunctureRequestPayload
        if new_style or not isinstance(lan_walker, UDPv4Address) or not isinstance(wan_walker, UDPv4Address):
            payload = NewPunctureRequestPayload(lan_walker, wan_walker, identifier)
        else:
            payload = PunctureRequestPayload(lan_walker, wan_walker, identifier)
        dist = GlobalTimeDistributionPayload(global_time)

        return self._ez_pack(prefix or self._prefix, payload.msg_id, [dist, payload], False)

    def introduction_request_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                      payload: IntroductionRequestPayload | NewIntroductionRequestPayload) -> None:
        """
        Callback that gets called after an introduction-request has been processed.
        If you want to some action to trigger upon receipt of an introduction-request,
        this would be the place to do so.

        :param peer the peer that sent us an introduction-request
        :param dist the GlobalTimeDistributionPayload
        :param payload the IntroductionRequestPayload
        """

    def introduction_response_callback(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                       payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        """
        Callback that gets called after an introduction-response has been processed.
        If you want to some action to trigger upon receipt of an introduction-response,
        this would be the place to do so.

        :param peer the peer that sent us an introduction-response
        :param dist the GlobalTimeDistributionPayload
        :param payload the IntroductionResponsePayload
        """

    @lazy_wrapper(GlobalTimeDistributionPayload, IntroductionRequestPayload)
    def on_old_introduction_request(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                      payload: IntroductionRequestPayload | NewIntroductionRequestPayload) -> None:
        """
        Interception callback for when we receive an old IPv4-only introduction request.

        Message handling is performed in ``on_introduction_request()``.
        """
        if payload.supports_new_style:
            peer.new_style_intro = True
        self.on_introduction_request(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, NewIntroductionRequestPayload)
    def on_new_introduction_request(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                      payload: NewIntroductionRequestPayload) -> None:
        """
        Interception callback for when we receive a new (non-IPv4-only) introduction request.

        Message handling is performed in ``on_introduction_request()``.
        """
        peer.new_style_intro = True
        self.on_introduction_request(peer, dist, payload)

    def on_introduction_request(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                payload: IntroductionRequestPayload | NewIntroductionRequestPayload) -> None:
        """
        Callback to handle introduction requests.

        We don't answer if we are at our peer capacity, triggering peer churn for the other peer. Otherwise,
        we respond with an introduction response.
        """
        if 0 <= self.max_peers < len(self.get_peers()):
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
    def on_old_introduction_response(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                     payload: IntroductionResponsePayload) -> None:
        """
        Interception callback for when we receive an old IPv4-only introduction response.

        Message handling is performed in ``on_introduction_response()``.
        """
        if payload.supports_new_style:
            peer.new_style_intro = True
        self.on_introduction_response(peer, dist, payload)

    @lazy_wrapper(GlobalTimeDistributionPayload, NewIntroductionResponsePayload)
    def on_new_introduction_response(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                     payload: NewIntroductionResponsePayload) -> None:
        """
        Interception callback for when we receive a new (non-IPv4-only) introduction response.

        Message handling is performed in ``on_introduction_response()``.
        """
        peer.new_style_intro = True
        self.on_introduction_response(peer, dist, payload)

    def on_introduction_response(self, peer: Peer, dist: GlobalTimeDistributionPayload,
                                 payload: IntroductionResponsePayload | NewIntroductionResponsePayload) -> None:
        """
        Callback to handle introduction responses.
        """
        if (isinstance(payload.destination_address, UDPv4Address)
                and not self.address_in_lan_subnets(payload.destination_address[0])):
            self.my_estimated_wan = payload.destination_address
        self.my_peer.address = payload.destination_address

        if peer.new_style_intro:
            # Peer wants to use a different interface which we support, so let's try to switch interfaces.
            requested_interface = payload.source_wan_address.__class__
            used_interface = peer.address.__class__
            if (requested_interface != used_interface
                    and payload.source_wan_address != peer.address
                    and (FAST_ADDR_TO_INTERFACE[requested_interface]
                         in cast(DispatcherEndpoint, self.endpoint).interfaces)):
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
    def on_puncture(self, peer: Peer, dist: GlobalTimeDistributionPayload, payload: PuncturePayload) -> None:
        """
        When we receive a puncture, we do nothing.
        """

    @lazy_wrapper(GlobalTimeDistributionPayload, NewPuncturePayload)
    def on_new_puncture(self, peer: Peer, dist: GlobalTimeDistributionPayload, payload: NewPuncturePayload) -> None:
        """
        When we receive a new-style puncture, we do nothing.
        """

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, PunctureRequestPayload)
    def on_old_puncture_request(self, source_address: Address, dist: GlobalTimeDistributionPayload,
                                payload: PunctureRequestPayload) -> None:
        """
        Interception callback for when we receive an old IPv4-only puncture request.

        Message handling is performed in ``on_puncture_request()``.
        """
        self.on_puncture_request(source_address, dist, payload)

    @lazy_wrapper_unsigned(GlobalTimeDistributionPayload, NewPunctureRequestPayload)
    def on_new_puncture_request(self, source_address: Address, dist: GlobalTimeDistributionPayload,
                                payload: NewPunctureRequestPayload) -> None:
        """
        Interception callback for when we receive a new (non-IPv4-only) puncture request.

        Message handling is performed in ``on_puncture_request()``.
        """
        self.on_puncture_request(source_address, dist, payload, True)

    def on_puncture_request(self, source_address: Address, dist: GlobalTimeDistributionPayload,
                            payload: PunctureRequestPayload | NewPunctureRequestPayload,
                            new_style: bool = False) -> None:
        """
        Callback to handle puncture requests.

        We send a puncture to the requested address.
        """
        target = payload.wan_walker_address
        if payload.wan_walker_address[0] == self.my_estimated_wan[0]:
            target = payload.lan_walker_address

        packet = self.create_puncture(self.my_estimated_lan, payload.wan_walker_address, payload.identifier,
                                      new_style)
        self.endpoint.send(target, packet)

    def on_packet(self, packet: tuple[Address, bytes], warn_unknown: bool = True) -> None:
        """
        Callback for when the Endpoint has new data for us.

        :param packet: The address, bytes tuple that was received.
        :param warn_unknown: Whether we should log incoming garbage data.
        """
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
                result = cast(Callable[[Address, bytes], None], handler)(source_address, data)
                if iscoroutine(result):
                    aw_result = cast(Awaitable, result)
                    self.register_anonymous_task('on_packet', ensure_future(aw_result), ignore=(Exception,))
            except Exception:
                self.logger.exception("Exception occurred while handling packet!\n%s",
                                      ''.join(format_exception(*sys.exc_info())))
        elif warn_unknown:
            self.logger.warning("Received unknown message: %d from (%s, %d)", msg_id, *source_address)

    def walk_to(self, address: Address) -> None:
        """
        Attempt to walk directly to the given address.
        """
        packet = self.create_introduction_request(address, new_style=self.network.is_new_style(address))
        self.endpoint.send(address, packet)

    def send_introduction_request(self, peer: Peer) -> None:
        """
        Send an introduction request to a specific peer.
        """
        packet = self.create_introduction_request(peer.address, new_style=peer.new_style_intro)
        self.endpoint.send(peer.address, packet)

    def get_new_introduction(self, from_peer: Peer | None = None) -> None:
        """
        Get a new introduction, or bootstrap if there are no available peers.
        """
        if not from_peer:
            available = self.get_peers()
            if available:
                # With a small chance, try to remedy any disconnected network phenomena.
                bootstrappers_ready = any(b.initialized for b in self.bootstrappers)
                if bootstrappers_ready and random() < 0.05:
                    for bootstrapper in self.bootstrappers:
                        bootstrapper.keep_alive(self)
                    return
                from_peer = choice(available)
            else:
                self.bootstrap()
                return
        self.send_introduction_request(from_peer)

    def get_peer_for_introduction(self, exclude: Peer | None = None, new_style: bool = False) -> Peer | None:
        """
        Return a random peer to send an introduction request to.
        """
        available = [p for p in self.get_peers() if p != exclude and not
                     (not new_style and not isinstance(p.address, UDPv4Address))]
        return choice(available) if available else None

    def get_walkable_addresses(self) -> list[Address]:
        """
        Get the addresses that we know of but have not been contacted to become a peer.
        """
        return self.network.get_walkable_addresses(self.community_id)

    def get_peers(self) -> list[Peer]:
        """
        Get the peers that we are currently connected to (and we have received signed messages from).
        """
        return self.network.get_peers_for_service(self.community_id)
