from __future__ import absolute_import, division

import os
import struct
import time
from binascii import unhexlify
from collections import namedtuple
from math import floor

from twisted.internet.defer import fail
from twisted.internet.task import LoopingCall

from .cache import ProposalCache, StatsRequestCache
from .discovery import LatencyEdgeWalk
from .payload import (BreakMatchPayload, ProposalAcceptPayload, ProposalPayload, ProposalRejectPayload,
                      StatsRequestPayload, StatsResponsePayload)
from .peer_selection import Option, PeerSelector, generate_reference
from ...community import DEFAULT_MAX_PEERS
from ...lazy_community import lazy_wrapper
from ...peer import Peer
from ...peerdiscovery.community import DiscoveryCommunity


Stats = namedtuple('Stats', ["total", "possible", "matched"])


def generate_nonce():
    """
    Create a 2 byte securely random nonce.

    :return: the 2-byte securely random integer
    :rtype: int
    """
    return struct.unpack(">H", os.urandom(2))[0]


def get_current_time():
    """
    Get the current time in 10s of seconds.

    :return: the time in 10s since the UNIX epoch
    :rtype: int
    """
    return int(time.time() / 10)


DEFAULT_PING_BINS = [x * 0.05 + 0.001 for x in range(0, 40, 1)]


class LatencyCommunity(DiscoveryCommunity):

    master_peer = Peer(unhexlify("4c69624e61434c504b3aaf489217d2a689086b9103bd7a7a249021f387e1af10c06a0dc82ea0c65786"
                                 "041b682e0db8fce6b4c3db0d4e47e4afbeed2e633752b949820dad16af1962d7fa"))

    def __init__(self, my_peer, endpoint, network, max_peers=DEFAULT_MAX_PEERS, anonymize=False, preferred_count=60,
                 k_window=30, ping_time_bins=DEFAULT_PING_BINS):
        """
        :param preferred_count: the maximum amount of partners, you will probably get between this and half of this
        :type preferred_count: int
        :param k_window: the amount of proposals to consider at the same time
        :type k_window: int
        :param ping_time_bins: the list of function evaluation points
        :type ping_time_bins: [float]
        """
        super(LatencyCommunity, self).__init__(my_peer, endpoint, network, max_peers=max_peers, anonymize=anonymize)

        self.ping_reference_bins = generate_reference(lambda x: preferred_count / x, ping_time_bins, preferred_count)
        self.preferred_count = preferred_count
        self.k_window = k_window

        self.possible_peers = []  # List of peers in the discovery
        self.acceptable_peers = set()  # Peers we want included in our next round

        self.open_proposals = set()
        self.accepted_proposals = set()

        self.add_message_handler(ProposalPayload.msg_id, self.on_proposal)
        self.add_message_handler(ProposalAcceptPayload.msg_id, self.on_accept_proposal)
        self.add_message_handler(ProposalRejectPayload.msg_id, self.on_reject_proposal)
        self.add_message_handler(BreakMatchPayload.msg_id, self.on_break_match)
        self.add_message_handler(StatsRequestPayload.msg_id, self.on_stats_request)
        self.add_message_handler(StatsResponsePayload.msg_id, self.on_stats_response)

        self.request_cache.register_task("update_acceptable_peers",
                                         LoopingCall(self.update_acceptable_peers)).start(5.0, False)

    def get_available_strategies(self):
        out = super(LatencyCommunity, self).get_available_strategies()
        out['LatencyEdgeWalk'] = LatencyEdgeWalk
        return out

    def check_payload(self, payload):
        """
        Check if a given payload (with `peerid` field) is targeted to us.

        :param payload: the payload to check for
        :type payload: Payload
        :except: RuntimeError
        :returns: None
        """
        if payload.peerid != self.my_peer.mid:
            raise RuntimeError("Someone is replay attacking us!")

    def update_acceptable_peers(self):
        """
        Propose to a fresh set of peers or swap out suboptimal peers.

        :returns: None
        """
        # Clean up mappings
        peer_set = self.get_peers()
        self.open_proposals = set(p for p in self.open_proposals if p in peer_set)
        self.accepted_proposals = set(p for p in self.accepted_proposals if p in peer_set)
        # If necessary, send out new proposals
        open_for_proposal_count = self.preferred_count - len(self.accepted_proposals) - len(self.open_proposals)
        if open_for_proposal_count > 0:
            peer_selector = PeerSelector(self.ping_reference_bins,
                                         included=[Option(peer.get_median_ping(), peer)
                                                   for peer in self.accepted_proposals
                                                   if peer.get_median_ping() is not None])
            options = []
            # Only consider peers that are not already accepted or proposed to
            for peer in self.possible_peers:
                if (peer not in self.accepted_proposals and peer not in self.open_proposals
                   and peer.get_median_ping() is not None):
                    options.append(Option(peer.get_median_ping(), peer))
            # Maximally send out K_WINDOW proposals at the same time
            choices = []
            for _ in range(self.k_window):
                choice = peer_selector.decide(options)
                if choice is not None:
                    options.remove(choice)
                    choices.append(choice)
                # If the K_WINDOW goes over the PREFERRED_COUNT, stop
                if len(peer_selector.included) == (self.preferred_count - len(self.accepted_proposals)
                                                   - len(self.open_proposals)):
                    break
            new_options = [tup.obj for tup in choices]
            self.acceptable_peers = new_options + list(self.open_proposals) + list(self.accepted_proposals)
            for peer in new_options:
                self.send_proposal(peer)
        elif self.preferred_count == len(self.accepted_proposals):
            # Remove the current worst peer, if there is one
            peer_selector = PeerSelector(self.ping_reference_bins,
                                         included=[Option(peer.get_median_ping(), peer)
                                                   for peer in self.accepted_proposals
                                                   if peer.get_median_ping() is not None])
            worst = peer_selector.current_worst()
            if worst:
                peer = worst.obj
                self.accepted_proposals.remove(peer)
                packet = self.ezr_pack(BreakMatchPayload.msg_id, BreakMatchPayload(get_current_time(), peer.mid))
                self.endpoint.send(peer.address, packet)

    def send_proposal(self, peer):
        """
        Send a proposal to a given peer.

        :param peer: the peer to send the proposal to
        :type peer: Peer
        :returns: None
        """
        nonce = generate_nonce()
        self.open_proposals.add(peer)
        self.request_cache.add(ProposalCache(self, peer, nonce))
        packet = self.ezr_pack(ProposalPayload.msg_id, ProposalPayload(nonce, peer.mid))
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(ProposalPayload)
    def on_proposal(self, peer, payload):
        """
        Upon receiving a proposal, respond with an acceptation or rejection.

        :param peer: the peer we have received a proposal from
        :type peer: Peer
        :param payload: the proposal payload
        :type payload: ProposalPayload
        :returns: None
        """
        self.check_payload(payload)
        accept = False
        if peer in self.acceptable_peers or peer in self.open_proposals or peer in self.accepted_proposals:
            accept = True
        elif len(self.open_proposals) + len(self.accepted_proposals) < self.preferred_count:
            if len(self.open_proposals) + len(self.accepted_proposals) < floor(self.preferred_count * 0.75):
                accept = True
                if not peer.get_median_ping():
                    self.send_ping(peer)
            elif peer.get_median_ping():
                peer_selector = PeerSelector(self.ping_reference_bins,
                                             included=[Option(p.get_median_ping(), p)
                                                       for p in self.accepted_proposals
                                                       if p.get_median_ping() is not None])
                if peer_selector.decide([Option(peer.get_median_ping(), peer)]):
                    accept = True
        if accept:
            packet = self.ezr_pack(ProposalAcceptPayload.msg_id, ProposalAcceptPayload(payload.nonce, peer.mid))
            self.accepted_proposals.add(peer)
        else:
            packet = self.ezr_pack(ProposalRejectPayload.msg_id, ProposalRejectPayload(payload.nonce, peer.mid))
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(ProposalAcceptPayload)
    def on_accept_proposal(self, peer, payload):
        """
        If someone accepted our proposal update our mappings.

        :param peer: the peer that sent us the accept
        :type peer: Peer
        :param payload: the acceptation payload
        :type payload: ProposalAcceptPayload
        :returns: None
        """
        self.check_payload(payload)
        try:
            request_cache = self.request_cache.pop(u"proposal-cache",
                                                   ProposalCache.number_from_pk_nonce(peer.mid, payload.nonce))
            if request_cache:
                if len(self.accepted_proposals) < self.preferred_count or peer in self.accepted_proposals:
                    self.accepted_proposals.add(peer)
                else:
                    self.logger.debug("%s accepted our proposal, but we don't want it anymore!", str(peer))
                    packet = self.ezr_pack(BreakMatchPayload.msg_id, BreakMatchPayload(get_current_time(), peer.mid))
                    self.endpoint.send(peer.address, packet)
                self.open_proposals.remove(peer)
            else:
                self.logger.debug("Got timed out or unwanted proposal response.")
        except KeyError:
            self.logger.debug("Got timed out or unwanted proposal response.")

    @lazy_wrapper(ProposalRejectPayload)
    def on_reject_proposal(self, peer, payload):
        """
        If someone rejected our proposal update our mappings.

        :param peer: the peer that sent us the reject
        :type peer: Peer
        :param payload: the rejection payload
        :type payload: ProposalRejectPayload
        :returns: None
        """
        self.check_payload(payload)
        try:
            request_cache = self.request_cache.pop(u"proposal-cache",
                                                   ProposalCache.number_from_pk_nonce(peer.mid, payload.nonce))
            if request_cache:
                self.open_proposals.remove(peer)
            else:
                self.logger.debug("Got timed out or unwanted proposal response.")
        except KeyError:
            self.logger.debug("Got timed out or unwanted proposal response.")

    @lazy_wrapper(BreakMatchPayload)
    def on_break_match(self, peer, payload):
        """
        If someone broke a match with us.

        :param peer: the peer that sent us the break
        :type peer: Peer
        :param payload: the break payload
        :type payload: BreakMatchPayload
        :returns: None
        """
        self.check_payload(payload)  # Peer id is correct
        current_time = get_current_time()
        if not current_time - 1 <= payload.time <= current_time:
            self.logger.debug("Got timed out match break.")
            return
        try:
            self.accepted_proposals.remove(peer)
        except KeyError:
            self.logger.debug("Tried to match break a non-accepted peer.")

    def send_stats_request(self, peer):
        """
        Request the stats of a particular peer.

        :param peer: the peer to request from
        :return: deferred object to wait for
        :rtype: Deferred
        """
        cache = self.request_cache.add(StatsRequestCache(self))
        if cache:
            packet = self.ezr_pack(StatsRequestPayload.msg_id, StatsRequestPayload(cache.number))
            self.endpoint.send(peer.address, packet)
            return cache.deferred
        return fail(None)

    @lazy_wrapper(StatsRequestPayload)
    def on_stats_request(self, peer, payload):
        """
        If someone requests our stats.

        :param peer: the peer that sent us the request
        :type peer: Peer
        :param payload: the stats request payload
        :type payload: StatsRequestPayload
        :returns: None
        """
        response = StatsResponsePayload(payload.identifier,
                                        len(self.get_peers()), len(self.possible_peers), len(self.accepted_proposals))
        packet = self.ezr_pack(StatsResponsePayload.msg_id, response)
        self.endpoint.send(peer.address, packet)

    @lazy_wrapper(StatsResponsePayload)
    def on_stats_response(self, peer, payload):
        """
        If someone responds with their stats.

        :param peer: the peer that sent us the request
        :type peer: Peer
        :param payload: the stats response payload
        :type payload: StatsResponsePayload
        :returns: None
        """
        try:
            cache = self.request_cache.pop(u"stats-request", payload.identifier)
            if cache:
                cache.deferred.callback(Stats(payload.total, payload.possible, payload.matched))
        except KeyError:
            self.logger.debug("Got a timed-out or unwanted StatsResponsePayload.")
