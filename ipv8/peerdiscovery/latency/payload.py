from __future__ import absolute_import

from ...messaging.lazy_payload import VariablePayload


class ProposalPayload(VariablePayload):
    """
    Packet for proposing to another peer.
    """
    msg_id = 5
    format_list = ['H', 'varlenH']
    names = ["nonce", 'peerid']


class ProposalAcceptPayload(VariablePayload):
    """
    Packet for accepting a proposal from another peer.
    """
    msg_id = 6
    format_list = ['H', 'varlenH']
    names = ["nonce", 'peerid']


class ProposalRejectPayload(VariablePayload):
    """
    Packet for rejecting a proposal from another peer.
    """
    msg_id = 7
    format_list = ['H', 'varlenH']
    names = ["nonce", 'peerid']


class BreakMatchPayload(VariablePayload):
    """
    Break a previously accepted proposal.
    """
    msg_id = 8
    format_list = ['I', 'varlenH']
    names = ["time", 'peerid']


class StatsRequestPayload(VariablePayload):
    """
    Request for peer statistics.
    """
    msg_id = 9
    format_list = ['Q']
    names = ["identifier"]


class StatsResponsePayload(VariablePayload):
    """
    Response with peer statistics.
    """
    msg_id = 10
    format_list = ['Q', 'I', 'I', 'I']
    names = ["identifier", "total", "possible", "matched"]
