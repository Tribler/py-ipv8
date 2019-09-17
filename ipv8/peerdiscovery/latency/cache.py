from __future__ import absolute_import

from twisted.internet.defer import Deferred

from ...requestcache import NumberCache


class ProposalCache(NumberCache):
    """
    Cache for keeping track of a made proposal.
    This cache concludes upon proposal (1) accept, (2) reject or (3) timeout.
    """

    def __init__(self, overlay, peer, nonce):
        super(ProposalCache, self).__init__(overlay.request_cache, u"proposal-cache",
                                            self.number_from_pk_nonce(peer.mid, nonce))
        self.overlay = overlay
        self.peer = peer

    @classmethod
    def number_from_pk_nonce(cls, public_key, nonce):
        """
        Create an identifier from a public key and a nonce.

        :param public_key: the counterparty public key
        :type public_key: str or bytes
        :param nonce: the nonce for this proposal
        :type nonce: str or bytes
        :return: the identifier for the given parameters
        :rtype: int
        """
        number = nonce
        for c in public_key:
            number <<= 8
            number += c if isinstance(c, int) else ord(c)
        return number

    def on_timeout(self):
        """
        When timing out, we remove this proposal from the open proposals.

        :returns: None
        """
        try:
            self.overlay.open_proposals.remove(self.peer)
        except KeyError:
            self.overlay.logger.debug("Proposal timed out, but peer already removed.")


class StatsRequestCache(NumberCache):
    """
    Cache for waiting for a stats response.
    """

    def __init__(self, overlay):
        super(StatsRequestCache, self).__init__(overlay.request_cache, u"stats-request", overlay.claim_global_time())
        self.deferred = Deferred()

    def on_timeout(self):
        self.deferred.errback(None)
