from __future__ import absolute_import

from twisted.trial import unittest

from ....peerdiscovery.latency.peer_selection import Option, PeerSelector, ReferenceFuncPoint


class TestPeerSelector(unittest.TestCase):

    def test_optimal_single_choice(self):
        """
        Given a single point of reference and one option closer to it than the other, pick the closer one.
        """
        selector = PeerSelector([ReferenceFuncPoint(1.0, 1.0)])
        options = [Option(0.0, 'A'), Option(1.5, 'B')]

        self.assertEqual(Option(1.5, 'B'), selector.decide(options, falloff=0.2))

    def test_optimal_single_double_bin(self):
        """
        Given a single point of reference with a weight of 2.0, allocate two points.
        """
        selector = PeerSelector([ReferenceFuncPoint(1.0, 2.0)])
        options = [Option(1.0, 'A'), Option(1.0, 'B')]

        selected = {selector.decide(options, falloff=0.2)}
        selected |= {selector.decide(list(option for option in options if option not in selected), falloff=0.2)}

        self.assertSetEqual(set(options), selected)

    def test_optimal_single_none(self):
        """
        Given a single point of reference and a two filling options, fill with any option and then don't add more.
        """
        selector = PeerSelector([ReferenceFuncPoint(1.0, 1.0)])
        options = [Option(1.0, 'A'), Option(1.0, 'B')]

        self.assertIn(selector.decide(options, falloff=0.2), options)
        self.assertIsNone(selector.decide(options, falloff=0.2))

    def test_optimal_double_under(self):
        """
        Errors should be weighted to prefer options under the reference function, instead of over.
        """
        selector = PeerSelector([ReferenceFuncPoint(0.0, 1.0), ReferenceFuncPoint(1.0, 1.0)],
                                included=[Option(0.0, 'A')])
        options = [Option(0.5, 'B'), Option(1.5, 'C')]

        self.assertEqual(Option(1.5, 'C'), selector.decide(options, falloff=0.2))
