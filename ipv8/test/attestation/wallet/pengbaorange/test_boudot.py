from __future__ import absolute_import

from binascii import unhexlify

from twisted.trial import unittest

from .....attestation.wallet.pengbaorange.boudot import EL, SQR
from .....attestation.wallet.primitives.structs import BonehPrivateKey
from .....attestation.wallet.primitives.value import FP2Value


class TestBoudot(unittest.TestCase):

    pk = BonehPrivateKey.unserialize(unhexlify("0109649b2a7d7992b008d1010958f4d560346bb392330109117572cef25"
                                               "23be2fe0109264c97f1868fd4b18b010908792e2bf8bcaa077f0108baa1"
                                               "b2ff06a0cfd50104c772a78f")).public_key()
    bitspace = 32
    a, b = 0, 18
    r, ra = 2, 3

    # Commitment generated with above parameters for message `7`
    el = EL.unserialize(unhexlify("000121029751139763ba5fc618be51e192166880e839a130c0d4aab00486576e2f80bc4a012956e492"
                                  "9cce245462a5ea5fecd5754a962ca1285cc0fbc2abc35ecaa46323001ef7093fadc48821678d01210a"
                                  "5d444e5d8ee97f1862f947864859a203a0e684c30352687449605457910d01870120dd1b0687cbe8ca"
                                  "975d94c5f5db5ccd804d688b104046de09b0c807074c166a9b"))[0]

    # Commitment generated with above parameters for message `16`
    sqr = SQR.unserialize(unhexlify("0109649b2a7d7992b008d101092ef4b2b3890136f39d0109300f2cb5896dcadc4901012a0a16027d"
                                    "ee86ae81c4cfc7f529f46261608252ab4daa517d68e21720790e4199f78a1929dbd013a105b6012a"
                                    "0285809f7ba1aba0714188435457007cbe08eaaf87506267fdb8c0ad262dfb6c15ca968e206a9777"
                                    "949e012102af10fec9115c85e85cd7d7aef94a65d3cc6c7357642706e8a37bb0ecd804845b0120ab"
                                    "c43fb24457217a1735f5ebbe529974f31b1cd5d909c1ba28deec3b36011fa3"))[0]

    def test_el_serialize(self):
        """
        Check if Boudot equality checks are correctly serialized.
        """
        el = EL(100008889479195929040786129547012695469496765491242069345687894691258593340059,
                1200106673750351148489433554564152345633961185894904832148254736295103120081287,
                185602027022725977391811873443578044718836100453180525236683325288764698585520893770670707818194829,
                300026668437587787122358388641038086408490296473726208115332223393004792101962)
        self.assertEqual(self.el, el)

    def test_el_equal(self):
        """
        Check if the Boudot commitment equality holds.
        """
        m = 7  # Message

        # Commitment
        c = self.pk.g.intpow(m) * self.pk.h.intpow(self.r)
        c1 = c // (self.pk.g.intpow(self.a - 1))
        c2 = self.pk.g.intpow(self.b + 1) // c

        # Shadow commitment
        ca = c1.intpow(self.b - m + 1) * self.pk.h.intpow(self.ra)

        # Check
        self.assertTrue(self.el.check(self.pk.g, self.pk.h, c1, self.pk.h, c2, ca))

    def test_el_modify_commitment(self):
        """
        Check if the Boudot commitment equality fails if the commitment message changes.
        """
        m = 7  # Message
        fake = 8

        # Commitment
        c = self.pk.g.intpow(fake) * self.pk.h.intpow(self.r)
        c1 = c // (self.pk.g.intpow(self.a - 1))
        c2 = self.pk.g.intpow(self.b + 1) // c

        # Shadow commitment
        ca = c1.intpow(self.b - m + 1) * self.pk.h.intpow(self.ra)

        # Check
        self.assertFalse(self.el.check(self.pk.g, self.pk.h, c1, self.pk.h, c2, ca))

    def test_el_modify_shadow_commitment(self):
        """
        Check if the Boudot commitment equality fails if the shadow commitment message changes.
        """
        m = 7  # Message
        fake = 8

        # Commitment
        c = self.pk.g.intpow(m) * self.pk.h.intpow(self.r)
        c1 = c // (self.pk.g.intpow(self.a - 1))
        c2 = self.pk.g.intpow(self.b + 1) // c

        # Shadow commitment
        ca = c1.intpow(self.b - fake + 1) * self.pk.h.intpow(self.ra)

        # Check
        self.assertFalse(self.el.check(self.pk.g, self.pk.h, c1, self.pk.h, c2, ca))

    def test_el_modify_commitments(self):
        """
        Check if the Boudot commitment equality fails if the shadow+commitment messages change.
        """
        fake = 8

        # Commitment
        c = self.pk.g.intpow(fake) * self.pk.h.intpow(self.r)
        c1 = c // (self.pk.g.intpow(self.a - 1))
        c2 = self.pk.g.intpow(self.b + 1) // c

        # Shadow commitment
        ca = c1.intpow(self.b - fake + 1) * self.pk.h.intpow(self.ra)

        # Check
        self.assertFalse(self.el.check(self.pk.g, self.pk.h, c1, self.pk.h, c2, ca))

    def test_sqr(self):
        """
        Check if the Boudot commitment-is-square holds.
        """
        sqr = SQR.create(4, 81, self.pk.g, self.pk.h, self.b, self.bitspace)
        self.assertTrue(sqr.check(self.pk.g, self.pk.h, self.pk.g.intpow(16) * self.pk.h.intpow(81)))

    def test_sqr_modify_commitment(self):
        """
        Check if the Boudot commitment-is-square fails if the commitment message changes.
        """
        sqr = SQR.create(9, 81, self.pk.g, self.pk.h, self.b, self.bitspace)
        self.assertFalse(sqr.check(self.pk.g, self.pk.h, self.pk.g.intpow(16) * self.pk.h.intpow(81)))

    def test_sqr_modify_shadow_commitment(self):
        """
        Check if the Boudot commitment-is-square fails if the shadow commitment message changes.
        """
        sqr = SQR.create(4, 81, self.pk.g, self.pk.h, self.b, self.bitspace)
        self.assertFalse(sqr.check(self.pk.g, self.pk.h, self.pk.g.intpow(9) * self.pk.h.intpow(81)))

    def test_sqr_serialize(self):
        """
        Check if Boudot commitment-is-square checks are correctly serialized.
        """
        el = EL(77692238748522549651683873494184958254240308467748145113388211342290056191907,
                310768954994090198606735493976739833016961233870992580453552845369160224769115,
                1378784829646587776157777333351527905785206201874845030390922605077647796646962410317344630260602014,
                -5515139318586351104624816262067481296619038413746351139945096955324703586833572052593411867046643126)
        sqr = SQR(FP2Value(self.pk.g.mod, 866182580282760557469, 886537163949459823689), el)

        self.assertEqual(self.sqr, sqr)
