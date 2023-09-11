from .....attestation.default_identity_formats import FORMATS
from .....attestation.wallet.irmaexact.algorithm import IRMAExactAlgorithm
from ....base import TestBase


class TestAlgorithm(TestBase):
    """
    Tests related to the IRMA algorithm definition.
    """

    def setUp(self) -> None:
        """
        Create a dummy blob for testing.
        """
        super().setUp()
        self.blob = """
        {
            "sign_date": 2586,
            "proofd": "0120ae8c08383eb6326ed4d690472c14167157ba95bddfc6eb961475d11146c78b7702010014ca54a5ca54059afa2ef17b9a8826082f01dc75a58cae5ec18a3b3f93b5de357dbb5b7a326f9ffb67aef043f7706dddd272c9b5e46d48598975bbb22ad28fbeda52e1384fc39edbfae6d48d6cb03148dd0b3bc7cf13b594529c3d9c9f325e847add7d8cf1007e8f8fb5cc4cedca88e9f4ebcc69eba22741e8ede9744677be96df68ad0f689052264e8ddd67f15b89ca106f9424efe0936fc3ea567573900a39254c28b9fcb4c805de6a55d13b716aac4669ed9f4620e98ed54012f4dfa633769e510961296e228f5152c1152b760ff58ebe964dd84bf9a6b39da9b4acee1cedcab3576d95dcffbd9cdea6bf61726f0468b2f405e825103bcb20763d0f69decb013f2425ecd45cf8d8a8e6feabcb2c7dbddce283c494fc309451dc310f3ca36de5e2bab532d50734bcbe250bcdae7cc7b6e978e2dfe5c4c11521aa4326b7683c91020191083b68a01f222fa9a6260d0b40bce3669a7dad64c9ec6bdb7418865f6c07aa616e06fbeb314f32f6f8d9773acc4cf96667044007a5e8f8364c67884219ddc84057f94f06c8c3677f8483da72a99ed05976856ca1597ecc3164d7f4236736b64b6b656e7bef4bfd30cfd51bcb4bef990ca0ff88b5b0cae9df789acb34dc6e34d3daf125e7ba13d34d70b3ba2085a85f1f5e5e39f704cd8af7787ec29f204b258abfe9fbfa644e79ac384f15817fb181255b57f1f8e3c6fae041422feb8786259356287266410ee4cf595418bcb392367ed17b8c3dbfd87c97d338dc919c99579294d301fcb54dcfde75f21ae310a390473e7801a9f5c339a861c50f5836175a92f31327c6b8fe82ff7bfb6a915cfe3a950765f5a4261ce1b22146435fe4aaf93e5a0e3e6febcc0542615dbfb0b1ab4bc09e3a1f7c4be574a268a5c9fd255cadf53d0924783965109f6de678210e6bd1ed66a3a11081e0958f20d01860208d1d2b7419576131e4e5759729defb2eceb0ec413fa2c1bb76a3f60fb1c41397c2d50f127be92d3dfc42bfd44d68dee28ce0617c0150d945cc7a583966ae5dc8e8340c24d2004eeaef1e073c6d2e71a55eb0e0cb6ffa56dc9f217631445bb8157548f7ddc735bb703f89e644d4ac6a5c5453312dae28b4c184e4b089f3c18ceec147f844b940",
            "z": 21025909574607652013242068407286517850424307678122890876135156101653321984092105929057125603368801791220668605323274805950534554333885095151891554345408081373199060099202339143424919643961351117275291540867055856626869631650968369803183902895146289487368006719436569169044553294877369014424433240847941963958916265623517330529414890418453511520187847786782916076948797140109695922159477047382915875554999783288589498520057591077035129853458855982695920607696398615002875185515097109401895544388882159438043913551570342780281962902283409019706410544114516101827596857844194407086012298321703512788196253222325858419223
        }
        """

    def test_integration(self) -> None:
        """
        Test whether blobs can be imported and challenged.
        """
        id_format = "id_irma_nijmegen_ageLimits_1568208470"
        algorithm = IRMAExactAlgorithm(id_format, FORMATS)
        attestation_blob, _ = algorithm.import_blob(self.blob)
        attestation = algorithm.get_attestation_class().unserialize_private(None, attestation_blob, id_format)
        attestation_public = attestation.unserialize(attestation.serialize(), id_format)

        aggregate = algorithm.create_certainty_aggregate(attestation_public)
        challenges = algorithm.create_challenges(None, attestation_public)
        for challenge in challenges:
            response = algorithm.create_challenge_response(None, attestation, challenge)
            algorithm.process_challenge_response(aggregate, challenge, response)

        value = '{"over16": "Yes", "over12": "Yes", "over21": "Yes", "over65": "No", "over18": "Yes"}'
        self.assertEqual(1.0, algorithm.certainty(value, aggregate))

    def test_integration_incomplete(self) -> None:
        """
        Check whether blobs can be imported and partially challenged.
        """
        id_format = "id_irma_nijmegen_ageLimits_1568208470"
        algorithm = IRMAExactAlgorithm(id_format, FORMATS)

        attestation_blob, _ = algorithm.import_blob(self.blob)
        attestation = algorithm.get_attestation_class().unserialize_private(None, attestation_blob, id_format)
        attestation_public = attestation.unserialize(attestation.serialize(), id_format)

        aggregate = algorithm.create_certainty_aggregate(attestation_public)
        challenges = algorithm.create_challenges(None, attestation_public)
        for challenge in challenges[:-1]:
            response = algorithm.create_challenge_response(None, attestation, challenge)
            algorithm.process_challenge_response(aggregate, challenge, response)

        value = '{"over16": "Yes", "over12": "Yes", "over21": "Yes", "over65": "No", "over18": "Yes"}'
        self.assertEqual((algorithm.challenge_count - 1.0) / len(challenges), algorithm.certainty(value, aggregate))

    def test_integration_wrong(self) -> None:
        """
        Check whether bad responses lead to 0% certainty.
        """
        id_format = "id_irma_nijmegen_ageLimits_1568208470"
        algorithm = IRMAExactAlgorithm(id_format, FORMATS)

        attestation_blob, _ = algorithm.import_blob(self.blob)
        attestation = algorithm.get_attestation_class().unserialize_private(None, attestation_blob, id_format)
        attestation_public = attestation.unserialize(attestation.serialize(), id_format)

        aggregate = algorithm.create_certainty_aggregate(attestation_public)
        challenges = algorithm.create_challenges(None, attestation_public)
        for challenge in challenges:
            response = algorithm.create_challenge_response(None, attestation, challenge)
            algorithm.process_challenge_response(aggregate, challenge, response)

        value = '{"over16": "Yes", "over12": "Yes", "over21": "Yes", "over65": "Yes", "over18": "Yes"}'
        self.assertEqual(0.0, algorithm.certainty(value, aggregate))
