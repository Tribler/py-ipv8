import json

from ....attestation.identity.database import IdentityDatabase
from ....attestation.identity.manager import IdentityManager
from ....keyvault.crypto import ECCrypto
from ...base import TestBase


class TestIdentityManager(TestBase):
    """
    Tests related to the identity manager.
    """

    def setUp(self) -> None:
        """
        Create a new identity manager for testing.
        """
        super().setUp()
        self.crypto = ECCrypto()
        self.private_key = self.crypto.generate_key("curve25519")
        self.public_key = self.private_key.pub()
        self.authority_private_key = self.crypto.generate_key("curve25519")
        self.authority_public_key = self.authority_private_key.pub()
        self.manager = IdentityManager()

    def forget_identities(self) -> None:
        """
        Drop all identity information from our memory database.
        """
        self.manager.pseudonyms.clear()
        self.manager.database = IdentityDatabase(":memory:")
        self.manager.database.open()

    def test_create_identity(self) -> None:
        """
        Test if a new pseudonym is correctly created.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)

        self.assertEqual([], pseudonym.get_credentials())

    def test_substantiate_empty(self) -> None:
        """
        Check if an empty identity disclosure is loaded and valid.
        """
        valid, pseudonym = self.manager.substantiate(self.public_key, b'', b'', b'', b'')

        self.assertTrue(valid)
        self.assertEqual([], pseudonym.get_credentials())

    def test_create_credential(self) -> None:
        """
        Test creating a credential without attestations.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})

        self.assertEqual(1, len(pseudonym.get_credentials()))
        self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))
        self.assertDictEqual({'some_key': 'some_value'},
                             json.loads(pseudonym.get_credentials()[0].metadata.serialized_json_dict))

    def test_substantiate_credential_update(self) -> None:
        """
        Test substantiating a credential without attestations, with existing metadata.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})
        metadata, tokens, attestations, authorities = pseudonym.disclose_credentials(pseudonym.get_credentials(), set())

        self.manager.pseudonyms.clear()

        valid, public_pseudonym = self.manager.substantiate(pseudonym.public_key, metadata, tokens, attestations,
                                                            authorities)

        self.assertTrue(valid)
        self.assertEqual(1, len(public_pseudonym.get_credentials()))
        self.assertEqual(0, len(public_pseudonym.get_credentials()[0].attestations))
        self.assertDictEqual({'some_key': 'some_value'},
                             json.loads(public_pseudonym.get_credentials()[0].metadata.serialized_json_dict))

    def test_substantiate_credential_no_metadata(self) -> None:
        """
        Test substantiating a credential without attestations, without metadata.

        This situation is a bit tricky:
         - The path to the root from the one disclosed Token is valid.
         - No Metadata is known for this Token and it therefore does not form a credential.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})
        metadata, tokens, attestations, authorities = pseudonym.disclose_credentials(pseudonym.get_credentials(), set())

        self.forget_identities()

        valid, public_pseudonym = self.manager.substantiate(pseudonym.public_key, b'', tokens, attestations,
                                                            authorities)

        self.assertTrue(valid)
        self.assertEqual(0, len(public_pseudonym.get_credentials()))
        self.assertEqual(1, len(public_pseudonym.tree.elements))

    def test_substantiate_credential_with_metadata(self) -> None:
        """
        Test substantiating a credential without attestations.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})
        metadata, tokens, attestations, authorities = pseudonym.disclose_credentials(pseudonym.get_credentials(), set())

        self.forget_identities()

        valid, public_pseudonym = self.manager.substantiate(pseudonym.public_key, metadata, tokens, attestations,
                                                            authorities)

        self.assertTrue(valid)
        self.assertEqual(1, len(public_pseudonym.get_credentials()))
        self.assertEqual(0, len(public_pseudonym.get_credentials()[0].attestations))
        self.assertDictEqual({'some_key': 'some_value'},
                             json.loads(public_pseudonym.get_credentials()[0].metadata.serialized_json_dict))

    def test_substantiate_credential_full(self) -> None:
        """
        Test substantiating a typical credential.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})

        attestation = pseudonym.create_attestation(pseudonym.get_credentials()[0].metadata, self.authority_private_key)
        pseudonym.add_attestation(self.authority_public_key, attestation)

        metadata, tokens, attestations, authorities = pseudonym.disclose_credentials(pseudonym.get_credentials(),
                                                                                     {attestation.get_hash()})

        self.forget_identities()

        valid, public_pseudonym = self.manager.substantiate(pseudonym.public_key, metadata, tokens, attestations,
                                                            authorities)

        self.assertTrue(valid)
        self.assertEqual(1, len(public_pseudonym.get_credentials()))
        self.assertEqual(1, len(public_pseudonym.get_credentials()[0].attestations))
        self.assertDictEqual({'some_key': 'some_value'},
                             json.loads(public_pseudonym.get_credentials()[0].metadata.serialized_json_dict))

    def test_substantiate_credential_partial(self) -> None:
        """
        Test substantiating a typical credential, with partial disclosure.
        """
        pseudonym = self.manager.get_pseudonym(self.private_key)
        pseudonym.create_credential(b'ab' * 16, {'some_key': 'some_value'})

        attestation = pseudonym.create_attestation(pseudonym.get_credentials()[0].metadata, self.authority_private_key)
        pseudonym.add_attestation(self.authority_public_key, attestation)

        attestation2 = pseudonym.create_attestation(pseudonym.get_credentials()[0].metadata, self.private_key)
        pseudonym.add_attestation(self.public_key, attestation2)

        metadata, tokens, attestations, authorities = pseudonym.disclose_credentials(pseudonym.get_credentials(),
                                                                                     {attestation.get_hash()})

        self.forget_identities()

        valid, public_pseudonym = self.manager.substantiate(pseudonym.public_key, metadata, tokens, attestations,
                                                            authorities)

        self.assertTrue(valid)
        self.assertEqual(1, len(public_pseudonym.get_credentials()))
        self.assertEqual(1, len(public_pseudonym.get_credentials()[0].attestations))
        self.assertDictEqual({'some_key': 'some_value'},
                             json.loads(public_pseudonym.get_credentials()[0].metadata.serialized_json_dict))
