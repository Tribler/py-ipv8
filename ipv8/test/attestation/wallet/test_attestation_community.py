import os
from binascii import unhexlify

from ...base import MockIPv8, TestBase
from ....attestation.wallet.bonehexact.structs import BonehAttestation
from ....attestation.wallet.community import AttestationCommunity
from ....attestation.wallet.database import AttestationsDB
from ....attestation.wallet.pengbaorange.structs import PengBaoAttestation
from ....attestation.wallet.primitives.structs import BonehPrivateKey


class TestCommunity(TestBase):

    private_key = BonehPrivateKey.unserialize(unhexlify("01064c65dcb113f901064228da3ea57101064793a4f9c77901062b083e"
                                                        "8690fb0106408293c67e9f010601d1a9d3744901030f4243"))

    def setUp(self):
        super(TestCommunity, self).setUp()
        self.initialize(AttestationCommunity, 2)

    def create_node(self):
        return MockIPv8(u"curve25519", AttestationCommunity, working_directory=u":memory:")

    async def test_request_attestation_callback(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name, metadata):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")
            self.assertDictEqual(metadata, {})

            f.called = True
        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key)

        await self.deliver_messages()

        self.assertTrue(f.called)
        # Request for attribute attestation goes unanswered
        self.overlay(1).request_cache.clear()

    async def test_request_attestation_twice_callback(self):
        """
        Check if the request_attestation callback is correctly called twice in a row.
        """

        def f(peer, attribute_name, metadata):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")
            self.assertDictEqual(metadata, {})

            f.called.append(True)

        f.called = []

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key)
        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key)

        await self.deliver_messages()

        self.assertListEqual([True, True], f.called)
        # Request for attribute attestation goes unanswered
        self.overlay(1).request_cache.clear()

    async def test_request_attestation_callback_metadata(self):
        """
        Check if the request_attestation callback is correctly called with metadata.
        """

        def f(peer, attribute_name, metadata):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")
            self.assertDictEqual(metadata, {u'test': 123})

            f.called = True

        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key, {'test': 123})

        await self.deliver_messages()

        self.assertTrue(f.called)
        # Request for attribute attestation goes unanswered
        self.overlay(1).request_cache.clear()

    async def test_request_attestation(self):
        """
        Check if the request_attestation callback is correctly called.
        """
        def f(peer, attribute_name, _, __=None):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True
        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(lambda x, y, z: b"AttributeValue")
        self.overlay(0).set_attestation_request_complete_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key)

        await self.deliver_messages(0.5)

        db_entries = self.overlay(1).database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

    async def test_request_attestation_big(self):
        """
        Check if the request_attestation callback is correctly called for id_metadata_big.
        """

        def f(peer, attribute_name, _, __=None):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True

        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(lambda x, y, z: b"AttributeValue")
        self.overlay(0).set_attestation_request_complete_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key,
                                            metadata={"id_format": "id_metadata_big"})

        await self.deliver_messages(1.5)

        db_entries = self.overlay(1).database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

    async def test_request_attestation_range(self):
        """
        Check if the request_attestation callback is correctly called for id_metadata_range_18plus.
        """

        def f(peer, attribute_name, _, __=None):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")

            f.called = True

        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(lambda x, y, z: b"\x13")
        self.overlay(0).set_attestation_request_complete_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key,
                                            metadata={"id_format": "id_metadata_range_18plus"})

        await self.deliver_messages(2.0)

        db_entries = self.overlay(1).database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

    async def test_verify_attestation(self):
        """
        Check if an attestation can be verified.
        """
        serialized = ""
        filename = os.path.join(os.path.dirname(__file__), 'attestation.txt')
        with open(filename, 'r') as f:
            serialized = unhexlify(f.read().strip())
        attestation = BonehAttestation.unserialize(serialized, "id_metadata")
        attestation_hash = unhexlify('9019195eb75c07ec3e86a62c314dcf5ef2bbcc0d')
        self.overlay(0).database.insert_attestation(attestation, attestation_hash, TestCommunity.private_key,
                                                    "id_metadata")
        self.overlay(0).attestation_keys[attestation_hash] = (TestCommunity.private_key, "id_metadata")

        def callback(rhash, values):
            self.assertEqual(attestation_hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True
        callback.called = False
        self.overlay(1).verify_attestation_values(self.address(0), attestation_hash, [b"MyAttribute"], callback,
                                                  "id_metadata")

        await self.deliver_messages(0.5)

        self.assertTrue(callback.called)
        self.overlay(1).request_cache.clear()

    async def test_reqandverif_attestation(self):
        attribute_value = b"2168897456"

        def f(peer, attribute_name, attestation_hash, __=None):
            self.assertEqual(peer.address, self.address(1))
            self.assertEqual(attribute_name, "MyAttribute")

            f.attestation_hash = attestation_hash
            f.called = True

        f.called = False

        await self.introduce_nodes()

        self.overlay(0).set_attestation_request_callback(lambda x, y, z: attribute_value)
        self.overlay(0).set_attestation_request_complete_callback(f)

        self.overlay(1).request_attestation(self.my_peer(0), "MyAttribute", TestCommunity.private_key)

        await self.deliver_messages(0.5)

        db_entries = self.overlay(1).database.get_all()
        self.assertEqual(1, len(db_entries))
        self.assertTrue(f.called)

        def callback(rhash, values):
            self.assertEqual(f.attestation_hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True
        callback.called = False
        self.overlay(0).verify_attestation_values(self.address(1), f.attestation_hash, [attribute_value], callback,
                                                  "id_metadata")

        await self.deliver_messages(0.5)

        self.assertTrue(callback.called)
        self.overlay(0).request_cache.clear()

    async def test_verify_attestation_big(self):
        """
        Check if an attestation can be verified for id_metadata_big.
        """
        filename = os.path.join(os.path.dirname(__file__), 'attestation_big.txt')
        with open(filename, 'r') as f:
            serialized = unhexlify(f.read().strip())
        attestation = BonehAttestation.unserialize(serialized, "id_metadata_big")
        attestation_hash = unhexlify('113d31c31b626268a16c198cbd58dd5aa8d1d81c')
        self.overlay(0).database.insert_attestation(attestation, attestation_hash, TestCommunity.private_key,
                                                    "id_metadata_big")
        self.overlay(0).attestation_keys[attestation_hash] = (TestCommunity.private_key, "id_metadata_big")

        def callback(rhash, values):
            self.assertEqual(attestation_hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True

        callback.called = False
        self.overlay(1).verify_attestation_values(self.address(0), attestation_hash, [b"AttributeValue"], callback,
                                                  "id_metadata_big")

        await self.deliver_messages(1.5)

        self.assertTrue(callback.called)
        self.overlay(1).request_cache.clear()

    async def test_verify_attestation_range(self):
        """
        Check if an attestation can be verified for id_metadata_range_18plus.
        """
        filename = os.path.join(os.path.dirname(__file__), 'attestation_range.txt')
        with open(filename, 'r') as f:
            serialized = unhexlify(f.read().strip())
        attestation = PengBaoAttestation.unserialize_private(self.private_key, serialized, "id_metadata_range_18plus")
        attestation_hash = unhexlify('b40c8734ba6c91a49670c1f0152c7f4dac2a8272')
        self.overlay(0).database.insert_attestation(attestation, attestation_hash, TestCommunity.private_key,
                                                    "id_metadata_range_18plus")
        self.overlay(0).attestation_keys[attestation_hash] = (TestCommunity.private_key, "id_metadata_range_18plus")

        def callback(rhash, values):
            self.assertEqual(attestation_hash, rhash)
            self.assertEqual(1, len(values))
            self.assertLess(0.99, values[0])
            callback.called = True

        callback.called = False
        self.overlay(1).verify_attestation_values(self.address(0), attestation_hash, [b"\x01"], callback,
                                                  "id_metadata_range_18plus")

        await self.deliver_messages(2.5)

        self.assertTrue(callback.called)
        self.overlay(1).request_cache.clear()

    def test_load_key(self):
        """
        Check if we can load the community correctly after shut down.
        """
        # Write to a temporary folder.
        temp_folder = self.temporary_directory()
        self.overlay(0).database = AttestationsDB(temp_folder, "test")

        # Create an attestation and write it to file.
        # Then close the database.
        attestation = BonehAttestation(TestCommunity.private_key.public_key(), [], "id_metadata")
        self.overlay(0).on_attestation_complete(attestation, TestCommunity.private_key, None, "test", b"a" * 20,
                                                "id_metadata")
        self.overlay(0).database.close(True)

        # Reload the community with the same database.
        self.overlay(0).__init__(self.my_peer(0), self.endpoint(0), self.network(0), working_directory=temp_folder,
                                 db_name="test")

        # The attestation should persist
        db_entries = self.overlay(0).database.get_all()
        self.assertEqual(1, len(db_entries))
