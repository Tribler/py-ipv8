import json

from ...base import MockIPv8, TestBase
from ....attestation.identity.community import IdentityCommunity
from ....attestation.identity.manager import IdentityManager
from ....peer import Peer


class TestIdentityCommunity(TestBase):

    FAKE_HASH = b'a' * 32

    def setUp(self):
        super(TestIdentityCommunity, self).setUp()
        self.initialize(IdentityCommunity, 2)

    def create_node(self):
        identity_manager = IdentityManager(u":memory:")
        return MockIPv8(u"curve25519", IdentityCommunity, identity_manager=identity_manager)

    def peer(self, i):
        return Peer(self.nodes[i].my_peer.public_key.key_to_bin(), self.nodes[i].endpoint.wan_address)

    def key_bin(self, i):
        return self.nodes[i].my_peer.public_key.key_to_bin()

    def overlay(self, i):
        return self.nodes[i].overlay

    async def test_advertise(self):
        """
        Check if a node can construct an advertisement for his attested attribute.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(1, len(pseudonym.get_credentials()))
            self.assertEqual(1, len(pseudonym.get_credentials()[0].attestations))

    async def test_advertise_twice(self):
        """
        Check if a node can construct two attributes.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        self.overlay(1).add_known_hash(self.FAKE_HASH[:-1] + b'b', "attribute", self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(2, len(pseudonym.get_credentials()))
            self.assertEqual(1, len(pseudonym.get_credentials()[0].attestations))
            self.assertEqual(1, len(pseudonym.get_credentials()[1].attestations))

    async def test_advertise_big(self):
        """
        Check if a node can construct an advertisement for his attested attribute, having more than 32 attributes.
        """
        await self.introduce_nodes()

        for i in range(39):
            self.overlay(0).self_advertise(self.FAKE_HASH[:-1] + bytes([i]), "attribute" + str(i))
        self.overlay(1).add_known_hash(self.FAKE_HASH[:-1] + bytes([39]), "attribute" + str(39), self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH[:-1] + bytes([39]),
                                                          "attribute" + str(39))

        await self.deliver_messages()
        from asyncio import sleep
        await sleep(.5)

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(40, len(pseudonym.tree.elements))
            self.assertEqual(40 if node_nr == 0 else 1, len(pseudonym.get_credentials()))

    async def test_advertise_metadata(self):
        """
        Check if a node can construct an advertisement for his attested attribute with metadata.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(0), {"a": "b"})
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute", "id_metadata",
                                                          {"a": "b"})

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(1, len(pseudonym.get_credentials()))
            self.assertEqual(1, len(pseudonym.get_credentials()[0].attestations))
            self.assertIn("a", json.loads(pseudonym.get_credentials()[0].metadata.serialized_json_dict))
            self.assertEqual("b", json.loads(pseudonym.get_credentials()[0].metadata.serialized_json_dict)["a"])

    async def test_advertise_metadata_reject(self):
        """
        Check if a node cannot construct an advertisement for his attested attribute with wrong metadata.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(0), {"c": "d"})
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute", "id_metadata",
                                                          {"a": "b"})

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(1, len(pseudonym.get_credentials()))
            self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))

    async def test_advertise_reject_hash(self):
        """
        Check if unknown hashes are not signed.
        """
        await self.introduce_nodes()

        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        pseudonym = self.overlay(0).identity_manager.get_pseudonym(self.peer(0).public_key)
        self.assertEqual(1, len(pseudonym.get_credentials()))
        self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))

        pseudonym = self.overlay(1).identity_manager.get_pseudonym(self.peer(0).public_key)
        self.assertEqual(0, len(pseudonym.get_credentials()))

    async def test_advertise_reject_public_key(self):
        """
        Check if we don't sign correct hashes for the wrong peer.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(1))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        pseudonym = self.overlay(0).identity_manager.get_pseudonym(self.peer(0).public_key)
        self.assertEqual(1, len(pseudonym.get_credentials()))
        self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))

        pseudonym = self.overlay(1).identity_manager.get_pseudonym(self.peer(0).public_key)
        self.assertEqual(0, len(pseudonym.get_credentials()))

    async def test_advertise_reject_old(self):
        """
        Check if we don't sign old attestations.
        """
        await self.introduce_nodes()

        self.overlay(1).known_attestation_hashes[self.FAKE_HASH] = ("attribute", 0, self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attribute")

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(1, len(pseudonym.get_credentials()))
            self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))

    async def test_advertise_reject_wrong_name(self):
        """
        Check if we don't sign attestations with incorrect metadata.
        """
        await self.introduce_nodes()

        self.overlay(1).add_known_hash(self.FAKE_HASH, "attribute", self.key_bin(0))
        self.overlay(0).request_attestation_advertisement(self.peer(1), self.FAKE_HASH, "attr1bute")

        await self.deliver_messages()

        for node_nr in [0, 1]:
            pseudonym = self.overlay(node_nr).identity_manager.get_pseudonym(self.peer(0).public_key)

            self.assertEqual(1, len(pseudonym.get_credentials()))
            self.assertEqual(0, len(pseudonym.get_credentials()[0].attestations))
