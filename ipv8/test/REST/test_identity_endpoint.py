from __future__ import annotations

import base64
import json
import urllib.parse
from typing import TYPE_CHECKING, cast

from ...attestation.communication_manager import CommunicationChannel, CommunicationManager, PseudonymFolderManager
from ...attestation.default_identity_formats import FORMATS
from ...attestation.identity.community import IdentityCommunity, IdentitySettings
from ...attestation.identity.manager import IdentityManager
from ...attestation.wallet.community import AttestationCommunity, AttestationSettings
from ...REST.identity_endpoint import IdentityEndpoint
from ..base import TestBase
from ..mocking.endpoint import AutoMockEndpoint
from .rest_base import MockRequest, response_to_json

if TYPE_CHECKING:
    from ...community import CommunitySettings
    from ...types import PrivateKey
    from ..mocking.ipv8 import MockIPv8


class MockPseudonymFolderManager(PseudonymFolderManager):
    """
    Mock the OS file system using a dictionary as to mock files in a folder.
    """

    def __init__(self) -> None:
        """
        Create a new mocked pseudonym folder manager.
        """
        super().__init__(".")
        self.folder_contents: dict[str, PrivateKey] = {}

    def get_or_create_private_key(self, name: str) -> PrivateKey:
        """
        Generate or load a new key in memory.
        """
        if name in self.folder_contents:
            return self.crypto.key_from_private_bin(self.folder_contents[name])
        private_key = self.crypto.generate_key("curve25519")
        self.folder_contents[name] = private_key
        return private_key

    def remove_pseudonym_file(self, name: str) -> None:
        """
        Remove the given "folder" in the dictionary, i.e., a key.
        """
        self.folder_contents.pop(name, None)

    def list_pseudonym_files(self) -> list[str]:
        """
        Retrieve the "folders", i.e., keys, in the fake file structure.
        """
        return list(self.folder_contents)


class TestIdentityEndpoint(TestBase[IdentityCommunity]):
    """
    Class for testing the REST API of the IdentityEndpoint.
    """

    async def setUp(self) -> None:
        """
        Set up an identity community, memory identity manager and memory pseudonym folder manager.
        """
        super().setUp()

        self.endpoints = []
        self.pseudonym_directories: dict[str, bytes] = {}  # Pseudonym to key-bytes mapping

        self.initialize(IdentityCommunity, 2, IdentitySettings(identity_manager=IdentityManager(":memory:"),
                                                               working_directory=":memory:"))

    def create_node(self, settings: CommunitySettings | None = None, create_dht: bool = False,
                          enable_statistics: bool = False) -> MockIPv8:
        """
        We load each node i with a pseudonym `my_peer{i}`, which is the default IPv8 `my_peer` key.
        """
        self.endpoints.append(IdentityEndpoint())
        ipv8 = super().create_node(settings, create_dht, enable_statistics)
        peer_num = len(self.pseudonym_directories)
        key_file_name = "my_peer" + str(peer_num)
        self.pseudonym_directories[key_file_name] = ipv8.my_peer.key.key_to_bin()

        communication_manager = CommunicationManager(ipv8, working_directory=":memory:")
        communication_manager.pseudonym_folder_manager = MockPseudonymFolderManager()
        communication_manager.pseudonym_folder_manager.get_or_create_private_key(key_file_name)

        identity_overlay = cast(IdentityCommunity, ipv8.get_overlay(IdentityCommunity))
        attestation_overlay = AttestationCommunity(AttestationSettings(my_peer=identity_overlay.my_peer,
                                                                       endpoint=identity_overlay.endpoint,
                                                                       network=identity_overlay.network,
                                                                       working_directory=":memory:"))
        channel = CommunicationChannel(attestation_overlay, identity_overlay)

        communication_manager.channels[ipv8.my_peer.public_key.key_to_bin()] = channel
        communication_manager.name_to_channel[key_file_name] = channel
        self.pseudonym_directories[key_file_name] = ipv8.my_peer.key.key_to_bin()
        self.rest_ep(peer_num).communication_manager = communication_manager

        return ipv8

    def rest_ep(self, i: int) -> IdentityEndpoint:
        """
        Shortcut to the REST endpoint of node i.
        """
        return self.endpoints[i]

    def communication_manager(self, i: int) -> CommunicationManager:
        """
        Shortcut to the communication manager of node i.
        """
        return self.rest_ep(i).communication_manager

    async def clear_pseudonyms(self) -> None:
        """
        We set up our tests with one pseudonym per peer by default: get rid of them.
        """
        for peer_id in range(2):
            await self.rest_ep(peer_id).remove_pseudonym(
                MockRequest(f"identity/my_peer{peer_id}/remove", match_info={"pseudonym_name": f"my_peer{peer_id}"})
            )

    async def introduce_pseudonyms(self) -> None:
        """
        Figure out the ephemeral communities of each node and introduce them to each other.
        """
        all_interfaces = [[cast(AutoMockEndpoint, overlay.endpoint).wan_address for overlay in node.overlays
                           if isinstance(overlay, IdentityCommunity)] for node in self.nodes]
        for i in range(len(self.nodes)):
            other_addresses = list(range(len(self.nodes)))
            other_addresses.remove(i)
            for j in other_addresses:
                for overlay in self.node(i).overlays:
                    if isinstance(overlay, IdentityCommunity):
                        for address in all_interfaces[j]:
                            overlay.walk_to(address)
            await self.deliver_messages()

    async def test_list_pseudonyms_empty(self) -> None:
        """
        Check that we do not start with any pseudonyms.
        """
        await self.clear_pseudonyms()

        result = await response_to_json(await self.rest_ep(0).list_pseudonyms(MockRequest(path="identity")))

        self.assertDictEqual({"names": []}, result)

    async def test_list_schemas(self) -> None:
        """
        Check that the endpoint reports the available schemas correctly.
        """
        result = await self.rest_ep(0).list_schemas(MockRequest("identity/test_pseudonym/schemas",
                                                                match_info={"pseudonym_name": "test_pseudonym"}))
        schemas = await response_to_json(result)

        self.assertSetEqual(set(FORMATS.keys()), set(schemas["schemas"]))

    async def test_list_pseudonyms_one(self) -> None:
        """
        Check that a loaded pseudonym is reported as such.
        """
        result = await response_to_json(await self.rest_ep(0).list_pseudonyms(MockRequest(path="identity")))

        self.assertDictEqual({"names": ["my_peer0"]}, result)

    async def test_list_pseudonyms_many(self) -> None:
        """
        Check that all loaded pseudonyms are reported as such.
        """
        pseudonyms = ["test_pseudonym1", "test_pseudonym2", "test_pseudonym3", "test_pseudonym4"]
        for pseudonym in pseudonyms:
            await self.rest_ep(0).list_schemas(MockRequest(f"identity/{pseudonym}/schemas",
                                                           match_info={"pseudonym_name": pseudonym}))

        result = await response_to_json(await self.rest_ep(0).list_pseudonyms(MockRequest(path="identity")))

        self.assertSetEqual(set(pseudonyms) | {"my_peer0"}, set(result["names"]))

    async def test_list_public_key_one(self) -> None:
        """
        Check that we retrieve the pseudonym public key correctly.
        """
        result = await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/test_pseudonym/public_key", match_info={"pseudonym_name": "test_pseudonym"})
        ))
        decoded_public_key = base64.b64decode(result["public_key"])

        # This should have made the `test_pseudonym` private key file (corresponding to the reported public key).
        private_key = self.communication_manager(0).pseudonym_folder_manager.folder_contents["test_pseudonym"]

        self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_public_key_many(self) -> None:
        """
        Check that we retrieve the pseudonym public key correctly.
        """
        pseudonyms = ["test_pseudonym1", "test_pseudonym2", "test_pseudonym3", "test_pseudonym4"]
        # Make sure all pseudonyms exist before querying their keys.
        # This is not necessary, but has the highest chance of exposing failures.
        for pseudonym in pseudonyms:
            await self.rest_ep(0).list_schemas(MockRequest(f"identity/{pseudonym}/schemas",
                                                           match_info={"pseudonym_name": pseudonym}))
        for pseudonym in pseudonyms:
            result = await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
                MockRequest(f"identity/{pseudonym}/public_key", match_info={"pseudonym_name": pseudonym})
            ))
            decoded_public_key = base64.b64decode(result["public_key"])

            private_key = self.communication_manager(0).pseudonym_folder_manager.folder_contents[pseudonym]

            self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_peers(self) -> None:
        """
        Check if peers are correctly listed.
        """
        await self.clear_pseudonyms()  # Start from nothing

        result1 = await response_to_json(await self.rest_ep(0).list_pseudonym_peers(
            MockRequest("identity/my_peer0/peers", match_info={"pseudonym_name": "my_peer0"})
        ))
        result2 = await response_to_json(await self.rest_ep(1).list_pseudonym_peers(
            MockRequest("identity/my_peer1/peers", match_info={"pseudonym_name": "my_peer1"})
        ))

        self.assertListEqual([], result1["peers"])
        self.assertListEqual([], result2["peers"])

        await self.introduce_pseudonyms()  # After walking, the peers should show up

        result1 = await response_to_json(await self.rest_ep(0).list_pseudonym_peers(
            MockRequest("identity/my_peer0/peers", match_info={"pseudonym_name": "my_peer0"})
        ))
        result2 = await response_to_json(await self.rest_ep(1).list_pseudonym_peers(
            MockRequest("identity/my_peer1/peers", match_info={"pseudonym_name": "my_peer1"})
        ))

        self.assertEqual(1, len(result1["peers"]))
        self.assertEqual(1, len(result2["peers"]))

    async def test_list_unload(self) -> None:
        """
        Check if a pseudonym stops communicating on unload.
        """
        await self.rest_ep(0).unload_pseudonym(MockRequest("identity/my_peer0/unload",
                                                           match_info={"pseudonym_name": "my_peer0"}))
        await self.rest_ep(1).unload_pseudonym(MockRequest("identity/my_peer1/unload",
                                                           match_info={"pseudonym_name": "my_peer1"}))

        self.assertListEqual([], self.node(0).overlays)
        self.assertListEqual([], self.node(1).overlays)

    async def test_list_credentials_empty(self) -> None:
        """
        Check that we retrieve credentials correctly, if none exist.
        """
        result = await response_to_json(await self.rest_ep(0).list_pseudonym_credentials(
            MockRequest("identity/my_peer0/credentials", match_info={"pseudonym_name": "my_peer0"})
        ))

        self.assertListEqual([], result["names"])

    async def test_request_attestation(self) -> None:
        """
        Check that requesting an attestation works.
        """
        b64_subject_key = (await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/my_peer0/public_key", match_info={"pseudonym_name": "my_peer0"})
        )))["public_key"]
        b64_authority_key = (await response_to_json(await self.rest_ep(1).get_pseudonym_public_key(
            MockRequest("identity/my_peer1/public_key", match_info={"pseudonym_name": "my_peer1"})
        )))["public_key"]

        request = await response_to_json(await self.rest_ep(0).create_pseudonym_credential(
            MockRequest(f"identity/my_peer0/request/{urllib.parse.quote(b64_authority_key, safe='')}", "PUT", {
                "name": "My attribute",
                "schema": "id_metadata",
                "metadata": {}
            }, {"pseudonym_name": "my_peer0", "authority_key": b64_authority_key})
        ))
        self.assertTrue(request["success"])

        await self.deliver_messages()

        outstanding = await response_to_json(await self.rest_ep(1).list_pseudonym_outstanding_attestations(
            MockRequest("identity/my_peer1/outstanding/attestations", match_info={"pseudonym_name": "my_peer1"})
        ))

        self.assertEqual(1, len(outstanding["requests"]))
        self.assertEqual(b64_subject_key, outstanding["requests"][0]["peer"])
        self.assertEqual("My attribute", outstanding["requests"][0]["attribute_name"])
        self.assertDictEqual({}, json.loads(outstanding["requests"][0]["metadata"]))

    async def test_request_attestation_metadata(self) -> None:
        """
        Check that requesting an attestation with metadata works.
        """
        b64_subject_key = (await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/my_peer0/public_key", match_info={"pseudonym_name": "my_peer0"})
        )))["public_key"]
        b64_authority_key = (await response_to_json(await self.rest_ep(1).get_pseudonym_public_key(
            MockRequest("identity/my_peer1/public_key", match_info={"pseudonym_name": "my_peer1"})
        )))["public_key"]

        request = await response_to_json(await self.rest_ep(0).create_pseudonym_credential(
            MockRequest(f"identity/my_peer0/request/{urllib.parse.quote(b64_authority_key, safe='')}", "PUT", {
                "name": "My attribute",
                "schema": "id_metadata",
                "metadata": {"Some key": "Some value"}
            }, {"pseudonym_name": "my_peer0", "authority_key": b64_authority_key})
        ))
        self.assertTrue(request["success"])

        await self.deliver_messages()

        outstanding = await response_to_json(await self.rest_ep(1).list_pseudonym_outstanding_attestations(
            MockRequest("identity/my_peer1/outstanding/attestations", match_info={"pseudonym_name": "my_peer1"})
        ))

        self.assertEqual(1, len(outstanding["requests"]))
        self.assertEqual(b64_subject_key, outstanding["requests"][0]["peer"])
        self.assertEqual("My attribute", outstanding["requests"][0]["attribute_name"])
        self.assertDictEqual({"Some key": "Some value"}, json.loads(outstanding["requests"][0]["metadata"]))

    async def test_attest(self) -> None:
        """
        Check that attesting to an attestation request with metadata works.
        """
        b64_subject_key = (await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/my_peer0/public_key", match_info={"pseudonym_name": "my_peer0"})
        )))["public_key"]
        b64_authority_key = (await response_to_json(await self.rest_ep(1).get_pseudonym_public_key(
            MockRequest("identity/my_peer1/public_key", match_info={"pseudonym_name": "my_peer1"})
        )))["public_key"]
        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}

        await self.rest_ep(0).create_pseudonym_credential(
            MockRequest(f"identity/my_peer0/request/{urllib.parse.quote(b64_authority_key, safe='')}", "PUT", request,
                        {"pseudonym_name": "my_peer0", "authority_key": b64_authority_key})
        )
        await self.deliver_messages()

        result = await response_to_json(await self.rest_ep(1).attest_pseudonym_credential(
            MockRequest(f"identity/my_peer1/attest/{urllib.parse.quote(b64_subject_key, safe='')}", "PUT", {
                                             "name": "My attribute",
                                             "value": base64.b64encode(b'Some value').decode()
                        }, {"pseudonym_name": "my_peer1", "subject_key": b64_subject_key})
        ))
        self.assertTrue(result["success"])

        await self.deliver_messages()

        # How node 0 sees itself after receiving the attestation
        result = await response_to_json(await self.rest_ep(0).list_pseudonym_credentials(
            MockRequest("identity/my_peer0/credentials", match_info={"pseudonym_name": "my_peer0"})
        ))
        self.assertEqual(1, len(result["names"]))
        self.assertEqual("My attribute", result["names"][0]["name"])
        self.assertListEqual([b64_authority_key], result["names"][0]["attesters"])
        for k, v in metadata.items():
            self.assertIn(k, result["names"][0]["metadata"])
            self.assertEqual(v, result["names"][0]["metadata"][k])

        # How node 1 sees node 0 after making the attestation
        result = await response_to_json(await self.rest_ep(1).list_subject_credentials(
            MockRequest(f"identity/my_peer1/credentials/{urllib.parse.quote(b64_subject_key, safe='')}",
                        match_info={"pseudonym_name": "my_peer1", "subject_key": b64_subject_key})
        ))
        self.assertEqual(1, len(result["names"]))
        self.assertEqual("My attribute", result["names"][0]["name"])
        self.assertListEqual([b64_authority_key], result["names"][0]["attesters"])
        for k, v in metadata.items():
            self.assertIn(k, result["names"][0]["metadata"])
            self.assertEqual(v, result["names"][0]["metadata"][k])

    async def test_verify(self) -> None:
        """
        Check that verifying a credential works.
        """
        self.nodes.append(self.create_node(IdentitySettings(identity_manager=IdentityManager(":memory:"),
                                                            working_directory=":memory:")))
        await self.introduce_nodes()

        b64_subject_key = (await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/my_peer0/public_key", match_info={"pseudonym_name": "my_peer0"})
        )))["public_key"]
        b64_authority_key = (await response_to_json(await self.rest_ep(1).get_pseudonym_public_key(
            MockRequest("identity/my_peer1/public_key", match_info={"pseudonym_name": "my_peer1"})
        )))["public_key"]
        b64_verifier_key = (await response_to_json(await self.rest_ep(2).get_pseudonym_public_key(
            MockRequest("identity/my_peer2/public_key", match_info={"pseudonym_name": "my_peer2"})
        )))["public_key"]

        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}
        attest = {"name": "My attribute", "value": base64.b64encode(b"Some value").decode()}

        await self.rest_ep(0).create_pseudonym_credential(
            MockRequest(f"identity/my_peer0/request/{urllib.parse.quote(b64_authority_key, safe='')}", "PUT", request,
                        {"pseudonym_name": "my_peer0", "authority_key": b64_authority_key})
        )
        await self.deliver_messages()
        await self.rest_ep(1).attest_pseudonym_credential(
            MockRequest(f"identity/my_peer1/attest/{urllib.parse.quote(b64_subject_key, safe='')}", "PUT", attest,
                        {"pseudonym_name": "my_peer1", "subject_key": b64_subject_key})
        )
        await self.deliver_messages()

        credentials = await response_to_json(await self.rest_ep(0).list_pseudonym_credentials(
            MockRequest("identity/my_peer0/credentials", match_info={"pseudonym_name": "my_peer0"})
        ))
        attribute_hash = credentials["names"][0]["hash"]

        result = await response_to_json(await self.rest_ep(2).verify_pseudonym_credential(
            MockRequest(f"identity/my_peer2/verify/{urllib.parse.quote(b64_subject_key, safe='')}", "PUT", {
                "hash": attribute_hash,
                "value": attest["value"],
                "schema": request["schema"]
            }, {"pseudonym_name": "my_peer2", "subject_key": b64_subject_key})
        ))
        self.assertTrue(result["success"])
        await self.deliver_messages()

        verification_requests = (await response_to_json(await self.rest_ep(0).list_pseudonym_outstanding_verifications(
            MockRequest("identity/my_peer0/outstanding/verifications", match_info={"pseudonym_name": "my_peer0"})
        )))["requests"]
        self.assertEqual(b64_verifier_key, verification_requests[0]["peer"])
        self.assertEqual("My attribute", verification_requests[0]["attribute_name"])

        result = await response_to_json(await self.rest_ep(0).allow_pseudonym_verification(
            MockRequest(f"identity/my_peer0/allow/{urllib.parse.quote(b64_verifier_key, safe='')}", "PUT",
                        {"name": "My attribute"}, {"pseudonym_name": "my_peer0", "verifier_key": b64_verifier_key})
        ))
        self.assertTrue(result["success"])
        await self.deliver_messages()

        output = await response_to_json(await self.rest_ep(2).list_pseudonym_verification_output(
            MockRequest("identity/my_peer2/verifications", match_info={"pseudonym_name": "my_peer2"})
        ))

        self.assertEqual(1, len(output["outputs"]))
        self.assertEqual(attribute_hash, output["outputs"][0]["hash"])
        self.assertEqual(base64.b64encode(b"Some value").decode(), output["outputs"][0]["reference"])
        self.assertGreaterEqual(output["outputs"][0]["match"], 0.98)

    async def test_disallow_verify(self) -> None:
        """
        Check that no verification is performed, if not allowed.
        """
        self.nodes.append(self.create_node(IdentitySettings(identity_manager=IdentityManager(":memory:"),
                                                            working_directory=":memory:")))
        await self.introduce_nodes()

        b64_subject_key = (await response_to_json(await self.rest_ep(0).get_pseudonym_public_key(
            MockRequest("identity/my_peer0/public_key", match_info={"pseudonym_name": "my_peer0"})
        )))["public_key"]
        b64_authority_key = (await response_to_json(await self.rest_ep(1).get_pseudonym_public_key(
            MockRequest("identity/my_peer1/public_key", match_info={"pseudonym_name": "my_peer1"})
        )))["public_key"]
        b64_verifier_key = (await response_to_json(await self.rest_ep(2).get_pseudonym_public_key(
            MockRequest("identity/my_peer2/public_key", match_info={"pseudonym_name": "my_peer2"})
        )))["public_key"]

        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}
        attest = {"name": "My attribute", "value": base64.b64encode(b'Some value').decode()}

        await self.rest_ep(0).create_pseudonym_credential(
            MockRequest(f"identity/my_peer0/request/{urllib.parse.quote(b64_authority_key, safe='')}", "PUT", request,
                        {"pseudonym_name": "my_peer0", "authority_key": b64_authority_key})
        )
        await self.deliver_messages()
        await self.rest_ep(1).attest_pseudonym_credential(
            MockRequest(f"identity/my_peer1/attest/{urllib.parse.quote(b64_subject_key, safe='')}", "PUT", attest,
                        {"pseudonym_name": "my_peer1", "subject_key": b64_subject_key})
        )
        await self.deliver_messages()

        credentials = await response_to_json(await self.rest_ep(0).list_pseudonym_credentials(
            MockRequest("identity/my_peer0/credentials", match_info={"pseudonym_name": "my_peer0"})
        ))
        attribute_hash = credentials["names"][0]["hash"]

        result = await response_to_json(await self.rest_ep(2).verify_pseudonym_credential(
            MockRequest(f"identity/my_peer2/verify/{urllib.parse.quote(b64_subject_key, safe='')}", "PUT", {
                "hash": attribute_hash,
                "value": attest["value"],
                "schema": request["schema"]
            }, {"pseudonym_name": "my_peer2", "subject_key": b64_subject_key})
        ))
        self.assertTrue(result["success"])
        await self.deliver_messages()

        verification_requests = (await response_to_json(await self.rest_ep(0).list_pseudonym_outstanding_verifications(
            MockRequest("identity/my_peer0/outstanding/verifications", match_info={"pseudonym_name": "my_peer0"})
        )))["requests"]
        self.assertEqual(b64_verifier_key, verification_requests[0]["peer"])
        self.assertEqual("My attribute", verification_requests[0]["attribute_name"])

        result = await response_to_json(await self.rest_ep(0).disallow_pseudonym_verification(
            MockRequest(f"identity/my_peer0/disallow/{urllib.parse.quote(b64_verifier_key, safe='')}", "PUT",
                        {"name": "My attribute"}, {"pseudonym_name": "my_peer0", "verifier_key": b64_verifier_key})
        ))
        self.assertTrue(result["success"])

        await self.deliver_messages()
        output = await response_to_json(await self.rest_ep(2).list_pseudonym_verification_output(
            MockRequest("identity/my_peer2/verifications", match_info={"pseudonym_name": "my_peer2"})
        ))

        self.assertEqual(0, len(output["outputs"]))
