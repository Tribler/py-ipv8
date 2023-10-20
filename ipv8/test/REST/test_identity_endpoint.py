from __future__ import annotations

import base64
import json
import urllib.parse
from typing import TYPE_CHECKING, Any, cast

from ...attestation.communication_manager import CommunicationChannel, CommunicationManager, PseudonymFolderManager
from ...attestation.default_identity_formats import FORMATS
from ...attestation.identity.community import IdentityCommunity, IdentitySettings
from ...attestation.identity.manager import IdentityManager
from ...attestation.wallet.community import AttestationCommunity, AttestationSettings
from ..mocking.endpoint import AutoMockEndpoint
from ..REST.rest_base import MockRestIPv8, RESTTestBase

if TYPE_CHECKING:
    from ...community import CommunitySettings
    from ...types import PrivateKey


class MockPseudonymFolderManager(PseudonymFolderManager):
    """
    Mock the OS file system using a dictionary as to mock files in a folder.
    """

    def __init__(self) -> None:
        """
        Create a new mocked pseudonym folder manager.
        """
        super().__init__(".")
        self.folder_contents: dict[str, bytes] = {}

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


class TestIdentityEndpoint(RESTTestBase):
    """
    Class for testing the REST API of the IdentityEndpoint.
    """

    async def setUp(self) -> None:
        """
        Set up an identity community, memory identity manager and memory pseudonym folder manager.
        """
        super().setUp()

        self.pseudonym_directories: dict[str, bytes] = {}  # Pseudonym to key-bytes mapping


        await self.initialize([IdentityCommunity], 2, self.create_settings())

    def create_settings(self) -> list[IdentitySettings]:
        """
        Create settings for any node.
        """
        return [IdentitySettings(identity_manager=IdentityManager(":memory:"), working_directory=':memory:')]

    async def create_node(self, settings: list[CommunitySettings]) -> MockRestIPv8:
        """
        We load each node i with a pseudonym `my_peer{i}`, which is the default IPv8 `my_peer` key.
        """
        ipv8 = await super().create_node(settings)
        key_file_name = 'my_peer' + str(len(self.pseudonym_directories))
        communication_manager = ipv8.rest_manager.root_endpoint.endpoints['/identity'].communication_manager
        communication_manager.working_directory = ':memory:'
        communication_manager.pseudonym_folder_manager = MockPseudonymFolderManager()
        communication_manager.pseudonym_folder_manager.get_or_create_private_key(key_file_name)

        identity_overlay = cast(IdentityCommunity, ipv8.get_overlay(IdentityCommunity))
        attestation_overlay = AttestationCommunity(AttestationSettings(my_peer=identity_overlay.my_peer,
                                                                       endpoint=identity_overlay.endpoint,
                                                                       network=identity_overlay.network,
                                                                       working_directory=':memory:'))
        channel = CommunicationChannel(attestation_overlay, identity_overlay)

        communication_manager.channels[ipv8.my_peer.public_key.key_to_bin()] = channel
        communication_manager.name_to_channel[key_file_name] = channel
        self.pseudonym_directories[key_file_name] = ipv8.my_peer.key.key_to_bin()
        return ipv8

    def communication_manager(self, i: int) -> CommunicationManager:
        """
        Shortcut to the communication manager of node i.
        """
        return self.node(i).rest_manager.root_endpoint.endpoints['/identity'].communication_manager

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

    async def wait_for(self, *args: Any, **kwargs) -> Any:  # noqa: ANN401
        """
        Fire a make request and keep repeating this request until a non-empty response is returned.
        """
        output = []
        while not output:
            output = await self.make_request(*args)
            await self.deliver_messages()
        return output

    async def wait_for_requests(self, *args: Any, **kwargs) -> Any:  # noqa: ANN401
        """
        Fire a make request and keep repeating this request until a response with the key "requests" is returned.
        """
        requests = []
        while not requests:
            output = await self.wait_for(*args)
            if 'requests' in output:
                requests = output['requests']
            else:
                await self.deliver_messages()
        return requests

    async def test_list_pseudonyms_empty(self) -> None:
        """
        Check that we do not start with any pseudonyms.
        """
        await self.make_request(self.node(0), 'identity/my_peer0/remove', 'get')
        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertDictEqual({'names': []}, result)

    async def test_list_schemas(self) -> None:
        """
        Check that the endpoint reports the available schemas correctly.
        """
        schemas = await self.make_request(self.node(0), 'identity/test_pseudonym/schemas', 'get')

        self.assertSetEqual(set(FORMATS.keys()), set(schemas['schemas']))

    async def test_list_pseudonyms_one(self) -> None:
        """
        Check that a loaded pseudonym is reported as such.
        """
        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertDictEqual({'names': ['my_peer0']}, result)

    async def test_list_pseudonyms_many(self) -> None:
        """
        Check that all loaded pseudonyms are reported as such.
        """
        pseudonyms = ['test_pseudonym1', 'test_pseudonym2', 'test_pseudonym3', 'test_pseudonym4']
        for pseudonym in pseudonyms:
            await self.make_request(self.node(0), f'identity/{pseudonym}/schemas', 'get')

        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertSetEqual(set(pseudonyms) | {'my_peer0'}, set(result['names']))

    async def test_list_public_key_one(self) -> None:
        """
        Check that we retrieve the pseudonym public key correctly.
        """
        result = await self.make_request(self.node(0), 'identity/test_pseudonym/public_key', 'get')
        decoded_public_key = base64.b64decode(result['public_key'])

        # This should have made the `test_pseudonym` private key file (corresponding to the reported public key).
        private_key = self.communication_manager(0).pseudonym_folder_manager.folder_contents['test_pseudonym']

        self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_public_key_many(self) -> None:
        """
        Check that we retrieve the pseudonym public key correctly.
        """
        pseudonyms = ['test_pseudonym1', 'test_pseudonym2', 'test_pseudonym3', 'test_pseudonym4']
        # Make sure all pseudonyms exist before querying their keys.
        # This is not necessary, but has the highest chance of exposing failures.
        for pseudonym in pseudonyms:
            await self.make_request(self.node(0), f'identity/{pseudonym}/schemas', 'get')
        for pseudonym in pseudonyms:
            result = await self.make_request(self.node(0), f'identity/{pseudonym}/public_key', 'get')
            decoded_public_key = base64.b64decode(result['public_key'])

            private_key = self.communication_manager(0).pseudonym_folder_manager.folder_contents[pseudonym]

            self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_peers(self) -> None:
        """
        Check if peers are correctly listed.
        """
        result1 = await self.make_request(self.node(0), 'identity/my_peer0/peers', 'get')
        result2 = await self.make_request(self.node(1), 'identity/my_peer1/peers', 'get')

        self.assertListEqual([], result1['peers'])
        self.assertListEqual([], result2['peers'])

        await self.introduce_pseudonyms()

        result1 = await self.make_request(self.node(0), 'identity/my_peer0/peers', 'get')
        result2 = await self.make_request(self.node(1), 'identity/my_peer1/peers', 'get')

        self.assertEqual(1, len(result1['peers']))
        self.assertEqual(1, len(result2['peers']))

    async def test_list_unload(self) -> None:
        """
        Check if a pseudonym stops communicating on unload.
        """
        await self.make_request(self.node(0), 'identity/my_peer0/unload', 'get')
        await self.make_request(self.node(1), 'identity/my_peer1/unload', 'get')

        self.assertListEqual([], self.node(0).overlays)
        self.assertListEqual([], self.node(1).overlays)

    async def test_list_credentials_empty(self) -> None:
        """
        Check that we retrieve credentials correctly, if none exist.
        """
        result = await self.make_request(self.node(0), 'identity/my_peer0/credentials', 'get')

        self.assertListEqual([], result['names'])

    async def test_request_attestation(self) -> None:
        """
        Check that requesting an attestation works.
        """
        b64_subject_key = (await self.make_request(self.node(0), 'identity/my_peer0/public_key', 'get'))['public_key']
        result = await self.make_request(self.node(1), 'identity/my_peer1/public_key', 'get')
        qb64_authority_key = urllib.parse.quote(result['public_key'], safe='')

        await self.introduce_pseudonyms()

        request = await self.make_request(self.node(0), f'identity/my_peer0/request/{qb64_authority_key}', 'put',
                                          json={
                                              "name": "My attribute",
                                              "schema": "id_metadata",
                                              "metadata": {}})
        self.assertTrue(request['success'])

        outstanding = await self.wait_for(self.node(1), 'identity/my_peer1/outstanding/attestations', 'get')

        self.assertEqual(1, len(outstanding['requests']))
        self.assertEqual(b64_subject_key, outstanding['requests'][0]['peer'])
        self.assertEqual("My attribute", outstanding['requests'][0]['attribute_name'])
        self.assertDictEqual({}, json.loads(outstanding['requests'][0]['metadata']))

    async def test_request_attestation_metadata(self) -> None:
        """
        Check that requesting an attestation with metadata works.
        """
        b64_subject_key = (await self.make_request(self.node(0), 'identity/my_peer0/public_key', 'get'))['public_key']
        result = await self.make_request(self.node(1), 'identity/my_peer1/public_key', 'get')
        qb64_authority_key = urllib.parse.quote(result['public_key'], safe='')

        await self.introduce_pseudonyms()

        request = await self.make_request(self.node(0), f'identity/my_peer0/request/{qb64_authority_key}', 'put',
                                          json={
                                              "name": "My attribute",
                                              "schema": "id_metadata",
                                              "metadata": {"Some key": "Some value"}})
        self.assertTrue(request['success'])

        outstanding = await self.wait_for(self.node(1), 'identity/my_peer1/outstanding/attestations', 'get')

        self.assertEqual(1, len(outstanding['requests']))
        self.assertEqual(b64_subject_key, outstanding['requests'][0]['peer'])
        self.assertEqual("My attribute", outstanding['requests'][0]['attribute_name'])
        self.assertDictEqual({"Some key": "Some value"}, json.loads(outstanding['requests'][0]['metadata']))

    async def test_attest(self) -> None:
        """
        Check that attesting to an attestation request with metadata works.
        """
        b64_subject_key = (await self.make_request(self.node(0), 'identity/my_peer0/public_key', 'get'))['public_key']
        qb64_subject_key = urllib.parse.quote(b64_subject_key, safe='')
        b64_authority_key = (await self.make_request(self.node(1), 'identity/my_peer1/public_key', 'get'))['public_key']
        qb64_authority_key = urllib.parse.quote(b64_authority_key, safe='')
        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}

        await self.introduce_pseudonyms()
        await self.make_request(self.node(0), f'identity/my_peer0/request/{qb64_authority_key}', 'put', json=request)
        await self.wait_for(self.node(1), 'identity/my_peer1/outstanding/attestations', 'get')

        result = await self.make_request(self.node(1), f'identity/my_peer1/attest/{qb64_subject_key}', 'put',
                                         json={
                                             "name": "My attribute",
                                             "value": base64.b64encode(b'Some value').decode()})
        self.assertTrue(result['success'])

        # How node 0 sees itself after receiving the attestation
        result = await self.wait_for(self.node(0), 'identity/my_peer0/credentials', 'get')
        self.assertEqual(1, len(result['names']))
        self.assertEqual("My attribute", result['names'][0]['name'])
        self.assertListEqual([b64_authority_key], result['names'][0]['attesters'])
        for k, v in metadata.items():
            self.assertIn(k, result['names'][0]['metadata'])
            self.assertEqual(v, result['names'][0]['metadata'][k])

        # How node 1 sees node 0 after making the attestation
        result = await self.wait_for(self.node(1), f'identity/my_peer1/credentials/{qb64_subject_key}', 'get')
        self.assertEqual(1, len(result['names']))
        self.assertEqual("My attribute", result['names'][0]['name'])
        self.assertListEqual([b64_authority_key], result['names'][0]['attesters'])
        for k, v in metadata.items():
            self.assertIn(k, result['names'][0]['metadata'])
            self.assertEqual(v, result['names'][0]['metadata'][k])

    async def test_verify(self) -> None:
        """
        Check that verifying a credential works.
        """
        self.nodes.append(await self.create_node(self.create_settings()))  # We need a third node for this one

        b64_subject_key = (await self.make_request(self.node(0), 'identity/my_peer0/public_key', 'get'))['public_key']
        qb64_subject_key = urllib.parse.quote(b64_subject_key, safe='')
        b64_authority_key = (await self.make_request(self.node(1), 'identity/my_peer1/public_key', 'get'))['public_key']
        qb64_authority_key = urllib.parse.quote(b64_authority_key, safe='')
        b64_verifier_key = (await self.make_request(self.node(2), 'identity/my_peer2/public_key', 'get'))['public_key']
        qb64_verifier_key = urllib.parse.quote(b64_verifier_key, safe='')

        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}
        attest = {"name": "My attribute", "value": base64.b64encode(b'Some value').decode()}

        await self.introduce_pseudonyms()
        await self.make_request(self.node(0), f'identity/my_peer0/request/{qb64_authority_key}', 'put', json=request)
        await self.wait_for(self.node(1), 'identity/my_peer1/outstanding/attestations', 'get')
        await self.make_request(self.node(1), f'identity/my_peer1/attest/{qb64_subject_key}', 'put', json=attest)

        credentials = await self.wait_for(self.node(0), 'identity/my_peer0/credentials', 'get')
        attribute_hash = credentials["names"][0]["hash"]

        result = await self.make_request(self.node(2), f'identity/my_peer2/verify/{qb64_subject_key}', 'put',
                                         json={
                                             "hash": attribute_hash,
                                             "value": attest["value"],
                                             "schema": request["schema"]})
        self.assertTrue(result['success'])

        verification_requests = await self.wait_for_requests(self.node(0),
                                                             'identity/my_peer0/outstanding/verifications',
                                                             'get')
        self.assertEqual(b64_verifier_key, verification_requests[0]['peer'])
        self.assertEqual("My attribute", verification_requests[0]['attribute_name'])

        result = await self.make_request(self.node(0), f'identity/my_peer0/allow/{qb64_verifier_key}', 'put',
                                         json={"name": "My attribute"})
        self.assertTrue(result['success'])

        await self.deliver_messages()
        output = await self.make_request(self.node(2), 'identity/my_peer2/verifications', 'get')

        self.assertEqual(1, len(output['outputs']))
        self.assertEqual(attribute_hash, output['outputs'][0]['hash'])
        self.assertEqual(base64.b64encode(b'Some value').decode(), output['outputs'][0]['reference'])
        self.assertGreaterEqual(output['outputs'][0]['match'], 0.98)

    async def test_disallow_verify(self) -> None:
        """
        Check that no verification is performed, if not allowed.
        """
        self.nodes.append(await self.create_node(self.create_settings()))  # We need a third node for this one

        b64_subject_key = (await self.make_request(self.node(0), 'identity/my_peer0/public_key', 'get'))['public_key']
        qb64_subject_key = urllib.parse.quote(b64_subject_key, safe='')
        b64_authority_key = (await self.make_request(self.node(1), 'identity/my_peer1/public_key', 'get'))['public_key']
        qb64_authority_key = urllib.parse.quote(b64_authority_key, safe='')
        b64_verifier_key = (await self.make_request(self.node(2), 'identity/my_peer2/public_key', 'get'))['public_key']
        qb64_verifier_key = urllib.parse.quote(b64_verifier_key, safe='')

        metadata = {"Some key": "Some value"}
        request = {"name": "My attribute", "schema": "id_metadata", "metadata": metadata}
        attest = {"name": "My attribute", "value": base64.b64encode(b'Some value').decode()}

        await self.introduce_pseudonyms()
        await self.make_request(self.node(0), f'identity/my_peer0/request/{qb64_authority_key}', 'put', json=request)
        await self.wait_for(self.node(1), 'identity/my_peer1/outstanding/attestations', 'get')
        await self.make_request(self.node(1), f'identity/my_peer1/attest/{qb64_subject_key}', 'put', json=attest)

        credentials = await self.wait_for(self.node(0), 'identity/my_peer0/credentials', 'get')
        attribute_hash = credentials["names"][0]["hash"]

        result = await self.make_request(self.node(2), f'identity/my_peer2/verify/{qb64_subject_key}', 'put',
                                         json={
                                             "hash": attribute_hash,
                                             "value": attest["value"],
                                             "schema": request["schema"]})
        self.assertTrue(result['success'])

        verification_requests = await self.wait_for_requests(self.node(0),
                                                             'identity/my_peer0/outstanding/verifications',
                                                             'get')
        self.assertEqual(b64_verifier_key, verification_requests[0]['peer'])
        self.assertEqual("My attribute", verification_requests[0]['attribute_name'])

        result = await self.make_request(self.node(0), f'identity/my_peer0/disallow/{qb64_verifier_key}', 'put',
                                         json={"name": "My attribute"})
        self.assertTrue(result['success'])

        await self.deliver_messages()
        output = await self.make_request(self.node(2), 'identity/my_peer2/verifications', 'get')

        self.assertEqual(0, len(output['outputs']))
