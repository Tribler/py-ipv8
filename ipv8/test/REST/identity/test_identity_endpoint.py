import base64
import json
import os
import urllib.parse

from ...REST.rest_base import RESTTestBase, partial_cls
from ....attestation.communication_manager import CommunicationChannel
from ....attestation.default_identity_formats import FORMATS
from ....attestation.identity.community import IdentityCommunity
from ....attestation.identity.manager import IdentityManager
from ....attestation.wallet.community import AttestationCommunity
from ....community import _DEFAULT_ADDRESSES
from ....keyvault.crypto import ECCrypto


class TestIdentityEndpoint(RESTTestBase):
    """
    Class for testing the REST API of the IdentityEndpoint
    """

    async def setUp(self):
        super(TestIdentityEndpoint, self).setUp()

        while _DEFAULT_ADDRESSES:
            _DEFAULT_ADDRESSES.pop()

        self.pseudonym_directories = []
        identity_manager = IdentityManager(u":memory:")

        await self.initialize([partial_cls(IdentityCommunity, identity_manager=identity_manager,
                                           working_directory=':memory:')], 2)

    async def create_node(self, *args, **kwargs):
        """
        We load each node i with a pseudonym `my_peer{i}`, which is the default IPv8 `my_peer` key.
        """
        ipv8 = await super(TestIdentityEndpoint, self).create_node(*args, **kwargs)
        temp_dir = self.temporary_directory()
        key_file_name = 'my_peer' + str(len(self.pseudonym_directories))
        with open(os.path.join(temp_dir, key_file_name), 'wb') as f:
            f.write(ipv8.my_peer.key.key_to_bin())
        communication_manager = ipv8.rest_manager.root_endpoint.endpoints['/identity'].communication_manager
        communication_manager.working_directory = ':memory:'
        communication_manager.pseudonym_folder = temp_dir

        identity_overlay = ipv8.get_overlay(IdentityCommunity)
        attestation_overlay = AttestationCommunity(identity_overlay.my_peer, identity_overlay.endpoint,
                                                   identity_overlay.network, working_directory=':memory:')
        channel = CommunicationChannel(attestation_overlay, identity_overlay)

        communication_manager.channels[ipv8.my_peer.public_key.key_to_bin()] = channel
        communication_manager.name_to_channel[key_file_name] = channel
        self.pseudonym_directories.append(temp_dir)
        return ipv8

    async def introduce_pseudonyms(self):
        all_interfaces = []
        for node in self.nodes:
            all_interfaces.append([overlay.endpoint.wan_address for overlay in node.overlays
                                   if isinstance(overlay, IdentityCommunity)])
        for i in range(len(self.nodes)):
            other_addresses = list(range(len(self.nodes)))
            other_addresses.remove(i)
            for j in other_addresses:
                for overlay in self.nodes[i].overlays:
                    if isinstance(overlay, IdentityCommunity):
                        for address in all_interfaces[j]:
                            overlay.walk_to(address)
            await self.deliver_messages()

    def node(self, i):
        return self.nodes[i]

    async def wait_for(self, *args, **kwargs):
        output = []
        while not output:
            output = await self.make_request(*args)
            await self.deliver_messages()
        return output

    async def wait_for_requests(self, *args, **kwargs):
        requests = []
        while not requests:
            output = await self.wait_for(*args)
            if 'requests' in output:
                requests = output['requests']
            else:
                await self.deliver_messages()
        return requests

    async def test_list_pseudonyms_empty(self):
        """
        Check that we do not start with any pseudonyms.
        """
        await self.make_request(self.node(0), 'identity/my_peer0/remove', 'get')
        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertDictEqual({'names': []}, result)

    async def test_list_schemas(self):
        """
        Check that the endpoint reports the available schemas correctly.
        """
        schemas = await self.make_request(self.node(0), 'identity/test_pseudonym/schemas', 'get')

        self.assertSetEqual(set(FORMATS.keys()), set(schemas['schemas']))

    async def test_list_pseudonyms_one(self):
        """
        Check that a loaded pseudonym is reported as such.
        """
        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertDictEqual({'names': ['my_peer0']}, result)

    async def test_list_pseudonyms_many(self):
        """
        Check that all loaded pseudonyms are reported as such.
        """
        pseudonyms = ['test_pseudonym1', 'test_pseudonym2', 'test_pseudonym3', 'test_pseudonym4']
        for pseudonym in pseudonyms:
            await self.make_request(self.node(0), f'identity/{pseudonym}/schemas', 'get')

        result = await self.make_request(self.node(0), 'identity', 'get')

        self.assertSetEqual(set(pseudonyms) | {'my_peer0'}, set(result['names']))

    async def test_list_public_key_one(self):
        """
        Check that we retrieve the pseudonym public key correctly.
        """
        result = await self.make_request(self.node(0), 'identity/test_pseudonym/public_key', 'get')
        decoded_public_key = base64.b64decode(result['public_key'])

        # This should have made the `test_pseudonym` private key file (corresponding to the reported public key).
        key_file = os.path.join(self.pseudonym_directories[0], 'test_pseudonym')
        with open(key_file, 'rb') as key_file_handle:
            private_key = ECCrypto().key_from_private_bin(key_file_handle.read())

        self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_public_key_many(self):
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

            key_file = os.path.join(self.pseudonym_directories[0], pseudonym)
            with open(key_file, 'rb') as key_file_handle:
                private_key = ECCrypto().key_from_private_bin(key_file_handle.read())

            self.assertEqual(private_key.pub().key_to_bin(), decoded_public_key)

    async def test_list_peers(self):
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

    async def test_list_unload(self):
        """
        Check if a pseudonym stops communicating on unload.
        """
        await self.make_request(self.node(0), 'identity/my_peer0/unload', 'get')
        await self.make_request(self.node(1), 'identity/my_peer1/unload', 'get')

        self.assertListEqual([], self.node(0).overlays)
        self.assertListEqual([], self.node(1).overlays)

    async def test_list_credentials_empty(self):
        """
        Check that we retrieve credentials correctly, if none exist.
        """
        result = await self.make_request(self.node(0), 'identity/my_peer0/credentials', 'get')

        self.assertListEqual([], result['names'])

    async def test_request_attestation(self):
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

    async def test_request_attestation_metadata(self):
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

    async def test_attest(self):
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

    async def test_verify(self):
        """
        Check that verifying a credential works.
        """
        self.nodes.append(await self.create_node())  # We need a third node for this one

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
                                                             f'identity/my_peer0/outstanding/verifications',
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

    async def test_disallow_verify(self):
        """
        Check that no verification is performed, if not allowed.
        """
        self.nodes.append(await self.create_node())  # We need a third node for this one

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
                                                             f'identity/my_peer0/outstanding/verifications',
                                                             'get')
        self.assertEqual(b64_verifier_key, verification_requests[0]['peer'])
        self.assertEqual("My attribute", verification_requests[0]['attribute_name'])

        result = await self.make_request(self.node(0), f'identity/my_peer0/disallow/{qb64_verifier_key}', 'put',
                                         json={"name": "My attribute"})
        self.assertTrue(result['success'])

        await self.deliver_messages()
        output = await self.make_request(self.node(2), 'identity/my_peer2/verifications', 'get')

        self.assertEqual(0, len(output['outputs']))
