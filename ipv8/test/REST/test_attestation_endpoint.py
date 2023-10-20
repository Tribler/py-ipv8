from __future__ import annotations

from asyncio import sleep
from base64 import b64encode
from typing import Collection, Sequence

from ...attestation.identity.community import IdentityCommunity, IdentitySettings
from ...attestation.identity.manager import IdentityManager
from ...attestation.wallet.community import AttestationCommunity, AttestationSettings
from ..REST.rest_base import MockRestIPv8, RESTTestBase


class TestAttestationEndpoint(RESTTestBase):
    """
    Class for testing the REST API of the AttestationEndpoint.
    """

    async def setUp(self) -> None:
        """
        Create a new memory-based identity manager and set up the necessary communities.
        """
        super().setUp()
        identity_manager = IdentityManager(":memory:")
        await self.initialize([AttestationCommunity, IdentityCommunity], 2,
                              settings=[AttestationSettings(working_directory=':memory:'),
                                        IdentitySettings(identity_manager=identity_manager)])

    async def make_outstanding(self, node: MockRestIPv8) -> list[Sequence[str, str, str]]:
        """
        Forward a request for outstanding attestation requests.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'outstanding'})

    async def make_verification_output(self, node: MockRestIPv8) -> dict[str, list[Sequence[str, float]]]:
        """
        Forward a request for the verification outputs.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'verification_output'})

    async def make_peers(self, node: MockRestIPv8) -> list[str]:
        """
        Forward a request for the known peers in the network.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'peers'})

    async def make_attributes(self, node: MockRestIPv8) -> list[Sequence[str, str, dict[str, str | int], str]]:
        """
        Forward a request for the attributes of a peer.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'attributes'})

    async def wait_for_attributes(self, node: MockRestIPv8) -> list[Sequence[str, str, dict[str, str | int], str]]:
        """
        Forward a request for the attributes of a peer.
        """
        attributes = await self.make_request(node, 'attestation', 'get', {'type': 'attributes'})
        while not attributes:
            attributes = await self.make_request(node, 'attestation', 'get', {'type': 'attributes'})
            await self.deliver_messages()
        return attributes

    async def make_drop_identity(self, node: MockRestIPv8) -> dict[str, bool]:
        """
        Forward a request for dropping a peer's identity.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'drop_identity'})

    async def make_outstanding_verify(self, node: MockRestIPv8) -> list[Sequence[str, str]]:
        """
        Forward a request which requests information on the outstanding verify requests.
        """
        return await self.make_request(node, 'attestation', 'get', {'type': 'outstanding_verify'})

    async def make_attestation_request(self, node: MockRestIPv8, attribute_name: str, mid: str,
                                       metadata: dict | None = None) -> dict[str, bool]:
        """
        Forward a request for the attestation of an attribute.
        """
        # Add the type of the request (request), and the rest of the parameters
        request_parameters = {'type': 'request',
                              'id_format': 'id_metadata',
                              'attribute_name': attribute_name,
                              'mid': mid}
        if metadata:
            request_parameters['metadata'] = metadata
        return await self.make_request(node, 'attestation', 'post', request_parameters)

    async def make_attest(self, node: MockRestIPv8, attribute_name: str, attribute_value: list[str],
                          mid: str) -> dict[str, bool]:
        """
        Forward a request which attests an attestation request.
        """
        return await self.make_request(node, 'attestation', 'post', {'type': 'attest',
                                                                     'attribute_name': attribute_name,
                                                                     'attribute_value': attribute_value,
                                                                     'mid': mid})

    async def make_verify(self, node: MockRestIPv8, attribute_hash: str, attribute_values: str,
                          mid: str) -> dict[str, bool]:
        """
        Forward a request which demands the verification of an attestation.
        """
        return await self.make_request(node, 'attestation', 'post', {'type': 'verify',
                                                                     'attribute_hash': attribute_hash,
                                                                     'mid': mid,
                                                                     'attribute_values': attribute_values})

    async def make_allow_verify(self, node: MockRestIPv8, attribute_name: str, mid: str) -> dict[str, bool]:
        """
        Forward a request which requests that verifications be allowed for a particular peer for a particular attribute.
        """
        return await self.make_request(node, 'attestation', 'post', {'type': 'allow_verify',
                                                                     'attribute_name': attribute_name,
                                                                     'mid': mid})

    async def create_attestation_request(self, node: MockRestIPv8, attribute_name: str,
                                         metadata: dict | None = None) -> None:
        """
        Request all known peers to attest to the node's given attribute name.
        """
        peer_list = await self.wait_for_peers(node)
        for mid in peer_list:
            await self.make_attestation_request(node, attribute_name, mid, metadata=metadata)

    async def wait_for_peers(self, node: MockRestIPv8) -> list[str]:
        """
        Wait until this peer receives a non-empty list of fellow peers in the network.
        """
        peer_list = await self.make_peers(node)
        while not peer_list:
            await sleep(.1)
            peer_list = await self.make_peers(node)
        return peer_list

    async def wait_for_outstanding_requests(self, node: MockRestIPv8) -> list[tuple[bytes, str, str]]:
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests.
        """
        outstanding_requests = await self.make_outstanding(node)
        while not outstanding_requests:
            await sleep(.1)
            outstanding_requests = await self.make_outstanding(node)
        return [(x[0].encode('utf-8'), x[1], x[2]) for x in outstanding_requests]

    async def attest_all_outstanding_requests(self, node: MockRestIPv8, attribute_name: str,
                                              attribute_value: str) -> tuple[list[tuple[bytes, str, str]],
                                                                             list[dict[str, bool]]]:
        """
        Forward an attestation for each of the outstanding attestation requests.

        :return: a list of the outstanding requests and their (empty if successful) request responses
        """
        outstanding_requests = await self.wait_for_outstanding_requests(node)
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

        # Collect the responses of the attestations; if functioning properly, this should be a list of empty strings
        responses = []

        for outstanding_request in outstanding_requests:
            # The attestation value is already computed, so don't bother recomputing it here
            mid = outstanding_request[0].decode('utf-8')
            attribute_value = b64encode(attribute_value).decode('utf-8')\
                if isinstance(attribute_value, bytes) else attribute_value
            response = await self.make_attest(node, attribute_name, attribute_value, mid)
            responses.append(response)

        return outstanding_requests, responses

    async def verify_all_attestations(self, node: MockRestIPv8, peer_mids: Collection[bytes], attribute_hash: str,
                                      attribute_values: str) -> list[dict[str, bool]]:
        """
        Forward an attestation verification for a set of attestations.

        :param peer_mids: the set of peer mids to which a verification request will be sent
        :return: the verification responses, as returned by the well-known peer. Ideally these should be all empty
        """
        assert peer_mids, "Attestation list is empty"

        verification_responses = []

        for mid in peer_mids:
            decoded_mid = b64encode(mid).decode('utf-8') if isinstance(mid, bytes) else mid
            intermediary_response = await self.make_verify(node, attribute_hash, attribute_values, decoded_mid)
            verification_responses.append(intermediary_response)

        return verification_responses

    async def test_get_peers_request(self) -> None:
        """
        Test the (GET: peers request) type.
        """
        await self.introduce_nodes()
        other_peer_mids = [b64encode(self.mid(1)).decode('utf-8')]
        result = await self.wait_for_peers(self.node(0))
        self.assertTrue(any(x in other_peer_mids for x in result), "Could not find the second peer.")

    async def test_get_outstanding_requests(self) -> None:
        """
        Test the (GET: outstanding) request type.
        """
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')

        result = await self.wait_for_outstanding_requests(self.node(0))

        mid = b64encode(self.mid(1))
        self.assertTrue(any(x[0] == mid and x[1] == 'QR' for x in result),
                        "Could not find the outstanding request forwarded by the second peer")

    async def test_get_verification_output(self) -> None:
        """
        Test the (GET: verification output) request type.
        """
        # Forward the attestations to the well-known peer
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = await self.wait_for_attributes(self.node(1))
        attribute_hash = attributes[0][1]

        # Forward the actual verification
        verification_responses = await self.verify_all_attestations(self.node(0),
                                                                    [self.mid(1)],
                                                                    attribute_hash, 'YXNk,YXNkMg==')
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        # Unlock the verification
        outstanding_verifications = []
        while not outstanding_verifications:
            outstanding_verifications = await self.make_outstanding_verify(self.node(1))
            self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")
            await self.deliver_messages()

        mid = outstanding_verifications[0][0]
        await self.make_allow_verify(self.node(1), 'QR', mid)
        await sleep(.1)

        # Get the output
        verification_output = await self.make_verification_output(self.node(0))
        self.assertTrue([["YXNk", 0.0], ["YXNkMg==", 0.0]] in verification_output.values(),
                        "Something went wrong with the verification. Unexpected output values.")

    async def test_get_outstanding_verify(self) -> None:
        """
        Test the (GET: outstanding verify) request type.
        """
        # Forward the attestations to the well-known peer
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = await self.wait_for_attributes(self.node(1))
        attribute_hash = attributes[0][1]

        # Forward the actual verification
        verification_responses = await self.verify_all_attestations(self.node(0),
                                                                    [self.mid(1)],
                                                                    attribute_hash, 'YXNk,YXNkMg==')
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        # Unlock the verification
        outstanding_verifications = []
        while not outstanding_verifications:
            outstanding_verifications = await self.make_outstanding_verify(self.node(1))
            self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")
            await self.deliver_messages()

        # Retrieve only the mids
        result = [x[0] for x in outstanding_verifications]
        self.assertTrue(any(x in result for x in [b64encode(self.mid(0)).decode('utf-8')]),
                        "Something went wrong. Could not find a master peer mid in the "
                        "outstanding verification requests.")

    async def test_get_attributes(self) -> None:
        """
        Test the (GET: attributes) request type.
        """
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = await self.wait_for_attributes(self.node(1))
        self.assertTrue(attributes[0][0] == 'QR' and attributes[0][1] != "",
                        "The response was not as expected. This would suggest that something went wrong with "
                        "the attributes request.")

    async def test_get_drop_identity(self) -> None:
        """
        Test the (GET: drop identity) request type.
        """
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        outstanding_requests = await self.wait_for_outstanding_requests(self.node(0))
        self.assertFalse(outstanding_requests == [], "The attestation requests were not received.")

        # Ensure that no block/attestation exists
        attributes = await self.make_attributes(self.node(1))
        self.assertEqual(attributes, [], "Something's wrong, there shouldn't be any blocks.")

        # Attest the outstanding request. This should mean that the attribute DB is non-empty in the well-known peer
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Ensure that the attestation has been completed
        attributes = await self.wait_for_attributes(self.node(1))
        self.assertNotEqual(attributes, [], "Something's wrong, the attribute list should be non-empty.")

        # Drop the identity
        result = await self.make_drop_identity(self.node(0))
        self.assertIn("success", result, "The identity could not be dropped. Success parameter not in response.")
        self.assertTrue(result["success"], "The identity could not be dropped, not successful.")

        # Make sure the identity was successfully dropped
        result = await self.make_attributes(self.node(0))
        self.assertEqual(result, [], 'The identity could not be dropped. Block DB still populated.')

        result = await self.make_outstanding(self.node(0))
        self.assertEqual(result, [], 'The identity could not be dropped. Outstanding requests still remaining.')

    async def test_post_attestation_request(self) -> None:
        """
        Test the (POST: request) request type.
        """
        # This should return an empty response
        outstanding_requests = await self.make_outstanding(self.node(0))
        self.assertEqual(outstanding_requests, [], "Something went wrong, there should be no outstanding requests.")

        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')

        # This should return a non-empty response
        outstanding_requests = await self.wait_for_outstanding_requests(self.node(0))
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

    async def test_post_attest(self) -> None:
        """
        Test the (POST: attest) request type.
        """
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')

        attributes = await self.make_attributes(self.node(1))
        self.assertTrue(len(attributes) == 0, "There mustn't already be any attestations in the other peer.")

        responses = await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')
        request_responses = list(responses[1])
        self.assertTrue(all("success" in x and x["success"] for x in request_responses),
                        "Something went wrong, not all responses were successful.")

        attributes = await self.wait_for_attributes(self.node(1))
        self.assertTrue(len(attributes) == 1, "There should only be one attestation in the DB.")
        self.assertTrue(attributes[0][0] == 'QR', f"Expected attestation for QR, got it for {attributes[0][0]}")

        attributes = await self.make_attributes(self.node(0))
        self.assertTrue(len(attributes) == 0, "There should be no attribute in the DB of the attester.")

    async def test_post_verify(self) -> None:
        """
        Test the (POST: verify) request type.
        """
        # Forward the attestations to the well-known peer
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = await self.wait_for_attributes(self.node(1))
        attribute_hash = attributes[0][1]

        # Forward the actual verification
        verification_responses = await self.verify_all_attestations(self.node(0),
                                                                    [self.mid(1)],
                                                                    attribute_hash, 'YXNk,YXNkMg==')
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

    async def test_post_allow_verify(self) -> None:
        """
        Test the (POST: allow verify) request type.
        """
        # Forward the attestations to the well-known peer
        await self.introduce_nodes()
        await self.create_attestation_request(self.node(1), 'QR')
        await self.attest_all_outstanding_requests(self.node(0), 'QR', 'data')

        # Get the hash of the attestation to be validated (the one which was just attested)
        attributes = await self.wait_for_attributes(self.node(1))
        attribute_hash = attributes[0][1]

        # Forward the actual verification
        verification_responses = await self.verify_all_attestations(self.node(0),
                                                                    [self.mid(1)],
                                                                    attribute_hash, 'YXNk,YXNkMg==')
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        # Unlock the verification
        outstanding_verifications = []
        while not outstanding_verifications:
            outstanding_verifications = await self.make_outstanding_verify(self.node(1))
            self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")
            await self.deliver_messages()

        mid = outstanding_verifications[0][0]
        response = await self.make_allow_verify(self.node(1), 'QR', mid)
        self.assertIn("success", response, "The attestion could not be unlocked: success not in JSON response")
        self.assertTrue(response["success"], "The attestation could not be unlocked: not successful.")
