from __future__ import absolute_import

from base64 import b64encode
from hashlib import sha1

from twisted.internet.defer import inlineCallbacks, returnValue

from .rest_peer_communication import HTTPGetRequesterAE, HTTPPostRequesterAE
from ...mocking.rest.base import RESTTestBase
from ...mocking.rest.comunities import TestAttestationCommunity, TestIdentityCommunity
from ...mocking.rest.peer_interactive_behavior import RequesterRestTestPeer
from ...mocking.rest.rest_api_peer import RestTestPeer
from ...mocking.rest.rest_peer_communication import string_to_url
from ....REST.base_endpoint import BaseEndpoint
from ....REST.json_util import dumps
from ....attestation.identity.community import IdentityCommunity


class TestAttestationEndpoint(RESTTestBase):
    """
    Class for testing the REST API of the IPv8 object
    """

    def setUp(self):
        super(TestAttestationEndpoint, self).setUp()
        self.initialize_configurations([(1, RestTestPeer)], HTTPGetRequesterAE(), HTTPPostRequesterAE())

    def create_new_peer(self, peer_cls, port, *args, **kwargs):
        self._create_new_peer_inner(peer_cls, port, [TestAttestationCommunity, TestIdentityCommunity], *args, **kwargs)

    def create_new_interactive_peer(self, peer_cls, port, *args, **kwargs):
        self._create_new_peer_inner(peer_cls, port, [TestAttestationCommunity, TestIdentityCommunity],
                                    HTTPGetRequesterAE(), HTTPPostRequesterAE(), *args, **kwargs)

    def get_latest_blocks(self, peer):
        """
        Gets the latest blocks (max 200) for a peer

        :param peer: the peer whose blocks are returned
        :return: the blocks for the peer (limit to 200 blocks)
        """
        trimmed = {}
        public_key = peer.get_named_key('my_peer').public_key.key_to_bin()

        blocks = peer.get_overlay_by_class(IdentityCommunity).persistence.get_latest_blocks(public_key, 200)

        for b in blocks:
            attester = b64encode(sha1(b.link_public_key).digest())
            previous = trimmed.get((attester, b.transaction[b"name"]), None)
            if not previous or previous.sequence_number < b.sequence_number:
                trimmed[(attester, b.transaction[b"name"])] = b

        return [(b.transaction[b"name"], b64encode(b.transaction[b"hash"]).decode('utf-8'), b.transaction[b"metadata"],
                 b64encode(sha1(b.link_public_key).digest()).decode('utf-8'))
                for b in trimmed.values()]

    @inlineCallbacks
    def wait_for_peers(self, dict_param, excluded_peer_mids=None):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :param excluded_peer_mids: A list of peer mids which should not be taken into consideration peers
        :return: a list of currently known peers in the network
        """
        assert isinstance(excluded_peer_mids, (list, set)) or not excluded_peer_mids, "excluded_peer_mids " \
                                                                                      "must be a list, set or None"

        # Make sure excluded_peer_mids is a set
        if not excluded_peer_mids:
            excluded_peer_mids = set()
        elif isinstance(excluded_peer_mids, list):
            excluded_peer_mids = set(excluded_peer_mids)

        peer_list = yield self._get_style_requests.make_peers(dict_param)
        peer_list = set(peer_list)

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            yield self.sleep()

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(peer_list)

        # Return the peer list, after they are encoded in utf-8 byte format
        returnValue([x.encode('utf-8') for x in list(peer_list - excluded_peer_mids)])

    @inlineCallbacks
    def wait_for_outstanding_requests(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while not outstanding_requests:
            yield self.sleep()

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue([(x[0].encode('utf-8'), x[1], x[2]) for x in outstanding_requests])

    @inlineCallbacks
    def attest_all_outstanding_requests(self, param_dict):
        """
        Forward an attestation for each of the outstanding attestation requests

        :param param_dict: the parameters required to contact a well-known peer for the POST and GET requests
        :return: a list of the outstanding requests and their (empty if successful) request responses
        """
        assert 'attribute_name' in param_dict, "No attribute name was specified"
        assert 'attribute_value' in param_dict, "No attribute value was specified"

        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

        # Collect the responses of the attestations; if functioning properly, this should be a list of empty strings
        responses = []

        for outstanding_request in outstanding_requests:
            # The attestation value is already computed, so don't bother recomputing it here
            param_dict['mid'] = string_to_url(outstanding_request[0])
            response = yield self._post_style_requests.make_attest(param_dict)
            responses.append(response)

        returnValue((outstanding_requests, responses))

    @inlineCallbacks
    def verify_all_attestations(self, peer_mids, param_dict):
        """
        Forward an attestation verification for a set of attestations

        :param peer_mids: the set of peer mids to which a verification request will be sent
        :param param_dict: the parameters required to contact a well-known peer for the POST: verify request
        :return: the verification responses, as returned by the well-known peer. Ideally these should be all empty
        """
        assert peer_mids, "Attestation list is empty"
        assert 'attribute_hash' in param_dict, "No attestation hash was specified"
        assert 'attribute_values' in param_dict, "No attestation values were specified"

        verification_responses = []

        for mid in peer_mids:
            param_dict['mid'] = string_to_url(mid)
            intermediary_response = yield self._post_style_requests.make_verify(param_dict)
            verification_responses.append(intermediary_response)

        returnValue(verification_responses)

    @inlineCallbacks
    def test_get_peers_request(self):
        """
        Test the (GET: peers request) type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation'
        }

        # Create a dummy peer which will be used towards peer discovery; there is no need to start() it
        self.create_new_peer(RestTestPeer, None, memory_dbs=True)
        other_peer_mids = [b64encode(x.mid) for x in self.nodes[1].get_keys().values()]

        # Add the peers
        self.nodes[0].add_and_verify_peers([self.nodes[1]])

        result = yield self.wait_for_peers(param_dict)

        self.assertTrue(any(x in other_peer_mids for x in result), "Could not find the second peer.")

    @inlineCallbacks
    def test_get_outstanding_requests(self):
        """
        Test the (GET: outstanding) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR'
        }

        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        result = yield self.wait_for_outstanding_requests(param_dict)

        self.assertTrue(any((x[0] == y and x[1] == param_dict['attribute_name'] for x in result)
                            for y in self.nodes[1].get_mids()),
                        "Could not find the outstanding request forwarded by the second peer")

    @inlineCallbacks
    def test_get_verification_output(self):
        """
        Test the (GET: verification output) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Forward the attestations to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.nodes[1].get_mids(), param_dict.copy())
        verification_responses = [BaseEndpoint.twisted_loads(response) for response in verification_responses]
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        # Unlock the verification
        param_dict['port'] = self.nodes[1].port

        outstanding_verifications = yield self._get_style_requests.make_outstanding_verify(param_dict)
        self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")

        param_dict['mid'] = string_to_url(outstanding_verifications[0][0])

        yield self._post_style_requests.make_allow_verify(param_dict)
        yield self.sleep()

        param_dict['port'] = self.nodes[0].port

        # Get the output
        verification_output = yield self._get_style_requests.make_verification_output(param_dict)

        self.assertTrue([["YXNk", 0.0], ["YXNkMg==", 0.0]] in verification_output.values(),
                        "Something went wrong with the verification. Unexpected output values.")

    @inlineCallbacks
    def test_get_outstanding_verify(self):
        """
        Test the (GET: outstanding verify) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Forward the attestations to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.nodes[1].get_mids(), param_dict.copy())
        verification_responses = [BaseEndpoint.twisted_loads(response) for response in verification_responses]
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        param_dict['port'] = self.nodes[1].port
        result = yield self._get_style_requests.make_outstanding_verify(param_dict)

        # Retrieve only the mids
        result = [x[0].encode('utf-8') for x in result]

        self.assertTrue(any(x in result for x in self.nodes[0].get_mids(False)), "Something went wrong. Could not "
                                                                                 "find a master peer mid in the "
                                                                                 "outstanding verification "
                                                                                 "requests.")

    @inlineCallbacks
    def test_get_attributes(self):
        """
        Test the (GET: attributes) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Forward the attestations to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        self.assertTrue(attributes[0][0] == param_dict['attribute_name'] and attributes[0][1] != "",
                        "The response was not as expected. This would suggest that something went wrong with "
                        "the attributes request.")

    @inlineCallbacks
    def test_get_drop_identity(self):
        """
        Test the (GET: drop identity) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Send a random attestation request to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)

        self.assertFalse(outstanding_requests == [], "The attestation requests were not received.")

        # Ensure that no block/attestation exists
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        self.assertEqual(attributes, [], "Something's wrong, there shouldn't be any blocks.")

        # Attest the outstanding request. This should mean that the attribute DB is non-empty in the well-known peer
        yield self.attest_all_outstanding_requests(param_dict)

        # Ensure that the attestation has been completed
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        self.assertNotEqual(attributes, [], "Something's wrong, the attribute list should be non-empty.")

        # Drop the identity
        result = yield self._get_style_requests.make_drop_identity(param_dict)
        json_response = BaseEndpoint.twisted_loads(result)
        self.assertIn("success", json_response, "The identity could not be dropped. Success parameter not in response.")
        self.assertTrue(json_response["success"], "The identity could not be dropped, not successful.")

        # Make sure the identity was successfully dropped
        result = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        self.assertEqual(result, [], 'The identity could not be dropped. Block DB still populated.')

        result = yield self._get_style_requests.make_outstanding(param_dict)
        self.assertEqual(result, [], 'The identity could not be dropped. Outstanding requests still remaining.')

    @inlineCallbacks
    def test_post_attestation_request(self):
        """
        Test the (POST: request) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # This should return an empty response
        outstanding_requests = yield self._get_style_requests.make_outstanding(param_dict)

        self.assertEqual(outstanding_requests, [], "Something went wrong, there should be no outstanding requests.")

        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        # This should return a non-empty response
        outstanding_requests = yield self.wait_for_outstanding_requests(param_dict)
        self.assertFalse(outstanding_requests == [], "Something went wrong, no request was received.")

    @inlineCallbacks
    def test_post_attest(self):
        """
        Test the (POST: attest) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        param_dict['port'] = self.nodes[1].port
        # attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        self.assertTrue(len(attributes) == 0, "There mustn't already be any attestations in the other peer.")

        param_dict['port'] = self.nodes[0].port
        responses = yield self.attest_all_outstanding_requests(param_dict.copy())
        request_responses = [BaseEndpoint.twisted_loads(response) for response in responses[1]]
        self.assertTrue(all("success" in x and x["success"] for x in request_responses),
                        "Something went wrong, not all responses were successful.")

        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)

        self.assertTrue(len(attributes) == 1, "There should only be one attestation in the DB.")
        self.assertTrue(attributes[0][0] == param_dict['attribute_name'], "Expected attestation for %s, got it for "
                                                                          "%s" % (param_dict['attribute_name'],
                                                                                  attributes[0][0]))

        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        self.assertTrue(len(attributes) == 0, "There should be no attribute in the DB of the attester.")

    @inlineCallbacks
    def test_post_verify(self):
        """
        Test the (POST: verify) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Forward the attestations to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the mids of the other peer
        other_peer_mids = [string_to_url(b64encode(x.mid)) for x in self.nodes[1].get_keys().values()]

        # Get the hash of the attestation to be validated (the one which was just attested)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(other_peer_mids, param_dict.copy())
        verification_responses = [BaseEndpoint.twisted_loads(response) for response in verification_responses]
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

    @inlineCallbacks
    def test_post_allow_verify(self):
        """
        Test the (POST: allow verify) request type
        """
        param_dict = {
            'port': self.nodes[0].port,
            'interface': self.nodes[0].interface,
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': string_to_url(b64encode(b'binarydata'), True),
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(dumps({'psn': '1234567890'}).encode('utf-8'))
        }

        # Forward the attestations to the well-known peer
        self.create_new_interactive_peer(RequesterRestTestPeer, None, param_dict.copy(), memory_dbs=True)
        self.introduce_nodes(IdentityCommunity)

        self.nodes[1].start()

        yield self.attest_all_outstanding_requests(param_dict.copy())

        # Get the hash of the attestation to be validated (the one which was just attested)
        param_dict.update({'port': self.nodes[1].port, 'interface': self.nodes[1].interface})
        attributes = yield self._get_style_requests.make_attributes(param_dict)
        param_dict.update({'port': self.nodes[0].port, 'interface': self.nodes[0].interface})

        param_dict['attribute_hash'] = string_to_url(attributes[0][1])

        # Forward the actual verification
        verification_responses = yield self.verify_all_attestations(self.nodes[1].get_mids(), param_dict.copy())
        verification_responses = [BaseEndpoint.twisted_loads(response) for response in verification_responses]
        self.assertTrue(all("success" in x and x["success"] for x in verification_responses),
                        "At least one of the verification responses was non-empty.")

        # Unlock the verification
        param_dict['port'] = self.nodes[1].port
        outstanding_verifications = yield self._get_style_requests.make_outstanding_verify(param_dict)
        self.assertIsNotNone(outstanding_verifications, "Could not retrieve any outstanding verifications")

        param_dict['mid'] = string_to_url(outstanding_verifications[0][0])

        response = yield self._post_style_requests.make_allow_verify(param_dict)
        json_response = BaseEndpoint.twisted_loads(response)

        self.assertIn("success", json_response, "The attestion could not be unlocked: success not in JSON response")
        self.assertTrue(json_response["success"], "The attestation could not be unlocked: not successful.")
