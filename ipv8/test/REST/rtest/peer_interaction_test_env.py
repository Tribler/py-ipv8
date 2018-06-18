import ast
import json
import time
import unittest
from urllib import quote
from base64 import b64encode
from twisted.internet.defer import returnValue, inlineCallbacks

from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8.test.REST.rtest.test_rest_api_peer import TestPeer
from ipv8.test.util import twisted_wrapper


class SingleServerSetup(unittest.TestCase):
    """AndroidTestPeer
    Test class which defines an environment with one well-known peer. This should be extended by other subclasses,
    which implement specific test cases.
    """

    def __init__(self, *args, **kwargs):
        super(SingleServerSetup, self).__init__(*args, **kwargs)

        # Call the method which sets up the environment
        self.initialize()

    def initialize(self, **kwargs):
        """
        An initializer method for the Single Server test environment

        :param kwargs: a dictionary containing additional configuration parameters:
        {
            'port': the master peer's port. Defaults to 8086
            '8086': the master peer's path to the working directory. Defaults to 'test_env'
            'interface': IP or alias of the peer. Defaults to '127.0.0.1'
            'configuration': IPv8 configuration object. Defaults to None
            'get_style_requests': GET style request generator. Defaults to None
            'post_style_requests': POST style request generator. Defaults to None
        }
        """

        port = kwargs.get('port', 8086)
        path = kwargs.get('path', 'test_env')
        interface = kwargs.get('interface', '127.0.0.1')
        configuration = kwargs.get('configuration', None)
        get_style_requests = kwargs.get('get_style_requests', None)
        post_style_requests = kwargs.get('post_style_requests', None)

        # Create a so called master (well-known) peer, which should be the peer to which the requests are directed
        self._master_peer = TestPeer(path, port, interface, configuration)

        # Check to see if the user has provided request generators
        if get_style_requests:
            assert isinstance(get_style_requests, GetStyleRequests), "The get_style_requests parameter must be a " \
                                                                     "subclass of GetStyleRequests"
            self._get_style_requests = get_style_requests
        else:
            # If no get style request provided, default to the HTTP implementation
            self._get_style_requests = HTTPGetRequester()

        if post_style_requests:
            assert isinstance(post_style_requests, PostStyleRequests), "The post_style_requests parameter must be a " \
                                                                       "subclass of PostStyleRequests"
            self._post_style_requests = post_style_requests
        else:
            # If no post style request provided, default to the HTTP implementation
            self._post_style_requests = HTTPPostRequester()

    def setUp(self):
        # Call super method
        pass

    def tearDown(self):
        # Call super method
        super(SingleServerSetup, self).tearDown()

        # Stop the master peer
        self._master_peer.stop()


class RequestTest(SingleServerSetup):

    @inlineCallbacks
    def wait_for_peers(self, dict_param):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :return: a list of currently known peers in the network
        """

        peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Keep iterating until peer_list is non-empty
        while peer_list == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Return the peer list
        returnValue(peer_list)

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests == "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue(outstanding_requests)

    @inlineCallbacks
    def send_attestation_requests_to_all(self, param_dict):
        """
        Request an attestation from each of the known peers in the system

        :param param_dict: the parameters required to contact a peer for the GET: peers request
        :return: a list of the peers and their (empty if successful) request responses
        """
        assert 'attribute_name' in param_dict, "No attribute name was specified"

        known_peers = yield self.wait_for_peers(param_dict)

        known_peers = ast.literal_eval(known_peers)

        responses = []

        for peer in known_peers:
            param_dict['mid'] = peer.replace('+', '%2B')
            intermediate_response = yield self._post_style_requests.make_attestation_request(param_dict)
            responses.append(intermediate_response)

        returnValue((known_peers, responses))

    @inlineCallbacks
    def attest_all_outstanding_requests(self, param_dict):
        """
        Forward an attestation for each of the outstanding attestation requests

        :param param_dict: the parameters required to contact a well-known peer for the POST and GET requests
        :return: a list of the outstanding requests and their (empty if successful) request responses
        """
        assert 'attribute_name' in param_dict, "No attribute name was specified"
        assert 'attribute_value' in param_dict, "No attribute value was specified"

        outstanding_requests = yield self.wait_for_attestation_request(param_dict)
        outstanding_requests = ast.literal_eval(outstanding_requests)
        response_list = []

        for request in outstanding_requests:
            param_dict['mid'] = str(request[0]).replace("+", "%2B")
            param_dict['attribute_name'] = str(request[1])
            response = yield self._post_style_requests.make_attest(param_dict)
            response_list.append(response)

        returnValue((outstanding_requests, response_list))

    @inlineCallbacks
    def verify_all_attestations(self, attestations, param_dict):
        """
        Forward an attestation verification for a set of attestations

        :param attestations: the set of attestations which will be verified
        :param param_dict: the parameters required to contact a well-known peer for the POST: verify request
        :return: the verification responses, as returned by the well-known peer. Ideally these should be all empty
        """
        assert attestations, "Attestation list is empty"
        assert 'attribute_hash' in param_dict, "No attestation hash was specified"
        assert 'attribute_values' in param_dict, "No attestation values were specified"

        verification_responses = []

        for attestation in attestations:
            param_dict['mid'] = attestation[0].replace("+", "%2B")
            intermediary_response = yield self._post_style_requests.make_verify(param_dict)
            verification_responses.append(intermediary_response)

        returnValue(verification_responses)

    @twisted_wrapper
    def test_get_peers_request(self):
        """
        Test the GET: peers request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        # Create a dummy peer which will be used towards peer discovery; there is no need to start() it
        TestPeer('android_peer', 9876)

        # result = yield self._get_style_requests.make_peers(param_dict)
        result = yield self.wait_for_peers(param_dict)

        self.assertNotEqual(result, "[]", "The request received an empty peer list, instead of a populated one.")

    @twisted_wrapper
    def test_get_outstanding_requests(self):
        """
        Test the GET: outstanding request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_outstanding(param_dict)
        self.assertEqual(result, "[]", "The response was not []. This would suggest that something went wrong with "
                                       "the outstanding request.")

    @twisted_wrapper(30)
    def test_get_verification_output(self):
        """
        Test the GET: verification output request type
        :return: None
        """
        attestation_value = quote(b64encode('binarydata')).replace("+", "%2B")

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_hash': attestation_value,
            'attribute_value': attestation_value,
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(json.dumps({'psn': '1234567890'}))
        }

        yield self.send_attestation_requests_to_all(param_dict)
        attestation_responses = yield self.attest_all_outstanding_requests(param_dict)

        yield self.verify_all_attestations(attestation_responses[0], param_dict)

        result = yield self._get_style_requests.make_verification_output(param_dict)
        print result
        self.assertFalse(not result, "The response was not an empty dictionary. This would suggest that something went "
                                     "wrong with the verification output request.")

    @twisted_wrapper
    def test_get_attributes(self):
        """
        Test the GET: attributes request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_attributes(param_dict)
        self.assertEqual(result, "[]", "The response was not []. This would suggest that something went wrong with "
                                       "the attributes request.")

    @twisted_wrapper
    def test_get_drop_identity(self):
        """
        Test the GET: drop identity request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_drop_identity(param_dict)
        self.assertEqual(result, "", "The identity could not be dropped. Received non-empty response.")

    @twisted_wrapper(30)
    def test_post_attestation_request(self):
        """
        Test the POST: request request type
        :return: None
        """
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': quote(b64encode('binarydata')).replace("+", "%2B"),
            'metadata': b64encode(json.dumps({'psn': '1234567890'}))
        }

        result = yield self.send_attestation_requests_to_all(param_dict)
        self.assertTrue(all(x == "" for x in result[1]), "At least one of the attestation request "
                                                         "responses was non-empty.")

    @twisted_wrapper(30)
    def test_post_attest(self):
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_value': quote(b64encode('binarydata')).replace("+", "%2B"),
            'metadata': b64encode(json.dumps({'psn': '1234567890'}))
        }

        yield self.send_attestation_requests_to_all(param_dict)

        response = yield self.attest_all_outstanding_requests(param_dict)

        self.assertTrue(all(x == "" for x in response[1]), "At least one of the attestation responses was non-empty.")

    @twisted_wrapper(30)
    def test_post_verify(self):
        """
        Test the POST: verify request type
        :return: None
        """
        attestation_value = quote(b64encode('binarydata')).replace("+", "%2B")

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation',
            'attribute_name': 'QR',
            'attribute_hash': attestation_value,
            'attribute_value': attestation_value,
            'attribute_values': 'YXNk,YXNkMg==',
            'metadata': b64encode(json.dumps({'psn': '1234567890'}))
        }

        yield self.send_attestation_requests_to_all(param_dict)
        attestation_responses = yield self.attest_all_outstanding_requests(param_dict)

        verification_responses = yield self.verify_all_attestations(attestation_responses[0], param_dict)

        self.assertTrue(all(x == "" for x in verification_responses), "At least one of the verification "
                                                                      "responses was non-empty.")
