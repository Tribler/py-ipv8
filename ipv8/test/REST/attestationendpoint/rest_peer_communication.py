from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks, returnValue

from .peer_communication import IGetStyleRequestsAE, IPostStyleRequestsAE
from ...mocking.rest.rest_peer_communication import HTTPRequester, RequestException, process_json_response


class HTTPGetRequesterAE(IGetStyleRequestsAE, HTTPRequester):
    """
    Implements the GetStyleRequests abstract methods using the HTTP protocol for the attestation endpoint.
    """

    def __init__(self):
        IGetStyleRequestsAE.__init__(self)
        HTTPRequester.__init__(self)

    @process_json_response
    @inlineCallbacks
    def make_outstanding(self, param_dict):
        """
        Forward a request for outstanding attestation requests.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           {'type': 'outstanding'},
                                           param_dict.get('callback', None))
        returnValue(response)

    @process_json_response
    @inlineCallbacks
    def make_verification_output(self, param_dict):
        """
        Forward a request for the verification outputs.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           {'type': 'verification_output'},
                                           param_dict.get('callback', None))
        returnValue(response)

    @process_json_response
    @inlineCallbacks
    def make_peers(self, param_dict):
        """
        Forward a request for the known peers in the network.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           {'type': 'peers'},
                                           param_dict.get('callback', None))
        returnValue(response)

    @process_json_response
    @inlineCallbacks
    def make_attributes(self, param_dict):
        """
        Forward a request for the attributes of a peer.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (attributes), and the (optional) b64_mid of the attester
        request_parameters = param_dict.get('request_parameters', dict())
        request_parameters.update({'type': 'attributes'})

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)

    @process_json_response
    @inlineCallbacks
    def make_dht_block(self, param_dict):
        """
        Forward a request for the latest TC block of a peer

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                'public_key': the public key of the peer whose latest TC block is being requested
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)
        request_parameters = {}

        if 'public_key' in param_dict:
            request_parameters['public_key'] = param_dict['public_key']
        else:
            raise RequestException("Malformed request: did not specify the public_key")

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)

    @inlineCallbacks
    def make_drop_identity(self, param_dict):
        """
        Forward a request for dropping a peer's identity.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           {'type': 'drop_identity'},
                                           param_dict.get('callback', None))
        returnValue(response)

    @process_json_response
    @inlineCallbacks
    def make_outstanding_verify(self, param_dict):
        """
        Forward a request which requests information on the outstanding verify requests

        :param param_dict: Should have at least the following structure:
            {
                    'interface': target peer IP or alias
                    'port': port_number
                    'endpoint': endpoint_name
                    (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (request), and the rest of the parameters
        request_parameters = {'type': 'outstanding_verify'}

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'GET',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)


class HTTPPostRequesterAE(IPostStyleRequestsAE, HTTPRequester):
    """
    Implements the PostStyleRequests abstract methods using the HTTP protocol for the AttestationEndpoint
    """

    def __init__(self):
        IPostStyleRequestsAE.__init__(self)
        HTTPRequester.__init__(self)

    @inlineCallbacks
    def make_attestation_request(self, param_dict):
        """
        Forward a request for the attestation of an attribute.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                'attribute_name': attribute_name
                'mid': attester b64_mid
                (optional) 'metadata': JSON style metadata required for the attestation process
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (request), and the rest of the parameters
        request_parameters = {'type': 'request', 'id_format': 'id_metadata'}

        # Add the request parameters one-by-one; if required parameter is missing, then raise error
        if 'attribute_name' in param_dict:
            request_parameters['attribute_name'] = param_dict['attribute_name']
        else:
            raise RequestException("Malformed request: did not specify the attribute_name")

        if 'mid' in param_dict:
            request_parameters['mid'] = param_dict['mid']
        else:
            raise RequestException("Malformed request: did not specify the attester's mid")

        if 'metadata' in param_dict:
            request_parameters['metadata'] = param_dict['metadata']

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)

    @inlineCallbacks
    def make_attest(self, param_dict):
        """
        Forward a request which attests an attestation request.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                'attribute_name': attribute_name
                'mid': attestee's b64_mid
                'attribute_value': b64 hash of the attestation blob
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (attest), and the rest of the parameters
        request_parameters = {'type': 'attest'}

        # Add the request parameters one-by-one; if required parameter is missing, then raise error
        if 'attribute_name' in param_dict:
            request_parameters['attribute_name'] = param_dict['attribute_name']
        else:
            raise RequestException("Malformed request: did not specify the attribute_name")

        if 'mid' in param_dict:
            request_parameters['mid'] = param_dict['mid']
        else:
            raise RequestException("Malformed request: did not specify the attestee's mid")

        if 'attribute_value' in param_dict:
            request_parameters['attribute_value'] = param_dict['attribute_value']
        else:
            raise RequestException("Malformed request: did not specify the attribute_value, i.e. the attestation"
                                   "blob hash")

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)

    @inlineCallbacks
    def make_verify(self, param_dict):
        """
        Forward a request which demands the verification of an attestation

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                'attribute_hash': the b64 hash of the attestation blob which needs to be verified
                'mid': verifier's b64_mid
                'attribute_values': a string of b64 encoded values, which are separated by ',' characters
                                    e.g. "val_1,val_2,val_3, ..., val_N"
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (attest), and the rest of the parameters
        request_parameters = {'type': 'verify', 'id_format': 'id_metadata'}

        # Add the request parameters one-by-one; if required parameter is missing, then raise error
        if 'attribute_hash' in param_dict:
            request_parameters['attribute_hash'] = param_dict['attribute_hash']
        else:
            raise RequestException("Malformed request: did not specify the attribute_hash")

        if 'mid' in param_dict:
            request_parameters['mid'] = param_dict['mid']
        else:
            raise RequestException("Malformed request: did not specify the verifier's mid")

        if 'attribute_values' in param_dict:
            request_parameters['attribute_values'] = param_dict['attribute_values']
        else:
            raise RequestException("Malformed request: did not specify the attribute_values")

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None))

        returnValue(response)

    @inlineCallbacks
    def make_allow_verify(self, param_dict):
        """
        Forward a request which requests that verifications be allowed for a particular peer for a particular attribute

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                'attribute_name': attribute_name
                'mid': verifier's b64_mid
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: the request's response
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (request), and the rest of the parameters
        request_parameters = {'type': 'allow_verify'}

        # Add the request parameters one-by-one; if required parameter is missing, then raise error
        if 'attribute_name' in param_dict:
            request_parameters['attribute_name'] = param_dict['attribute_name']
        else:
            raise RequestException("Malformed request: did not specify the attribute_name")

        if 'mid' in param_dict:
            request_parameters['mid'] = param_dict['mid']
        else:
            raise RequestException("Malformed request: did not specify the attester's mid")

        response = yield self.make_request(HTTPRequester.basic_url_builder(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None))
        returnValue(response)
