from __future__ import absolute_import

import logging
from json import loads

from six.moves.urllib_parse import quote
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers

from .peer_communication import IGetStyleRequestsAE, RequestException, IPostStyleRequestsAE


def process_json_response(func):
    """
    Processes a json'ed request response, and returns a de-json'ed Python data structure
    """
    @inlineCallbacks
    def wrapper(self, param_dict):
        res = yield func(self, param_dict)
        returnValue(loads(res))
    return wrapper


class HTTPRequester(object):
    """
    HTTP request superclass, which defines the common behavior between the different types of HTTP REST requests
    """

    def __init__(self):
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Initializing the HTTP Requester.")

        self._agent = Agent(reactor)

        self._logger.info("HTTP Requester initialized.")

    @inlineCallbacks
    def make_request(self, url, request_type, arguments=None, on_complete_callback=None):
        """
        Forward an HTTP request of the specified type to a url, with the specified set of arguments.

        :param url: the url of this request (i.e. http://<interface>:<port>/<endpoint>)
        :param request_type: the type of request (GET, POST, PUT, DELETE, etc.)
        :param arguments: the arguments to be attached to the request. This should be a dictionary or None
        :param on_complete_callback: a callback which is triggered when the request completes
        :return: a Deferred object for the response of this request
        """
        # If no arguments are sent, then assign default empty arguments
        if arguments is None:
            arguments = {}

        request_url = url + '?' + '&'.join("%s=%s" % (k, v) for k, v in arguments.items())
        self._logger.info("[HTTP-%s] %s", request_type, request_url)

        d = self._agent.request(
            request_type.encode('utf_8'),
            request_url.encode('utf_8'),
            Headers({'User-Agent': ['Twisted Web Client'],
                     'Content-Type': ['text/x-greeting']}),
            None)

        response = yield d.addCallback(on_complete_callback if on_complete_callback else readBody)
        returnValue(response)

    @staticmethod
    def get_access_parameters(param_dict):
        """
        Retrieves the interface, port, and endpoint from the param_dict dictionary parameter. The param_dict dictionary
        must contain the following keys (with associated value examples):
            {
                'interface': '127.0.0.1'
                'port': 8086 or 'port': '8086'
                'endpoint': 'attestation'
            }

        :param param_dict: holds a dictionary of the request parameters, which must contain entries for the interface,
                           port and endpoint
        :return: the interface, port, and endpoint objects
        :raises RequestException: raised when the method could not find some element required for the construction of
                                  the request
        """
        interface = param_dict.get('interface', None)
        if not interface:
            raise RequestException("Malformed request: did not specify interface")

        port = param_dict.get('port', None)
        if not port:
            raise RequestException("Malformed request: did not specify port")

        endpoint = param_dict.get('endpoint', None)
        if not endpoint:
            raise RequestException("Malformed request: did not specify endpoint")

        return interface, port, endpoint

    @staticmethod
    def basic_url_builder(interface, port, endpoint, protocol='http'):
        """
        Build a basic url consisting of the protocol, interface, port and endpoint

        :param interface: the interface
        :param port: the port
        :param endpoint: the endpoint
        :param protocol: the protocol of the associate request
        :return: a url of the form <protocol>://<interface>:<port>/<endpoint>
        """
        return "%s://%s:%d/%s" % (protocol, interface, port, endpoint)


class HTTPGetRequesterAE(IGetStyleRequestsAE, HTTPRequester):
    """
    Implements the GetStyleRequests abstract methods using the HTTP protocol for the attestation endpoint
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
        request_parameters = {'type': 'request'}

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
        request_parameters = {'type': 'verify'}

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


def string_to_url(string, quote_string=False, to_utf_8=False):
    """
    Convert a string to a format which is compatible to it being passed via a url

    :param string: the string to be processed
    :param quote_string: True if the processed string should be quoted or not
    :param to_utf_8: if True result is returned as utf-8 format, otherwise as unicode
    :return: a url compatible string
    """
    string = string if isinstance(string, str) else string.decode('utf-8')

    string = string.replace("+", "%2B") if not quote_string else quote(string.replace("+", "%2B"))

    return string.encode('utf-8') if to_utf_8 else string
