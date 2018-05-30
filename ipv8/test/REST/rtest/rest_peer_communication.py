from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, RequestException, PostStyleRequests
from twisted.web.http_headers import Headers


class HTTPRequester(object):
    """
    HTTP request superclass, which defines the common behavior between the different types of HTTP REST requests
    """

    def __init__(self):
        self._agent = Agent(reactor)

    @inlineCallbacks
    def make_request(self, url, request_type, arguments=None, on_complete_callback=None):
        """
        Forward an HTTP request of the specified type to a url, with the specified set of arguments.

        :param url: the destination of the request
        :param request_type: the type of request (GET, POST, PUT, DELETE, etc.)
        :param arguments: the arguments to be attached to the request
        :param on_complete_callback:
        :return: a Deferred object for the response of this request
        """
        # If no arguments are sent, then assign default empty arguments
        if arguments is None:
            arguments = {}

        # If no callback is supplied, then assign a standard callback
        if not on_complete_callback:
            on_complete_callback = (lambda x: readBody(x))

        request_url = url + '?' + '&'.join("%s=%s" % (k, v) for k, v in arguments.iteritems())
        print "\t[HTTP-%s] %s" % (request_type, request_url)
        d = self._agent.request(
            request_type,
            request_url,
            Headers({'User-Agent': ['Twisted Web Client Example'],
                     'Content-Type': ['text/x-greeting']}),
            None)

        response = yield d.addCallback(on_complete_callback)
        returnValue(response)

    @staticmethod
    def get_access_parameters(param_dict):
        """
        Explores the **kwargs parameter in order to obtain the interface, port, and endpoint parameters required in
        order to forward an HTTP request to a peer. May E.g. of proper contents of **kwargs:

            'interface': '127.0.0.1'
            'port': 8086 or 'port': '8086'
            'endpoint': 'attestation'

        :param param_dict: holds a dictionary of the
        :return: the interface, port, and endpoint objects
        :raises RequestException: raised when the method could not find one of the required pieces of information
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


class HTTPGetRequester(GetStyleRequests, HTTPRequester):
    """
    Implements the GetStyleRequests abstract methods using the HTTP protocol
    """

    def __init__(self):
        GetStyleRequests.__init__(self)
        HTTPRequester.__init__(self)

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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           {'type': 'outstanding'},
                                           param_dict.get('callback', None)
                                           )
        returnValue(response)

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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           {'type': 'verification_output'},
                                           param_dict.get('callback', None)
                                           )
        returnValue(response)

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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           {'type': 'peers'},
                                           param_dict.get('callback', None)
                                           )
        returnValue(response)

    @inlineCallbacks
    def make_attributes(self, param_dict):
        """
        Forward a request for the known peers in the network.

        :param param_dict: Should have at least the following structure:
            {
                'interface': target peer IP or alias
                'port': port_number
                'endpoint': endpoint_name
                (optional) 'callback': single parameter callback for the request's response
            }
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (attributes), and the (optional) b64_mid of the attester
        request_parameters = param_dict.get('request_parameters', dict())
        request_parameters.update({'type': 'attributes'})

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           request_parameters,
                                           param_dict.get('callback', None)
                                           )
        returnValue(response)

    @inlineCallbacks
    def make_drop_identity(self, param_dict):
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'GET',
                                           {'type': 'drop_identity'},
                                           param_dict.get('callback', None)
                                           )
        returnValue(response)


class HTTPPostRequester(PostStyleRequests, HTTPRequester):
    """
    Implements the PostStyleRequests abstract methods using the HTTP protocol
    """

    def __init__(self):
        PostStyleRequests.__init__(self)
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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
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

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None)
                                           )
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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
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

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None)
                                           )
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
        :return: None
        :raises RequestException: raised when the method could not find one of the required pieces of information
        """
        interface, port, endpoint = HTTPRequester.get_access_parameters(param_dict)

        # Add the type of the request (attest), and the rest of the parameters
        request_parameters = {'type': 'attest'}

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

        response = yield self.make_request("http://{0}:{1}/{2}".format(interface, port, endpoint),
                                           'POST',
                                           request_parameters,
                                           param_dict.get('callback', None)
                                           )

        returnValue(response)
