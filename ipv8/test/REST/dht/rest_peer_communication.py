from __future__ import absolute_import

from twisted.internet.defer import inlineCallbacks, returnValue

from ...mocking.rest.rest_peer_communication import HTTPRequester, RequestException, process_json_response


class HTTPGetRequesterDHT(HTTPRequester):
    """
    Implements the HTTP GET type requests for the DHT endpoint
    """

    def __init__(self):
        HTTPRequester.__init__(self)

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
