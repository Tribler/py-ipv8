import logging
from json import loads

from six.moves.urllib_parse import quote
from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, returnValue
from twisted.web.client import Agent, readBody
from twisted.web.http_headers import Headers


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


class RequestException(Exception):
    """
    Custom exception used to model request errors
    """
