import time
import unittest
from base64 import b64encode
from twisted.internet.defer import returnValue, inlineCallbacks
from urllib import quote

from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.peer_interactive_behavior import AndroidTestPeer
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8.test.REST.rtest.test_rest_api_peer import TestPeer
from ipv8.test.util import twisted_wrapper


class SingleServerSetup(unittest.TestCase):
    """
    Test class which defines an environment with one well-known peer. This should be extended by other subclasses,
    which implement specific test cases.
    """

    def __init__(self, *args, **kwargs):
        super(SingleServerSetup, self).__init__(*args, **kwargs)

        # Call the method which sets up the environment
        self.initialize()

    def initialize(self,
                   port=8086,
                   interface='127.0.0.1',
                   path='test_env',
                   configuration=None,
                   get_style_requests=None,
                   post_style_requests=None):
        """
        An initializer method for the Single Server test environment

        :param port: the port at which the Well Known peer will serve requests
        :param interface: the address of the interface at which the Well Known peer will serve requests
        :param path: the path where a local working directory will be created
        :param configuration: a configuration object for the initialization of the well-known peer
        be a unit test. That is, it should be a short method that calls some of
        the assert* methods.
        :param get_style_requests: a subclass of the
        :param post_style_requests:
        """

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
        super(SingleServerSetup, self).setUp()

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

    @twisted_wrapper(40)
    def test_general_scenario(self):
        from json import loads

        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        client_peer = AndroidTestPeer(param_dict, 'client_peer', 9876)
        client_peer.start()

        try:
            value = yield self.wait_for_peers(param_dict)
            print "Known peers:", value
            done = False
            while not done:
                value = yield self.wait_for_attestation_request(param_dict)
                value = loads(value)
                print "Pending attestation request for attester:", value
                raw_input('PRESS ANY KEY TO CONTINUE')
                for (identifier, attribute) in value:
                    param_dict['mid'] = str(identifier).replace("+", "%2B")
                    param_dict['attribute_name'] = str(attribute)
                    param_dict['attribute_value'] = quote(b64encode('binarydata')).replace("+", "%2B")

                    yield self._post_style_requests.make_attest(param_dict)
                    done = True
        except:
            import traceback
            traceback.print_exc()

    @twisted_wrapper
    def test_during_development(self):
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        result = yield self._get_style_requests.make_peers(param_dict)
        print "The response body:", result
