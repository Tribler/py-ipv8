import logging
import os
import time
from twisted.internet.defer import returnValue
from twisted.trial import unittest

from ipv8.configuration import get_default_configuration
from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8.test.REST.rtest.test_rest_api_server import RestAPITestWrapper
from ipv8_service import IPv8


class SingleServerSetup(unittest.TestCase):
    """
    Test class which defines an environment with one well-known server
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
        self._logger = logging.getLogger(self.__class__.__name__)

        self._port = port
        self._interface = interface

        self._path = path
        self._configuration = configuration

        # Check to see if we've received a custom configuration
        if configuration is None:
            # Create a default configuration
            self._configuration = get_default_configuration()

            self._configuration['logger'] = {'level': "ERROR"}

            overlays = ['AttestationCommunity', 'IdentityCommunity']
            self._configuration['overlays'] = [o for o in self._configuration['overlays'] if o['class'] in overlays]
            for o in self._configuration['overlays']:
                o['walkers'] = [{
                    'strategy': "RandomWalk",
                    'peers': 20,
                    'init': {
                        'timeout': 60.0
                    }
                }]

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

    @staticmethod
    def create_working_directory(path):
        """
        Creates a dir at the specified path, if not previously there; otherwise deletes the dir, and makes a new one.

        :param path: the location at which the dir is created
        :return: None
        """
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)
        os.mkdir(path)

    def setUp(self):
        # Call super method
        super(SingleServerSetup, self).setUp()

        SingleServerSetup.create_working_directory(self._path)
        os.chdir(self._path)

        ipv8 = IPv8(self._configuration)
        os.chdir(os.path.dirname(__file__))
        self.rest_manager = RestAPITestWrapper(ipv8, self._port, self._interface)
        self.rest_manager.start()

    def tearDown(self):
        # Call super method
        super(SingleServerSetup, self).tearDown()

        self.rest_manager.stop()

    def test_example(self):
        pass


class RequestTest(SingleServerSetup):

    def wait_for_peers(self, dict_param):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :return: a list of currently known peers in the network
        """

        peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Keep iterating until peer_list is non-empty
        while peer_list is "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Return the peer list
        returnValue(peer_list)

    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests is "[]":
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        returnValue(outstanding_requests)

    def test_during_development(self):
        param_dict = {
            'port': 8086,
            'interface': '127.0.0.1',
            'endpoint': 'attestation'
        }

        print("HERE")
        self._get_style_requests.make_peers(param_dict)
