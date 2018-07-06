import os
import threading
import time

import logging

from ipv8.REST.rest_manager import RESTRequest
from ipv8.REST.root_endpoint import RootEndpoint
from ipv8.configuration import get_default_configuration
from ipv8.taskmanager import TaskManager
from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8_service import IPv8

from twisted.web import server
from twisted.internet.defer import maybeDeferred, inlineCallbacks, returnValue
from twisted.internet import reactor


class TestPeer(object):

    def __init__(self,
                 path,
                 port,
                 interface='127.0.0.1',
                 configuration=None):

        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Peer starting-up.")

        self._rest_manager = None

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

        self._create_working_directory(self._path)
        self._logger.info("Created working directory.")
        os.chdir(self._path)

        self._ipv8 = IPv8(self._configuration)
        os.chdir(os.path.dirname(__file__))
        self._rest_manager = TestPeer.RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

    def stop(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")
        self._rest_manager.stop()

    @staticmethod
    def _create_working_directory(path):
        """
        Creates a dir at the specified path, if not previously there; otherwise deletes the dir, and makes a new one.

        :param path: the location at which the dir is created
        :return: None
        """
        if os.path.isdir(path):
            import shutil
            shutil.rmtree(path)
        os.mkdir(path)

    def get_keys(self):
        """
        Get the peer's keys

        :return: the peer's keys
        """
        return self._ipv8.keys

    def get_overlays(self):
        """
        Get the peer's overlays

        :return: the peer's overlays
        """
        return self._ipv8.overlays

    @property
    def port(self):
        return self._port

    @property
    def interface(self):
        return self._interface

    class RestAPITestWrapper(TaskManager):
        """
        This class is responsible for managing the startup and closing of the HTTP API.
        """

        def __init__(self, session, port=8085, interface='127.0.0.1'):
            super(TestPeer.RestAPITestWrapper, self).__init__()
            self._logger = logging.getLogger(self.__class__.__name__)
            self._session = session
            self._site = None
            self._root_endpoint = None
            self._port = port
            self._interface = interface

        def start(self):
            """
            Starts the HTTP API with the listen port as specified in the session configuration.
            """
            self._root_endpoint = RootEndpoint(self._session)
            self._site = server.Site(resource=self._root_endpoint)
            self._site.requestFactory = RESTRequest
            self._site = reactor.listenTCP(self._port, self._site, interface=self._interface)

        def stop(self):
            """
            Stop the HTTP API and return a deferred that fires when the server has shut down.
            """
            return maybeDeferred(self._site.stopListening)

        def get_access_parameters(self):
            """
            Creates a dictionary of parameters used to access the peer

            :return: the dictionary of parameters used to access the peer
            """
            return {
                'port': self._port,
                'interface': self._interface,
                'url': 'http://{0}:{1}/attestation'.format(self._interface, self._port)
            }

    def get_attestation_by_hash(self, attestation_hash):
        return self._ipv8.overlays[0].database.get_attestation_by_hash(attestation_hash)

    def get_all_attestations(self):
        return self._ipv8.overlays[0].database.get_all()


class InteractiveTestPeer(TestPeer, threading.Thread):
    """
    This class models the basic behavior of simple peer instances which are used for interaction. Subclasses should
    implement the actual main logic of the peer in the run() method (from Thread).
    """

    def __init__(self,
                 path,
                 port,
                 **kwargs):
        """
        InteractiveTestPeer initializer

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param kwargs: a dictionary containing additional configuration parameters:
        {
            'interface': IP or alias of the peer. Defaults to '127.0.0.1'
            'configuration': IPv8 configuration object. Defaults to None
            'get_style_requests': GET style request generator. Defaults to None
            'post_style_requests': POST style request generator. Defaults to None
        }
        """

        interface = kwargs.get('interface', '127.0.0.1')
        configuration = kwargs.get('configuration', None)
        get_style_requests = kwargs.get('get_style_requests', None)
        post_style_requests = kwargs.get('post_style_requests', None)

        TestPeer.__init__(self, path, port, interface, configuration)
        threading.Thread.__init__(self)

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

        self._logger.info("Successfully acquired request generators.")

    @inlineCallbacks
    def wait_for_peers(self, dict_param):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :return: a list of currently known peers in the network
        """
        self._logger.info("Attempting to acquire a list of peers...")
        peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Keep iterating until peer_list is non-empty
        while peer_list == "[]":
            self._logger.info("Could not acquire a list of peers. Will wait 4 seconds and retry.")
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of peers. Returning it.")
        returnValue(peer_list)

    @inlineCallbacks
    def wait_for_attestation_request(self, dict_param):
        """
        Wait until this peer receives a non-empty list of outstanding attestation requests

        :param dict_param: the required parameters by the GET request generator for the outstanding request type
        :return: a list of outstanding attestation requests
        """
        self._logger.info("Attempting to acquire a list of outstanding requests...")
        outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Keep iterating until peer_list is non-empty
        while outstanding_requests == "[]":
            self._logger.info("Could not acquire a list of outstanding requests. Will wait 4 seconds and retry.")
            # Wait for 4 seconds before trying again
            time.sleep(4)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of outstanding requests. Returning it.")
        returnValue(outstanding_requests)
