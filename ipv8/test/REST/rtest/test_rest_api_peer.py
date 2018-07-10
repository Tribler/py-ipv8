import logging
import os
import threading

from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred, inlineCallbacks, returnValue
from twisted.internet.task import deferLater
from twisted.web import server

from ipv8.REST.rest_manager import RESTRequest
from ipv8.REST.root_endpoint import RootEndpoint
from ipv8.configuration import get_default_configuration
from ipv8.keyvault.crypto import ECCrypto
from ipv8.peer import Peer
from ipv8.taskmanager import TaskManager
from ipv8.test.REST.rtest.peer_communication import GetStyleRequests, PostStyleRequests
from ipv8.test.REST.rtest.rest_peer_communication import HTTPGetRequester, HTTPPostRequester
from ipv8_service import IPv8

COMMUNITY_TO_MASTER_PEER = {
    'AttestationCommunity': ECCrypto().generate_key(u'low'),
    'DiscoveryCommunity':  ECCrypto().generate_key(u'low'),
    'HiddenTunnelCommunity':  ECCrypto().generate_key(u'low'),
    'IdentityCommunity':  ECCrypto().generate_key(u'low'),
    'TrustChainCommunity':  ECCrypto().generate_key(u'low'),
    'TunnelCommunity':  ECCrypto().generate_key(u'low')
}


class TestPeer(object):
    """
    Class for the purpose of testing the REST API
    """

    def __init__(self,
                 path,
                 port,
                 interface='127.0.0.1',
                 configuration=None):
        """
        Create a test peer with a REST API interface.

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        """
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

        # Change the master_peers of the IPv8 object's overlays, in order to avoid conflict with the live networks
        for idx, overlay in enumerate(self._ipv8.overlays):
            self._ipv8.overlays[idx].master_peer = Peer(COMMUNITY_TO_MASTER_PEER[type(overlay).__name__])

        self._rest_manager = TestPeer.RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

    def stop(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")
        self._ipv8.endpoint.close()
        self._rest_manager.shutdown_task_manager()
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
        self._logger.info("Fetching my IPv8 object's peer.")
        return self._ipv8.keys

    def get_overlays(self):
        """
        Get the peer's overlays

        :return: the peer's overlays
        """
        self._logger.info("Fetching my IPv8 object's overlays.")
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
            """
            Creates a TaskManager object for REST API testing purposes

            :param session: an (IPv8) session object.
            :param port: this peer's port. Defaults to 8085
            :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
            """
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


class InteractiveTestPeer(TestPeer, threading.Thread):
    """
    This class models the basic behavior of simple peer instances which are used for interaction. Subclasses should
    implement the actual main logic of the peer in the run() method (from Thread).
    """

    def __init__(self,
                 path,
                 port,
                 interface='127.0.0.1',
                 configuration=None,
                 get_style_requests=None,
                 post_style_requests=None):
        """
        InteractiveTestPeer initializer

        :param path: the for the working directory of this peer
        :param port: this peer's port
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param configuration: IPv8 configuration object. Defaults to None
        :param get_style_requests: GET style request generator. Defaults to None
        :param post_style_requests: POST style request generator. Defaults to None
        """
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
    def wait_for_peers(self, dict_param, excluded_peer_mids=None):
        """
        Wait until this peer receives a non-empty list of fellow peers in the network

        :param dict_param: the required parameters by the GET request generator for the peers request type
        :param excluded_peer_mids: A list of peer mids which should not be taken into consideration peers
        :return: a list of currently known peers in the network
        """
        assert isinstance(excluded_peer_mids, (list, set)) or not excluded_peer_mids, "excluded_peer_mids " \
                                                                                      "must be a list or set or None"

        # Make sure excluded_peer_mids is a set
        if not excluded_peer_mids:
            excluded_peer_mids = set()
        elif isinstance(excluded_peer_mids, list):
            excluded_peer_mids = set(excluded_peer_mids)

        import ast

        peer_list = yield self._get_style_requests.make_peers(dict_param)
        peer_list = set(ast.literal_eval(peer_list))

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            # Wait for 4 seconds before trying again
            yield deferLater(reactor, 4, lambda: None)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(ast.literal_eval(peer_list))

        # Return the peer list
        returnValue(list(peer_list - excluded_peer_mids))

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
            yield deferLater(reactor, 4, lambda: None)

            # Forward and wait for the response
            outstanding_requests = yield self._get_style_requests.make_outstanding(dict_param)

        # Return the peer list
        self._logger.info("Have found a non-empty list of outstanding requests. Returning it.")
        returnValue(outstanding_requests)
