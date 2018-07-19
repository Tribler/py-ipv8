import logging
import os
import threading
from ast import literal_eval
from shutil import rmtree

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

COMMUNITY_TO_MASTER_PEER_KEY = {
    'AttestationCommunity': ECCrypto().generate_key(u'high'),
    'DiscoveryCommunity': ECCrypto().generate_key(u'high'),
    'HiddenTunnelCommunity': ECCrypto().generate_key(u'high'),
    'IdentityCommunity': ECCrypto().generate_key(u'high'),
    'TrustChainCommunity': ECCrypto().generate_key(u'high'),
    'TunnelCommunity': ECCrypto().generate_key(u'high')
}


class TestPeer(object):
    """
    Class for the purpose of testing the REST API
    """

    master_peer_att = Peer(("3052301006072a8648ce3d020106052b8104001a033e000400fde127289850e6e550d28a083"
                            "c539e6a449b7131ef53cf90f2fc3f3243017c98631855c0d80e77939da29cfef70ecdb3cea7"
                            "c37db7e18d275f715c").decode("HEX"))

    master_peer_identity = Peer(("3052301006072a8648ce3d020106052b8104001a033e000400d1aaecf1acc0db3aecc0"
                                 "efb07f66f815d1a4e0804c7aa233bf144ed9cd002e2579265ef30e0a4355460a50f12f"
                                 "5a4a5ad5033095aec4f9111f5376").decode("HEX"))

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
            self._ipv8.overlays[idx].master_peer = Peer(COMMUNITY_TO_MASTER_PEER_KEY[type(overlay).__name__])
            # if type(overlay).__name__ == "AttestationCommunity":
            #     self._ipv8.overlays[idx].master_peer = self.master_peer_att
            # else:
            #     self._ipv8.overlays[idx].master_peer = self.master_peer_identity

        self._rest_manager = TestPeer.RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

    def print_master_peers(self):
        """
        Print details on the master peers of each of this peer's overlays

        :return: None
        """
        from base64 import b64encode

        for overlay in self._ipv8.overlays:
            print b64encode(overlay.master_peer.mid), overlay.master_peer.public_key, overlay.master_peer.address, \
                overlay.master_peer.key.pub().key_to_bin().encode("HEX")

    def get_address(self):
        """
        Return the address of this peer

        :return: A tuple[str, int] representing the address of this peer (i.e. the interface and port)
        """
        return self._ipv8.endpoint.get_address()

    def add_and_verify_peers(self, peer_and_addresses):
        """
        Add a set of peers to the set of verified peers and register their services

        :param peer_and_addresses: a list where each element contains a peer and a None or a tuple[String, Int]
                                   of the interface and the port
        :return: None
        """
        assert peer_and_addresses is not None and isinstance(peer_and_addresses, list), "peer_and_addresses must be " \
                                                                                        "a non-empty list"
        assert all(isinstance(x[0], Peer) and (x[1] is None or isinstance(x[1], tuple) and isinstance(x[1][0], str) and
                                               isinstance(x[1][1], int)) for x in peer_and_addresses), \
            "peer_and_addresses must be  a list of tuple[Peer, tuple[String, Int]]"

        for peer, address in peer_and_addresses:
            if address is not None:
                self.add_and_verify_peer(peer, address)
            else:
                self.add_and_verify_peer(peer)

    def add_and_verify_peer(self, peer, address=("192.168.0.100", 8090)):
        """
        Add a set of peers to the set of verified peers and register their services

        :param peer: the peer to be added
        :param address: the address of the peer
        :return: None
        """
        self._ipv8.network.add_verified_peer(peer)
        self._ipv8.network.discover_services(peer, [overlay.master_peer.mid for overlay in self.get_overlays()])
        self._ipv8.network.discover_address(peer, address)

    def add_verified_peer(self, peer):
        """
        Add a new verified peer

        :param peer: the new peer
        :return: None
        """
        self._ipv8.network.add_verified_peer(peer)

    def add_peer_to_all_services(self, peer):
        """
        Add a pier to the identity service

        :param peer: the peer to be added to the identity service
        :return: None
        """
        self._ipv8.network.discover_services(peer, [overlay.master_peer.mid for overlay in self.get_overlays()])

    def add_peer_address(self, peer, interface, port):
        """
        Add the address of a peer so it becomes accessible

        :param peer: the peer whose address will be added
        :param interface: The interface (IP or alias) of the peer
        :param port: The port on which the peer accepts requests
        :return: None
        """
        self._ipv8.network.discover_address(peer, (interface, port))

    def stop(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")
        self._ipv8.endpoint.close()
        self._rest_manager.shutdown_task_manager()
        self._rest_manager.stop()

        if os.path.isdir(self._path):
            rmtree(self._path)

    @staticmethod
    def _create_working_directory(path):
        """
        Creates a dir at the specified path, if not previously there; otherwise deletes the dir, and makes a new one.

        :param path: the location at which the dir is created
        :return: None
        """
        if os.path.isdir(path):
            rmtree(path)
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

    excluded_peers = {'rZvL7BqYKKrnbdsWfRDk1DMTtG0='}

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
        assert get_style_requests is None or isinstance(get_style_requests, GetStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"
        assert post_style_requests is None or isinstance(post_style_requests, PostStyleRequests), \
            "The get_style_requests parameter must be a subclass of GetStyleRequests"

        TestPeer.__init__(self, path, port, interface, configuration)
        threading.Thread.__init__(self)

        # Check to see if the user has provided request generators
        self._get_style_requests = get_style_requests if get_style_requests is not None else HTTPGetRequester()
        self._post_style_requests = post_style_requests if post_style_requests is not None else HTTPPostRequester()

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

        peer_list = yield self._get_style_requests.make_peers(dict_param)
        peer_list = set(literal_eval(peer_list))

        # Keep iterating until peer_list is non-empty
        while not peer_list - excluded_peer_mids:
            # Wait for 4 seconds before trying again
            yield deferLater(reactor, 4, lambda: None)

            # Forward and wait for the response
            peer_list = yield self._get_style_requests.make_peers(dict_param)
            peer_list = set(literal_eval(peer_list))

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
