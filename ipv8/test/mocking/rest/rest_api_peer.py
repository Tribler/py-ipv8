import logging
import threading
from base64 import b64encode

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, maybeDeferred
from twisted.internet.task import deferLater
from twisted.web import server

from .ipv8 import TestRestIPv8
from ....REST.rest_manager import RESTRequest
from ....REST.root_endpoint import RootEndpoint
from ....taskmanager import TaskManager


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
        super(RestAPITestWrapper, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        self._session = session
        self._site = None
        self._site_port = None
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
        self._site_port = reactor.listenTCP(self._port, self._site, interface=self._interface)

    def stop(self):
        """
        Stop the HTTP API and return a deferred that fires when the server has shut down.
        """
        self._site.stopFactory()
        return maybeDeferred(self._site_port.stopListening)

    def get_access_parameters(self):
        """
        Creates a dictionary of parameters used to access the peer

        :return: the dictionary of parameters used to access the peer
        """
        return {
            'port': self._port,
            'interface': self._interface,
            'url': 'http://%s:%d/attestation' % (self._interface, self._port)
        }


class RestTestPeer(object):
    """
    This class provides a basic level of functionality for peers that can be used in the REST API test cases
    """

    def __init__(self, port, overlay_classes, interface='127.0.0.1', memory_dbs=True):
        """
        Create a test peer with a REST API interface. All subclasses should maintain 'port' as their first initializer
        parameter

        :param port: this peer's port
        :param overlay_classes: the set of overlay classes which should be contained in the peer's IPv8 session object
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param memory_dbs: True if the peers should use a memory DB. If False, a folder will be generated for this peer
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self._logger.info("Peer starting-up.")

        self._rest_manager = None

        self._port = port
        self._interface = interface

        self._ipv8 = TestRestIPv8(u'curve25519', overlay_classes, memory_dbs)

        self._rest_manager = RestAPITestWrapper(self._ipv8, self._port, self._interface)
        self._rest_manager.start()
        self._logger.info("Peer started up.")

    def get_address(self):
        """
        Return the address of this peer

        :return: A tuple[str, int] representing the address of this peer (i.e. the interface and port)
        """
        return self._ipv8.endpoint.wan_address

    def add_and_verify_peers(self, peers, replace_default_interface=True):
        """
        Add a set of peers to the set of verified peers and register their services

        :param peers: a list of peers of the type TestPeer
        :param replace_default_interface: if True, replaces the '0.0.0.0' all broadcast interface to the 'localhost'
        :return: None
        """
        assert peers is not None and isinstance(peers, list), "peers must be a non-empty list"
        assert all(isinstance(x, RestTestPeer) for x in peers), "All peers must be of the TestPeer type"

        for peer in peers:
            interface, port = peer.get_address()

            if interface == '0.0.0.0' and replace_default_interface:
                for inner_peers in peer.get_keys().values():
                    self.add_and_verify_peer(inner_peers, port=port)
            else:
                for inner_peers in peer.get_keys().values():
                    self.add_and_verify_peer(inner_peers, interface, port)

    def add_and_verify_peer(self, peer, interface='127.0.0.1', port=8090):
        """
        Manually add a peer to the set of verified peers and register it for all services in this peer

        :param peer: the peer to be added
        :param interface: the peer's interface
        :param port: the peer's REST API port
        :return: None
        """
        # Add verified peer
        self._ipv8.network.add_verified_peer(peer)

        # Add the peer as to all services
        self._ipv8.network.discover_services(peer, [overlay.master_peer.mid for overlay in self._ipv8.overlays])

        # Associate an address to this peer
        self._ipv8.network.discover_address(peer, (interface, port))

    def add_verified_peer(self, peer):
        """
        Add a new verified peer

        :param peer: the new peer
        :return: None
        """
        self._ipv8.network.add_verified_peer(peer)

    def add_peer_address(self, peer, interface, port):
        """
        Add the address of a peer so it becomes accessible

        :param peer: the peer whose address will be added
        :param interface: The interface (IP or alias) of the peer
        :param port: The port on which the peer accepts requests
        :return: None
        """
        self._ipv8.network.discover_address(peer, (interface, port))

    @inlineCallbacks
    def unload(self):
        """
        Stop the peer

        :return: None
        """
        self._logger.info("Shutting down the peer")

        self._rest_manager.stop()
        self._rest_manager.shutdown_task_manager()

        yield self._ipv8.unload()

    def get_keys(self):
        """
        Get the peer's keys

        :return: the peer's keys
        """
        self._logger.info("Fetching my IPv8 object's peer.")
        return self._ipv8.keys

    def get_named_key(self, name):
        """
        Get the peer's keys

        :param name: the name of the key
        :return: the peer's keys
        """
        self._logger.info("Fetching my IPv8 object's peer.")
        return self._ipv8.keys[name]

    def get_mids(self, replace_characters=True):
        """
        Return a list of the b64 encoded mids of this peer

        :param replace_characters: a boolean variable, which indicates whether certain characters which cannot
                                  be forwarded within an HTTP request should be replaced
        :return: a list of the peer's mids (encoded in b64)
        """
        if replace_characters:
            return [b64encode(x.mid) for x in self._ipv8.keys.values()]

        return [b64encode(x.mid) for x in self._ipv8.keys.values()]

    def get_overlay_by_class(self, cls):
        """
        Get one of the peer's overlays as identified by its name

        :parameter cls: the class of the overlay
        :return: the peer's overlays
        """
        self._logger.info("Fetching my IPv8 object's overlay: %s", cls)
        for overlay in self._ipv8.overlays:
            if isinstance(overlay, cls):
                return overlay

        return None

    @inlineCallbacks
    def sleep(self, time=.05):
        yield deferLater(reactor, time, lambda: None)

    @property
    def port(self):
        return self._port

    @property
    def interface(self):
        return self._interface


class InteractiveRestTestPeer(RestTestPeer, threading.Thread):
    """
    This class adds fields for GET and POST type requests, as well as inheriting from the Thread class, for independent,
    asynchronous behaviour. Subclasses should implement the actual main logic of the peer in the run() method
    (from Thread).
    """

    def __init__(self, port, overlay_classes, get_style_requests, post_style_requests, interface='127.0.0.1',
                 memory_dbs=True):
        """
        InteractiveTestPeer initializer

        :param port: this peer's port
        :param overlay_classes: the set of overlay classes which should be contained in the peer's IPv8 session object
        :param get_style_requests: GET style request generator
        :param post_style_requests: POST style request generator
        :param interface: IP or alias of the peer. Defaults to '127.0.0.1'
        :param memory_dbs: if True, then the DBs of the various overlays / communities are stored in memory; on disk
                           if False
        """
        RestTestPeer.__init__(self, port, overlay_classes, interface, memory_dbs)
        threading.Thread.__init__(self)

        self._get_style_requests = get_style_requests
        self._post_style_requests = post_style_requests

        self._logger.info("Successfully acquired request generators.")
