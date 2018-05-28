from ipv8.REST.rest_manager import RESTRequest
from ipv8.REST.root_endpoint import RootEndpoint
from ipv8.taskmanager import TaskManager
from twisted.web import server
from twisted.internet.defer import maybeDeferred
from twisted.internet import reactor

import logging


class RestAPITestWrapper(TaskManager):
    """
    This class is responsible for managing the startup and closing of the HTTP API.
    """

    def __init__(self, session, port=8085, interface='127.0.0.1'):
        super(RestAPITestWrapper, self).__init__()
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
