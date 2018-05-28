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
        self.session = session
        self.site = None
        self.root_endpoint = None
        self.port = port
        self.interface = interface

    def start(self):
        """
        Starts the HTTP API with the listen port as specified in the session configuration.
        """
        self.root_endpoint = RootEndpoint(self.session)
        site_aux = server.Site(resource=self.root_endpoint)
        site_aux.requestFactory = RESTRequest
        self.site = reactor.listenTCP(8085, site_aux, interface='localhost')

    def stop(self):
        """
        Stop the HTTP API and return a deferred that fires when the server has shut down.
        """
        return maybeDeferred(self.site.stopListening)

    def get_access_parameters(self):
        """
        Creates a dictionary of parameters used to access the peer

        :return: the dictionary of parameters used to access the peer
        """
        return {
            'port': self.port,
            'interface': self.interface,
            'url': 'http://{0}:{1}/attestation'.format(self.interface, self.port)
        }
