from __future__ import absolute_import

import logging
from traceback import format_tb

from twisted.internet import reactor
from twisted.internet.defer import maybeDeferred
from twisted.python.compat import intToBytes
from twisted.web import http, server

from .json_util import dumps
from .root_endpoint import RootEndpoint
from ..taskmanager import TaskManager


class RESTManager(TaskManager):
    """
    This class is responsible for managing the startup and closing of the HTTP API.
    """

    def __init__(self, session):
        super(RESTManager, self).__init__()
        self._logger = logging.getLogger(self.__class__.__name__)
        self.session = session
        self.site = None
        self.root_endpoint = None

    def start(self, port=8085):
        """
        Starts the HTTP API with the listen port as specified in the session configuration.
        """
        self.root_endpoint = RootEndpoint(self.session)
        site = server.Site(resource=self.root_endpoint)
        site.requestFactory = RESTRequest
        self.site = reactor.listenTCP(port, site, interface="127.0.0.1")

    def stop(self):
        """
        Stop the HTTP API and return a deferred that fires when the server has shut down.
        """
        return maybeDeferred(self.site.stopListening)


class RESTRequest(server.Request):
    """
    This class gracefully takes care of unhandled exceptions raised during the processing of any request.
    """
    defaultContentType = b"application/json"

    def __init__(self, *args, **kw):
        server.Request.__init__(self, *args, **kw)
        self._logger = logging.getLogger(self.__class__.__name__)

        # Default headers
        self.setHeader(b'Access-Control-Allow-Origin', b'*')

    def processingFailed(self, failure):
        self._logger.exception(failure)
        response = {
            u"error": {
                u"handled": False,
                u"code": failure.value.__class__.__name__,
                u"message": str(failure.value)
            }
        }
        if self.site.displayTracebacks:
            response[u"error"][u"trace"] = format_tb(failure.getTracebackObject())

        body = dumps(response, True).encode('utf-8')
        self.setResponseCode(http.INTERNAL_SERVER_ERROR)
        self.setHeader(b'Content-Type', self.defaultContentType)
        self.setHeader(b'Content-Length', intToBytes(len(body)))
        self.write(body)
        self.finish()
        return failure
