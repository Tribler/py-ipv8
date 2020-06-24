import logging

from aiohttp import web

from . import json_util as json

HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_PRECONDITION_FAILED = 412
HTTP_INTERNAL_SERVER_ERROR = 500

DEFAULT_HEADERS = {}


class BaseEndpoint:

    def __init__(self, middlewares=()):
        self._logger = logging.getLogger(self.__class__.__name__)
        self.app = web.Application(middlewares=middlewares)
        self.session = None
        self.endpoints = {}
        self.setup_routes()

    def setup_routes(self):
        pass

    def initialize(self, session):
        self.session = session
        for endpoint in self.endpoints.values():
            endpoint.initialize(session)

    def add_endpoint(self, prefix, endpoint):
        self.endpoints[prefix] = endpoint
        self.app.add_subapp(prefix, endpoint.app)


class Response(web.Response):

    def __init__(self, body=None, headers=None, content_type=None, status=200, **kwargs):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            content_type = 'application/json'
        super(Response, self).__init__(body=body, headers=headers or DEFAULT_HEADERS,
                                       content_type=content_type, status=status, **kwargs)
