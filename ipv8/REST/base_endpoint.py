from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Callable, Generic, Iterable, TypeVar

from aiohttp import web
from aiohttp.abc import Request, StreamResponse
from aiohttp.typedefs import Handler, LooseHeaders

HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404
HTTP_CONFLICT = 409
HTTP_PRECONDITION_FAILED = 412
HTTP_INTERNAL_SERVER_ERROR = 500

DEFAULT_HEADERS: dict[str, str] = {}

T = TypeVar('T')
MiddleWaresType = Iterable[Callable[[Request, Handler], Awaitable[StreamResponse]]]


class BaseEndpoint(Generic[T]):
    """
    Base class for all REST endpoints.
    """

    def __init__(self, middlewares: MiddleWaresType = ()) -> None:
        """
        Create new unregistered and uninitialized REST endpoint.
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self.app = web.Application(middlewares=middlewares)
        self.session: T | None = None
        self.endpoints: dict[str, BaseEndpoint] = {}
        self.setup_routes()

    def setup_routes(self) -> None:
        """
        Register the names to make this endpoint callable.
        """

    def initialize(self, session: T) -> None:
        """
        Initialize this endpoint for the given session instance.
        """
        self.session = session
        for endpoint in self.endpoints.values():
            endpoint.initialize(session)

    def add_endpoint(self, prefix: str, endpoint: BaseEndpoint) -> None:
        """
        Add a new child endpoint to this endpoint.
        """
        self.endpoints[prefix] = endpoint
        self.app.add_subapp(prefix, endpoint.app)


class Response(web.Response):
    """
    A convenience class to auto-encode response bodies in JSON format.
    """

    def __init__(self, body: Any = None, headers: LooseHeaders | None = None,  # noqa: ANN401
                 content_type: str | None = None, status: int = 200, **kwargs) -> None:
        """
        Create the response.
        """
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            content_type = 'application/json'
        super().__init__(body=body, headers=headers or DEFAULT_HEADERS, content_type=content_type, status=status,
                         **kwargs)
