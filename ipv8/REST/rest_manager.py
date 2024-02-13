from __future__ import annotations

import logging
from typing import TYPE_CHECKING, cast

from aiohttp import web
from aiohttp_apispec import AiohttpApiSpec

from .base_endpoint import HTTP_INTERNAL_SERVER_ERROR, HTTP_UNAUTHORIZED, BaseEndpoint, Response
from .root_endpoint import RootEndpoint

if TYPE_CHECKING:
    from aiohttp.abc import Request
    from aiohttp.connector import SSLContext
    from aiohttp.typedefs import Handler
    from aiohttp.web_response import StreamResponse
    from aiohttp.web_runner import BaseRunner


@web.middleware
class ApiKeyMiddleware:
    """
    Middleware to check for authorized REST access.
    """

    def __init__(self, api_key: str | None) -> None:
        """
        Create new middleware for the given API key.
        """
        self.api_key = api_key

    async def __call__(self, request: Request, handler: Handler) -> StreamResponse | Response:
        """
        Intercept requests that are not authorized.
        """
        if self.authenticate(request):
            return await handler(request)
        return Response({'error': 'Unauthorized access'}, status=HTTP_UNAUTHORIZED)

    def authenticate(self, request: Request) -> bool:
        """
        Check if the given request is authorized.
        """
        if request.path.startswith('/docs') or request.path.startswith('/static'):
            return True
        # The api key can either be in the headers or as part of the url query
        api_key = request.headers.get('X-Api-Key') or request.query.get('apikey')
        return not self.api_key or self.api_key == api_key


@web.middleware
async def cors_middleware(request: Request, handler: Handler) -> Response | StreamResponse:
    """
    Cross-origin resource sharing middleware.
    """
    preflight_cors = request.method == "OPTIONS" and 'Access-Control-Request-Method' in request.headers
    if not preflight_cors:
        return await handler(request)

    response = web.StreamResponse()
    # For now, just allow all methods
    response.headers['Access-Control-Allow-Methods'] = "GET, PUT, POST, PATCH, DELETE, OPTIONS"
    response.headers['Access-Control-Allow-Headers'] = '*'
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Max-Age'] = str(86400)
    return response


@web.middleware
async def error_middleware(request: Request, handler: Handler) -> Response | StreamResponse:
    """
    Middleware to catch call errors when handling requests.
    """
    try:
        response = await handler(request)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return Response({
            "success": False,
            "error": {
                "code": e.__class__.__name__,
                "message": str(e)
            }
        }, status=HTTP_INTERNAL_SERVER_ERROR)
    return response


class RESTManager:
    """
    This class is responsible for managing the startup and closing of the HTTP API.
    """

    def __init__(self, session: object, root_endpoint_class: type[BaseEndpoint] | None = None) -> None:
        """
        Create a new manager to orchestrate REST requests and responses.
        """
        self._logger = logging.getLogger(self.__class__.__name__)
        self.session = session
        self.site: web.TCPSite | None = None
        self.root_endpoint: BaseEndpoint | None = None
        self._root_endpoint_class = root_endpoint_class or RootEndpoint

    async def start(self, port: int = 8085, host: str = '127.0.0.1', api_key: str | None = None,
                    ssl_context: SSLContext | None = None) -> None:
        """
        Starts the HTTP API with the listen port as specified in the session configuration.
        """
        self.root_endpoint = self._root_endpoint_class(middlewares=[ApiKeyMiddleware(api_key),
                                                                    cors_middleware,
                                                                    error_middleware])
        self.root_endpoint.initialize(self.session)

        # Not using setup_aiohttp_apispec here, as we need access to the APISpec to set the security scheme
        aiohttp_apispec = AiohttpApiSpec(
            app=self.root_endpoint.app,
            title="IPv8 REST API documentation",
            version="v2.13",  # Do not change manually! Handled by github_increment_version.py
            url="/docs/swagger.json",
            swagger_path="/docs",
        )
        if api_key:
            # Set security scheme and apply to all endpoints
            aiohttp_apispec.spec.options['security'] = [{'apiKey': []}]
            aiohttp_apispec.spec.components.security_scheme('apiKey', {'type': 'apiKey',
                                                                       'in': 'header',
                                                                       'name': 'X-Api-Key'})

        from apispec.core import VALID_METHODS_OPENAPI_V2
        if 'head' in VALID_METHODS_OPENAPI_V2:
            VALID_METHODS_OPENAPI_V2.remove('head')

        runner = web.AppRunner(self.root_endpoint.app, access_log=None)
        await runner.setup()
        await self.start_site(runner, host, port, ssl_context)

    async def start_site(self, runner: BaseRunner, host: str | None, port: int | None,
                         ssl_context: SSLContext | None) -> None:
        """
        Create and start the internal TCP-based site.
        """
        # If localhost is used as hostname, it will randomly either use 127.0.0.1 or ::1
        self.site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
        await self.site.start()

    async def stop(self) -> None:
        """
        Stop the HTTP API and return when the server has shut down.
        """
        if self.site is None:
            return
        self.site = cast(web.TCPSite, self.site)
        await self.site.stop()
