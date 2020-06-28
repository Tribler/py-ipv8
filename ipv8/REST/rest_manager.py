import logging

from aiohttp import web

from aiohttp_apispec import setup_aiohttp_apispec

from .base_endpoint import HTTP_INTERNAL_SERVER_ERROR, HTTP_UNAUTHORIZED, Response
from .root_endpoint import RootEndpoint


@web.middleware
class ApiKeyMiddleware(object):
    def __init__(self, api_key):
        self.api_key = api_key

    async def __call__(self, request, handler):
        if self.authenticate(request):
            return await handler(request)
        else:
            return Response({'error': 'Unauthorized access'}, status=HTTP_UNAUTHORIZED)

    def authenticate(self, request):
        # The api key can either be in the headers or as part of the url query
        api_key = request.headers.get('X-Api-Key') or request.query.get('apikey')
        return not self.api_key or self.api_key == api_key


@web.middleware
async def cors_middleware(request, handler):
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
async def error_middleware(request, handler):
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

    def __init__(self, session):
        self._logger = logging.getLogger(self.__class__.__name__)
        self.session = session
        self.site = None
        self.root_endpoint = None

    async def start(self, port=8085, host='127.0.0.1', api_key=None, ssl_context=None):
        """
        Starts the HTTP API with the listen port as specified in the session configuration.
        """
        self.root_endpoint = RootEndpoint(middlewares=[ApiKeyMiddleware(api_key),
                                                       cors_middleware,
                                                       error_middleware])
        self.root_endpoint.initialize(self.session)
        setup_aiohttp_apispec(
            app=self.root_endpoint.app,
            title="IPv8 REST API documentation",
            version="v2.2",  # Do not change manually! Handled by github_increment_version.py
            url="/docs/swagger.json",
            swagger_path="/docs",
        )

        from apispec.core import VALID_METHODS_OPENAPI_V2
        if 'head' in VALID_METHODS_OPENAPI_V2:
            VALID_METHODS_OPENAPI_V2.remove('head')

        runner = web.AppRunner(self.root_endpoint.app, access_log=None)
        await runner.setup()
        # If localhost is used as hostname, it will randomly either use 127.0.0.1 or ::1
        self.site = web.TCPSite(runner, host, port, ssl_context=ssl_context)
        await self.site.start()

    async def stop(self):
        """
        Stop the HTTP API and return when the server has shut down.
        """
        await self.site.stop()
