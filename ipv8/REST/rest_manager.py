import logging

from aiohttp import web

from .root_endpoint import RootEndpoint


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


class RESTManager:
    """
    This class is responsible for managing the startup and closing of the HTTP API.
    """

    def __init__(self, session):
        self._logger = logging.getLogger(self.__class__.__name__)
        self.session = session
        self.site = None

    async def start(self, port=8085):
        """
        Starts the HTTP API with the listen port as specified in the session configuration.
        """
        root_endpoint = RootEndpoint(middlewares=[cors_middleware])
        root_endpoint.initialize(self.session)
        runner = web.AppRunner(root_endpoint.app, access_log=None)
        await runner.setup()
        self.site = web.TCPSite(runner, 'localhost', port)
        await self.site.start()

    async def stop(self):
        """
        Stop the HTTP API and return when the server has shut down.
        """
        await self.site.stop()
