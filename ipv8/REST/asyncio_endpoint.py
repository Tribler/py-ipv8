import collections
import time

from aiohttp import web

from aiohttp_apispec import docs, json_schema

from marshmallow.fields import Boolean, Float

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_NOT_FOUND, Response
from .schema import DefaultResponseSchema, schema
from ..peerdiscovery.discovery import DiscoveryStrategy


class DriftMeasurementStrategy(DiscoveryStrategy):

    def __init__(self, core_update_rate):
        super(DriftMeasurementStrategy, self).__init__(None)
        self.last_measurement = time.time()
        self.history = collections.deque(maxlen=100)
        self.core_update_rate = core_update_rate
        self.overlay = type('FakeOverlay', (object,), {'get_peers': lambda: []})

    def take_step(self):
        with self.walk_lock:
            this_time = time.time()
            self.history.append((this_time, max(0.0, this_time - self.last_measurement - self.core_update_rate)))
            self.last_measurement = this_time


class AsyncioEndpoint(BaseEndpoint):
    """
    This endpoint manages measurements of non-functional requirements.
    """

    def __init__(self):
        super(AsyncioEndpoint, self).__init__()
        self.strategy = None
        self.enabled = False

    def setup_routes(self):
        self.app.add_routes([web.get('/drift', self.retrieve_drift), web.put('/enable', self.enable_measurements)])

    def enable(self):
        if not self.session:
            return False
        if not self.enabled:
            self.strategy = DriftMeasurementStrategy(self.session.walk_interval)
            with self.session.overlay_lock:
                self.session.strategies.append((self.strategy, -1))
            return True
        return True

    def disable(self):
        if not self.session:
            return False
        if self.enabled:
            with self.session.overlay_lock:
                self.session.strategies = [s for s in self.session.strategies
                                           if not isinstance(s[0], DriftMeasurementStrategy)]
            return True
        return True

    @docs(
        tags=["Asyncio"],
        summary="Measure the core drift.",
        responses={
            200: {
                "schema": schema(DriftResponse={"measurements": [
                    schema(Measurement={
                        "timestamp": Float,
                        "drift": Float
                    })
                ]})
            },
            400: {
                "schema": DefaultResponseSchema,
                "example": {"success": False, "error": "Core drift disabled."}
            }
        }
    )
    async def retrieve_drift(self, _):
        if self.strategy is None:
            return Response({"success": False, "error": "Core drift disabled."}, status=HTTP_NOT_FOUND)
        with self.strategy.walk_lock:
            return Response({"measurements": [{"timestamp": e[0], "drift": e[1]} for e in self.strategy.history]})

    @docs(
        tags=["Asyncio"],
        summary="Enable or disable measurements.",
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "examples": {'Enable value not specified': {"success": False, "error": "incorrect parameters"}}
            }
        }
    )
    @json_schema(schema(EnableDriftRequest={
        'enable*': (Boolean, 'Whether to enable or disable measuring.'),
    }))
    async def enable_measurements(self, request):
        parameters = await request.json()
        if 'enable' not in parameters:
            return Response({"error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        status = self.enable() if parameters.get('enable') else self.disable()
        if status:
            return Response({"success": True})
        else:
            return Response({"success": False, "error": "Session not initialized."})
