import collections
import logging
import time
from asyncio import all_tasks, current_task, get_event_loop

from aiohttp import web

from aiohttp_apispec import docs, json_schema

from marshmallow.fields import Boolean, Float, Integer, String

from .base_endpoint import BaseEndpoint, HTTP_BAD_REQUEST, HTTP_NOT_FOUND, Response
from .schema import DefaultResponseSchema, schema
from ..peerdiscovery.discovery import DiscoveryStrategy


class DequeLogHandler(logging.Handler):

    def __init__(self, maxlen=50):
        super(DequeLogHandler, self).__init__()
        self.deque = collections.deque(maxlen=maxlen)

    def emit(self, record):
        self.deque.append(self.format(record))


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
    This endpoint helps with the monitoring of the Asyncio thread.
    """

    def __init__(self):
        super(AsyncioEndpoint, self).__init__()
        self.strategy = None
        self.asyncio_log_handler = None

    def setup_routes(self):
        self.app.add_routes([web.get('/drift', self.retrieve_drift),
                             web.put('/drift', self.enable_measurements),
                             web.get('/tasks', self.get_asyncio_tasks),
                             web.put('/debug', self.set_asyncio_debug),
                             web.get('/debug', self.get_asyncio_debug)])

    def enable(self):
        if not self.session:
            return False
        if not self.strategy:
            self.strategy = DriftMeasurementStrategy(self.session.walk_interval)
            with self.session.overlay_lock:
                self.session.strategies.append((self.strategy, -1))
            return True
        return True

    def disable(self):
        if not self.session:
            return False
        if self.strategy:
            with self.session.overlay_lock:
                self.session.strategies = [s for s in self.session.strategies
                                           if not isinstance(s[0], DriftMeasurementStrategy)]
            self.strategy = None
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
        summary="Enable or disable drift measurements.",
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

    @docs(
        tags=["Asyncio"],
        summary="Return all currently running Asyncio tasks.",
        responses={
            200: {
                "schema": schema(AsyncioTasksResponse={"tasks": [
                    schema(AsyncioTask={
                        "name": String,
                        "running": Boolean,
                        "stack": [String],
                        "taskmanager": String,
                        "start_time": Float,
                        "interval": Integer
                    })
                ]})
            }
        }
    )
    async def get_asyncio_tasks(self, _):
        current = current_task()
        tasks = []
        for task in all_tasks():
            # Only in Python 3.8+ will we have a get_name function
            name = task.get_name() if hasattr(task, 'get_name') else getattr(task, 'name', f'Task-{id(task)}')

            task_dict = {"name": name,
                         "running": task == current,
                         "stack": [str(f) for f in task.get_stack()]}

            # Add info specific to tasks owner by TaskManager
            if hasattr(task, "start_time"):
                # Only TaskManager tasks have a start_time attribute
                cls, tsk = name.split(":")
                task_dict.update({"name": tsk, "taskmanager": cls, "start_time": task.start_time})
                if task.interval:
                    task_dict["interval"] = task.interval
            tasks.append(task_dict)
        return Response({"tasks": tasks})

    @docs(
        tags=["Asyncio"],
        summary="Set asyncio debug options.",
        responses={
            200: {
                "schema": DefaultResponseSchema,
                "example": {"success": True}
            },
            400: {
                "schema": DefaultResponseSchema,
                "example": {"success": False, "error": "incorrect parameters"}
            }
        }
    )
    @json_schema(schema(AsyncioDebugRequest={
        'enable': (Boolean, 'Whether to enable or disable asyncio debug mode.'),
        'slow_callback_duration': (Integer, 'Time threshold above which tasks will be logged.'),
    }))
    async def set_asyncio_debug(self, request):
        parameters = await request.json()
        if 'enable' not in parameters and 'slow_callback_duration' not in parameters:
            return Response({"success": False, "error": "incorrect parameters"}, status=HTTP_BAD_REQUEST)

        loop = get_event_loop()
        loop.slow_callback_duration = parameters.get('slow_callback_duration', loop.slow_callback_duration)

        if 'enable' in parameters:
            enable = bool(parameters['enable'])
            loop.set_debug(enable)

            # Add/remove asyncio log handler
            if enable and not self.asyncio_log_handler:
                self.asyncio_log_handler = DequeLogHandler()
                logging.getLogger('asyncio').addHandler(self.asyncio_log_handler)
            if not enable and self.asyncio_log_handler:
                logging.getLogger('asyncio').removeHandler(self.asyncio_log_handler)
                self.asyncio_log_handler = None

        return Response({"success": True})

    @docs(
        tags=["Asyncio"],
        summary="Return Asyncio log messages.",
        responses={
            200: {
                "schema": schema(AsyncioLogResponse={"debug": [
                    schema(AsyncioLogMessage={
                        "message": String
                    })
                ]})
            },
            400: {
                "schema": DefaultResponseSchema,
                "example": {"success": False, "error": "debug mode is disabled"}
            }
        }
    )
    async def get_asyncio_debug(self, _):
        loop = get_event_loop()
        messages = self.asyncio_log_handler.deque if self.asyncio_log_handler else []
        return Response({'messages': [{'message': r} for r in messages],
                         'enable': loop.get_debug(),
                         'slow_callback_duration': loop.slow_callback_duration})
