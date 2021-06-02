import asyncio
import heapq


class DiscreteLoop(asyncio.AbstractEventLoop):
    """
    A discrete asyncio loop that immediately executes incoming tasks without a real-time waiting period.
    This loop can be helpful when quickly running simulation experiments with the IPv8 library. Usage:

    loop = DiscreteLoop()
    set_event_loop(loop)
    """

    def __init__(self):
        self._time = 0
        self._running = False
        self._immediate = []
        self._scheduled = []
        self._exc = None

    def get_debug(self):
        return False

    def time(self):
        return self._time

    def run_forever(self):
        self._running = True
        asyncio._set_running_loop(self)
        while (self._immediate or self._scheduled) and self._running:
            if self._immediate:
                h = self._immediate[0]
                self._immediate = self._immediate[1:]
            else:
                h = heapq.heappop(self._scheduled)
                self._time = h._when
                h._scheduled = False
            if not h._cancelled:
                h._run()
            if self._exc is not None:
                raise self._exc

    def run_until_complete(self, future):
        raise NotImplementedError

    def _timer_handle_cancelled(self, handle):
        pass

    def is_running(self):
        return self._running

    def is_closed(self):
        return not self._running

    def stop(self):
        self._running = False

    def close(self):
        self._running = False

    def call_exception_handler(self, context):
        self._exc = context.get('exception', None)

    def call_soon(self, callback, *args, context=None):
        h = asyncio.Handle(callback, args, self)
        self._immediate.append(h)
        return h

    def call_later(self, delay, callback, *args):
        if delay < 0:
            raise Exception("Can't schedule in the past")
        return self.call_at(self._time + delay, callback, *args)

    def call_at(self, when, callback, *args):
        if when < self._time:
            raise Exception("Can't schedule in the past")
        h = asyncio.TimerHandle(when, callback, args, self)
        heapq.heappush(self._scheduled, h)
        h._scheduled = True
        return h

    def create_task(self, coro):
        async def wrapper():
            try:
                await coro
            except asyncio.CancelledError:
                pass
            except Exception as e:
                self._exc = e

        return asyncio.Task(wrapper(), loop=self)

    def create_future(self):
        return asyncio.Future(loop=self)
