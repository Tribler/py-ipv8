from asyncio import ensure_future, get_event_loop

from pyipv8.ipv8.requestcache import NumberCache, RequestCache

REQUEST_CACHE = RequestCache()


class MyState(NumberCache):

    def __init__(self, request_cache, identifier, state):
        super().__init__(request_cache, "my-state", identifier)
        self.state = state

    def on_timeout(self):
        print("Oh no! I never received a response!")
        get_event_loop().stop()

    @property
    def timeout_delay(self):
        # We will timeout after 3 seconds (default is 10 seconds)
        return 3.0


async def foo():
    cache = MyState(REQUEST_CACHE, 0, 42)
    REQUEST_CACHE.add(cache)


ensure_future(foo())
get_event_loop().run_forever()
