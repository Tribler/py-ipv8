from asyncio import run, sleep

from pyipv8.ipv8.requestcache import NumberCache, RequestCache


class MyState(NumberCache):

    def __init__(self, request_cache, identifier, state):
        super().__init__(request_cache, "my-state", identifier)
        self.state = state

    def on_timeout(self):
        print("Oh no! I never received a response!")

    @property
    def timeout_delay(self):
        # We will timeout after 3 seconds (default is 10 seconds)
        return 3.0


async def foo():
    request_cache = RequestCache()
    cache = MyState(request_cache, 0, 42)
    request_cache.add(cache)
    await sleep(4)


run(foo())
