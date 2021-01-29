from asyncio import ensure_future, get_event_loop, sleep

from pyipv8.ipv8.requestcache import NumberCache, RequestCache

# We store the RequestCache in this global variable.
# Normally, you would add this to a network overlay instance.
REQUEST_CACHE = RequestCache()


class MyState(NumberCache):

    def __init__(self, request_cache, identifier, state):
        super().__init__(request_cache, "my-state", identifier)
        self.state = state


async def foo():
    """
    Add a new MyState cache to the global request cache.
    The state variable is set to 42 and the identifier of this cache is 0.
    """
    cache = MyState(REQUEST_CACHE, 0, 42)
    REQUEST_CACHE.add(cache)


async def bar():
    """
    Wait until a MyState cache with identifier 0 is added.
    Then, remove this cache from the global request cache and print its state.
    """
    while not REQUEST_CACHE.has("my-state", 0):
        await sleep(0.1)
    cache = REQUEST_CACHE.pop("my-state", 0)
    print("I found a cache with the state:", cache.state)
    get_event_loop().stop()


ensure_future(foo())
ensure_future(bar())
get_event_loop().run_forever()
