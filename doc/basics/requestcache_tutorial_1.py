from asyncio import create_task, run, sleep

from pyipv8.ipv8.requestcache import NumberCache, RequestCache


class MyState(NumberCache):

    def __init__(self, request_cache, identifier, state):
        super().__init__(request_cache, "my-state", identifier)
        self.state = state


async def foo(request_cache):
    """
    Add a new MyState cache to the global request cache.
    The state variable is set to 42 and the identifier of this cache is 0.
    """
    cache = MyState(request_cache, 0, 42)
    request_cache.add(cache)


async def bar():
    """
    Wait until a MyState cache with identifier 0 is added.
    Then, remove this cache from the global request cache and print its state.
    """
    # Normally, you would add this to a network overlay instance.
    request_cache = RequestCache()

    create_task(foo(request_cache))

    while not request_cache.has("my-state", 0):
        await sleep(0.1)
    cache = request_cache.pop("my-state", 0)
    print("I found a cache with the state:", cache.state)


run(bar())
