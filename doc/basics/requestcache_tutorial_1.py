from asyncio import create_task, run, sleep

from ipv8.requestcache import NumberCacheWithName, RequestCache


class MyState(NumberCacheWithName):

    name = "my-state"

    def __init__(self, request_cache: RequestCache,
                 identifier: int, state: int) -> None:
        super().__init__(request_cache, self.name, identifier)
        self.state = state


async def foo(request_cache: RequestCache) -> None:
    """
    Add a new MyState cache to the global request cache.
    The state variable is set to 42 and the identifier of this cache is 0.
    """
    cache = MyState(request_cache, 0, 42)
    request_cache.add(cache)


async def bar() -> None:
    """
    Wait until a MyState cache with identifier 0 is added.
    Then, remove this cache from the global request cache and print its state.
    """
    # Normally, you would add this to a network overlay instance.
    request_cache = RequestCache()

    _ = create_task(foo(request_cache))

    while not request_cache.has(MyState, 0):
        await sleep(0.1)
    cache = request_cache.pop(MyState, 0)
    print("I found a cache with the state:", cache.state)


run(bar())
