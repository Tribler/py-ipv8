from asyncio import run, sleep

from ipv8.requestcache import NumberCacheWithName, RequestCache


class MyState(NumberCacheWithName):

    name = "my-state"

    def __init__(self, request_cache: RequestCache,
                 identifier: int, state: int) -> None:
        super().__init__(request_cache, self.name, identifier)
        self.state = state

    def on_timeout(self) -> None:
        print("Oh no! I never received a response!")

    @property
    def timeout_delay(self) -> float:
        # We will timeout after 3 seconds (default is 10 seconds)
        return 3.0


async def foo() -> None:
    request_cache = RequestCache()
    cache = MyState(request_cache, 0, 42)
    request_cache.add(cache)
    await sleep(4)


run(foo())
