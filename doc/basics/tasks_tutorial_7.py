import asyncio

from ipv8.requestcache import NumberCacheWithName, RequestCache


class MyCache(NumberCacheWithName):

    name = "my cache"

    def __init__(self,
                 request_cache: RequestCache,
                 number: int) -> None:
        super().__init__(request_cache, self.name, number)

        self.awaitable = asyncio.Future()

        self.register_future(self.awaitable, on_timeout=False)

    @property
    def timeout_delay(self) -> float:
        return 1.0

    def finish(self) -> None:
        self.awaitable.set_result(True)


async def main() -> None:
    rq = RequestCache()

    rq.add(MyCache(rq, 0))
    with rq.passthrough():
        rq.add(MyCache(rq, 1))  # Overwritten timeout = 0.0
    rq.add(MyCache(rq, 2))

    future0 = rq.get(MyCache, 0).awaitable
    future1 = rq.get(MyCache, 1).awaitable
    future2 = rq.get(MyCache, 2).awaitable

    rq.get(MyCache, 0).finish()
    await future0
    print(f"future0.result()={future0.result()}")
    rq.pop(MyCache, 0)

    await future1
    print(f"future1.result()={future1.result()}")

    await rq.shutdown()

    print(f"future2.cancelled()={future2.cancelled()}")


asyncio.run(main())
