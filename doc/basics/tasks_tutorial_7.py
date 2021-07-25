import asyncio

from pyipv8.ipv8.requestcache import NumberCache, RequestCache


class MyCache(NumberCache):

    def __init__(self, request_cache, number):
        super().__init__(request_cache, "my cache", number)

        self.awaitable = asyncio.Future()

        self.register_future(self.awaitable, on_timeout=False)

    @property
    def timeout_delay(self):
        return 1.0

    def finish(self):
        self.awaitable.set_result(True)


async def main():
    rq = RequestCache()

    rq.add(MyCache(rq, 0))
    with rq.passthrough():
        rq.add(MyCache(rq, 1))  # Overwritten timeout = 0.0
    rq.add(MyCache(rq, 2))

    future0 = rq.get("my cache", 0).awaitable
    future1 = rq.get("my cache", 1).awaitable
    future2 = rq.get("my cache", 2).awaitable

    rq.get("my cache", 0).finish()
    await future0
    print(f"future0.result()={future0.result()}")
    rq.pop("my cache", 0)

    await future1
    print(f"future1.result()={future1.result()}")

    await rq.shutdown()

    print(f"future2.cancelled()={future2.cancelled()}")


asyncio.run(main())
