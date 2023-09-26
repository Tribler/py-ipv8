import asyncio

COMPLETED = []


async def execute_me_too(i: int) -> None:
    await asyncio.sleep(0.5)
    COMPLETED.append(i)


async def execute_me() -> None:
    await execute_me_too(2)
    COMPLETED.append(3)
    fut = asyncio.ensure_future(execute_me_too(4))  # store future
    COMPLETED.append(5)
    await fut  # await future before exiting

asyncio.run(execute_me())
print(COMPLETED)
