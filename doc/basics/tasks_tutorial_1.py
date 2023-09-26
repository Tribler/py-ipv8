import asyncio

COMPLETED = []


async def execute_me_too(i: int) -> None:
    await asyncio.sleep(0.5)
    COMPLETED.append(i)


async def execute_me() -> None:
    execute_me_too(1)  # 1
    await execute_me_too(2)  # 2
    COMPLETED.append(3)  # 3
    _ = asyncio.ensure_future(execute_me_too(4))  # 4
    COMPLETED.append(5)  # 5
    await asyncio.sleep(1)  # 6

asyncio.run(execute_me())
print(COMPLETED)
