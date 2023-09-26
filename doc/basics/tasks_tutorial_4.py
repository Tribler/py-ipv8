import asyncio

from ipv8.taskmanager import TaskManager

COMPLETED = []


async def execute_me_too(i: int) -> None:
    await asyncio.sleep(0.5)
    COMPLETED.append(i)


async def main() -> None:
    task_manager = TaskManager()

    for i in range(20):
        task_manager.register_anonymous_task("execute_me_too",
                                             execute_me_too, i)
    await task_manager.wait_for_tasks()

    await task_manager.shutdown_task_manager()
    print(COMPLETED)

asyncio.run(main())
