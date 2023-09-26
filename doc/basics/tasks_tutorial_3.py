import asyncio

from ipv8.taskmanager import TaskManager

COMPLETED = []


async def execute_me_too(i: int) -> None:
    await asyncio.sleep(0.5)
    COMPLETED.append(i)


async def main() -> None:
    task_manager = TaskManager()

    task_manager.register_task("execute_me_too1", execute_me_too, 1)
    task_manager.register_task("execute_me_too2", execute_me_too, 2)
    task_manager.cancel_pending_task("execute_me_too1")
    await task_manager.wait_for_tasks()

    await task_manager.shutdown_task_manager()
    print(COMPLETED)

asyncio.run(main())
