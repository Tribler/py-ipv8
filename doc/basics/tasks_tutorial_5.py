import asyncio

from ipv8.taskmanager import TaskManager

COMPLETED = []


async def execute_me_too(i: int, task_manager: TaskManager) -> None:
    if len(COMPLETED) == 20:
        task_manager.cancel_pending_task("keep adding 1")
        return
    COMPLETED.append(i)


async def main() -> None:
    task_manager = TaskManager()

    task_manager.register_task("keep adding 1", execute_me_too,
                               1, task_manager, interval=0.1)
    task_manager.register_task("sneaky inject", execute_me_too,
                               2, task_manager, delay=0.5)
    await task_manager.wait_for_tasks()

    await task_manager.shutdown_task_manager()
    print(COMPLETED)

asyncio.run(main())
